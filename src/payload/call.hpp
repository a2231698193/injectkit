// payload/call.hpp —— 调用任意函数（x64 调用约定）
//
// 这是注入框架最高价值的能力：**执行目标进程里已有的函数**。
// 外部读永远做不到这件事。
//
// 为什么不用 hook
// ==============
// 调用函数 = 执行游戏已有的代码，不修改任何字节。
// hook      = 修改游戏代码的字节。
//
// Warden 的 Mem 检查逐字节比对，一次 Mismatch 就定罪（IntegrityInvariant）。
// 所以"调用"安全，"hook"危险。这是两件完全不同的事。
//
// x64 调用约定的完整规则
// =====================
//
//   整型/指针参数：RCX, RDX, R8, R9              （第 1-4 个）
//   浮点参数：    XMM0, XMM1, XMM2, XMM3        （独立的 4 个槽，不占整型槽）
//   5+ 参数：     压栈，从右往左（最后一个先压）
//   影子空间：    RSP 之下必须有 32 字节空位（被调用者可能往里写）
//   栈对齐：      进入被调用函数时 RSP % 16 == 8
//                 （因为 call 会压入 8 字节返回地址）
//
// 最容易错的三个地方
// =================
//
//   1. **浮点和整型用不同的寄存器槽**
//      如果第 1 个参数是 float，它去 XMM0，而第 2 个整型参数仍然去 RDX
//      （不是 RCX）。这是最容易搞错的。
//
//   2. **栈对齐**
//      我们自己的函数体开始时 RSP%16==8（call 压了返回地址）。
//      如果再 sub rsp, N，N 必须是 8 的奇数倍才能让进入被调函数时对齐。
//      实践中：影子空间 32 + 栈参数 8*n，总和要满足对齐。
//
//   3. **Shadow space 是给被调用者的**
//      即使函数只有 1 个参数，也要留 32 字节。不留的话被调函数
//      往那里写东西就会覆盖我们的数据。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>

namespace ik {
namespace call {

// ---------- 参数类型 ----------
enum class ArgType : uint8_t {
    Int = 0,      // 整型 / 指针（走 RCX/RDX/R8/R9 或压栈）
    Float = 1,    // float（走 XMM0-3，占 4 字节）
    Double = 2,   // double（走 XMM0-3，占 8 字节）
};

// 一个参数
//
// value 是 64 位原始值：
//   Int    → 直接用
//   Float  → 低 32 位是 float 的位模式
//   Double → 整个 64 位是 double 的位模式
struct Arg {
    ArgType type = ArgType::Int;
    uint64_t value = 0;

    static Arg i(uint64_t v) { return Arg{ArgType::Int, v}; }
    static Arg f(float v) {
        uint32_t bits;
        std::memcpy(&bits, &v, 4);
        return Arg{ArgType::Float, bits};
    }
    static Arg d(double v) {
        uint64_t bits;
        std::memcpy(&bits, &v, 8);
        return Arg{ArgType::Double, bits};
    }
};

// 返回值
struct Result {
    uint64_t rax = 0;       // 整型/指针返回值
    uint64_t xmm0 = 0;      // 浮点返回值（低 32 位 float，全部 64 位 double）
    ArgType retType = ArgType::Int;

    uint64_t as_int() const noexcept { return rax; }

    float as_float() const noexcept {
        uint32_t bits = static_cast<uint32_t>(xmm0 & 0xFFFFFFFFu);
        float f;
        std::memcpy(&f, &bits, 4);
        return f;
    }

    double as_double() const noexcept {
        double d;
        std::memcpy(&d, &xmm0, 8);
        return d;
    }
};

// ============================================================================
// 核心：x64 调用蹦床（trampoline）
// ============================================================================
//
// 这是整个文件里唯一需要汇编的地方。手写机器码，因为：
//   * 不能用 inline asm（MSVC x64 不支持）
//   * 不能用编译器生成的代码（它会插入自己的 prologue/epilogue）
//   * 必须精确控制栈布局
//
// 调用序列（进入 trampoline 时 RSP%16==8）：
//
//   push rbp                     ; 保存
//   mov  rbp, rsp                ; 固定基准，方便后面访问参数
//   sub  rsp, <locals>           ; 本地空间（对齐到 16）
//   ...                          ; 见下面的具体实现
//   mov  rsp, rbp                ; 恢复
//   pop  rbp
//   ret
//
// 更简单的做法：直接在 C++ 里用汇编块（GCC/Clang 支持 __asm__），
// 或者用一组固定的寄存器搬运 + 内联汇编。
//
// 但为了跨编译器（MinGW gcc + MSVC 都可能用），这里用
// **手写机器码 + VirtualAlloc 执行** 的方式。虽然丑，但通用。

// ---------- 构造调用蹦床 ----------
//
// 蹦床的作用：把 N 个参数放进正确的寄存器/栈位置，然后 call 目标函数。
//
// 参数在内存里连续存放（Arg 数组），蹦床逐個搬运。
//
// 机器码布局（x64）：
//
//   55                     push rbp
//   48 89 E5               mov  rbp, rsp
//   48 83 EC xx            sub  rsp, xx            ; 本地空间（32 影子 + 栈参数 + 对齐）
//
//   ; 搬运前 4 个整型参数
//   48 8B 0D xx xx xx xx   mov  rcx, [rip+disp]    ; 或从栈上参数区读
//   ...
//
//   ; 搬运前 4 个浮点参数
//   F3 0F 10 05 xx xx xx xx  movss xmm0, [rip+disp]
//   ...
//
//   ; 5+ 参数压栈（已经在 sub rsp 的区域里预留）
//
//   ; call
//   48 B8 xx xx xx xx xx xx xx xx   mov rax, target
//   FF D0                           call rax
//
//   ; 保存返回值
//   48 89 05 xx xx xx xx   mov [rip+disp], rax
//   F3 0F 11 05 xx xx xx   movss [rip+disp], xmm0   （如果返回浮点）
//
//   48 89 EC               mov rsp, rbp
//   5D                     pop rbp
//   C3                     ret

// 与其手写全部机器码（容易出错且难调试），
// 采用更可控的方案：**用函数指针 + 内联汇编搬运参数**
//
// 这里定义一个模板，参数个数固定（分 0-8 个），
// 每个版本单独实现参数搬运。这样：
//   * 不需要运行时生成机器码
//   * 每个版本可以单独测试
//   * 出错时容易定位

// ---------- 0 参数 ----------
inline Result invoke0(uint64_t fnAddr) {
    using Fn0 = uint64_t (*)();
    Result r;
    r.rax = reinterpret_cast<Fn0>(fnAddr)();
    return r;
}

// ---------- 1 参数 ----------
inline Result invoke1(uint64_t fnAddr, const Arg& a0) {
    Result r;
    if (a0.type == ArgType::Int) {
        using FnT = uint64_t (*)(uint64_t);
        r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value);
    } else if (a0.type == ArgType::Float) {
        using FnT = uint64_t (*)(float);
        const float f = *reinterpret_cast<const float*>(&a0.value);
        r.rax = reinterpret_cast<FnT>(fnAddr)(f);
    } else {
        using FnT = uint64_t (*)(double);
        const double d = *reinterpret_cast<const double*>(&a0.value);
        r.rax = reinterpret_cast<FnT>(fnAddr)(d);
    }
    return r;
}

// ---------- 2 参数 ----------
inline Result invoke2(uint64_t fnAddr, const Arg& a0, const Arg& a1) {
    Result r;

    // 四种类型组合，各写一遍（穷举，避免运行时分派出错）
    const bool f0 = (a0.type != ArgType::Int);
    const bool f1 = (a1.type != ArgType::Int);

    if (!f0 && !f1) {
        using FnT = uint64_t (*)(uint64_t, uint64_t);
        r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value, a1.value);
    } else if (f0 && !f1) {
        // a0 是 float，a1 是 int
        if (a0.type == ArgType::Float) {
            using FnT = uint64_t (*)(float, uint64_t);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const float*>(&a0.value),
                                                  a1.value);
        } else {
            using FnT = uint64_t (*)(double, uint64_t);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const double*>(&a0.value),
                                                  a1.value);
        }
    } else if (!f0 && f1) {
        if (a1.type == ArgType::Float) {
            using FnT = uint64_t (*)(uint64_t, float);
            r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value,
                                                  *reinterpret_cast<const float*>(&a1.value));
        } else {
            using FnT = uint64_t (*)(uint64_t, double);
            r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value,
                                                  *reinterpret_cast<const double*>(&a1.value));
        }
    } else {
        if (a0.type == ArgType::Float && a1.type == ArgType::Float) {
            using FnT = uint64_t (*)(float, float);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const float*>(&a0.value),
                                                  *reinterpret_cast<const float*>(&a1.value));
        } else if (a0.type == ArgType::Double && a1.type == ArgType::Double) {
            using FnT = uint64_t (*)(double, double);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const double*>(&a0.value),
                                                  *reinterpret_cast<const double*>(&a1.value));
        } else if (a0.type == ArgType::Float) {
            using FnT = uint64_t (*)(float, double);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const float*>(&a0.value),
                                                  *reinterpret_cast<const double*>(&a1.value));
        } else {
            using FnT = uint64_t (*)(double, float);
            r.rax = reinterpret_cast<FnT>(fnAddr)(*reinterpret_cast<const double*>(&a0.value),
                                                  *reinterpret_cast<const float*>(&a1.value));
        }
    }
    return r;
}

// ---------- 3、4 参数：全整型（最常见的游戏 API 形态）----------
inline Result invoke3(uint64_t fnAddr, const Arg& a0, const Arg& a1, const Arg& a2) {
    using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t);
    Result r;
    r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value, a1.value, a2.value);
    return r;
}

inline Result invoke4(uint64_t fnAddr, const Arg& a0, const Arg& a1, const Arg& a2,
                      const Arg& a3) {
    using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
    Result r;
    r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value, a1.value, a2.value, a3.value);
    return r;
}

// ---------- 5+ 参数：需要压栈 ----------
//
// 前 4 个走寄存器，第 5 个开始压栈。
// 用编译器帮我们生成正确的栈布局 —— 声明一个 5 参数的函数指针类型，
// 调用时传 5 个参数，编译器会自动压栈。
//
// 这是关键洞察：**不需要手写汇编**。
// 编译器知道 x64 调用约定，我们只要给出正确的函数指针类型。
inline Result invoke5(uint64_t fnAddr, const Arg& a0, const Arg& a1, const Arg& a2,
                      const Arg& a3, const Arg& a4) {
    using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    Result r;
    r.rax = reinterpret_cast<FnT>(fnAddr)(a0.value, a1.value, a2.value, a3.value, a4.value);
    return r;
}

// 浮点返回值的版本
//
// float/double 返回值在 XMM0，不是 RAX。
// 声明返回类型为 float/double，编译器会自动从 XMM0 取。
inline Result invoke_float_ret(uint64_t fnAddr, const Arg* args, size_t nargs) {
    Result r;
    r.retType = ArgType::Float;

    const float f0 = (nargs > 0) ? *reinterpret_cast<const float*>(&args[0].value) : 0.0f;
    const float f1 = (nargs > 1) ? *reinterpret_cast<const float*>(&args[1].value) : 0.0f;

    // 同 double 版本的教训：函数指针声明必须匹配实际参数类型
    if (nargs == 0) {
        using FnT = float (*)();
        const float f = reinterpret_cast<FnT>(fnAddr)();
        std::memcpy(&r.xmm0, &f, 4);
    } else if (nargs == 1) {
        if (args[0].type == ArgType::Float) {
            using FnT = float (*)(float);
            const float f = reinterpret_cast<FnT>(fnAddr)(f0);
            std::memcpy(&r.xmm0, &f, 4);
        } else if (args[0].type == ArgType::Double) {
            using FnT = float (*)(double);
            const float f = reinterpret_cast<FnT>(fnAddr)(
                *reinterpret_cast<const double*>(&args[0].value));
            std::memcpy(&r.xmm0, &f, 4);
        } else {
            using FnT = float (*)(uint64_t);
            const float f = reinterpret_cast<FnT>(fnAddr)(args[0].value);
            std::memcpy(&r.xmm0, &f, 4);
        }
    } else {
        if (args[0].type == ArgType::Float && args[1].type == ArgType::Float) {
            using FnT = float (*)(float, float);
            const float f = reinterpret_cast<FnT>(fnAddr)(f0, f1);
            std::memcpy(&r.xmm0, &f, 4);
        } else {
            using FnT = float (*)(uint64_t, uint64_t);
            const float f = reinterpret_cast<FnT>(fnAddr)(args[0].value, args[1].value);
            std::memcpy(&r.xmm0, &f, 4);
        }
    }
    return r;
}

inline Result invoke_double_ret(uint64_t fnAddr, const Arg* args, size_t nargs) {
    Result r;
    r.retType = ArgType::Double;

    const double d0 = (nargs > 0) ? *reinterpret_cast<const double*>(&args[0].value) : 0.0;
    const double d1 = (nargs > 1) ? *reinterpret_cast<const double*>(&args[1].value) : 0.0;
    const float f0 = (nargs > 0) ? *reinterpret_cast<const float*>(&args[0].value) : 0.0f;

    // 按参数实际类型选择函数指针签名
    if (nargs == 0) {
        using FnT = double (*)();
        const double d = reinterpret_cast<FnT>(fnAddr)();
        std::memcpy(&r.xmm0, &d, 8);
    } else if (nargs == 1) {
        if (args[0].type == ArgType::Double) {
            using FnT = double (*)(double);
            const double d = reinterpret_cast<FnT>(fnAddr)(d0);
            std::memcpy(&r.xmm0, &d, 8);
        } else if (args[0].type == ArgType::Float) {
            using FnT = double (*)(float);
            const double d = reinterpret_cast<FnT>(fnAddr)(f0);
            std::memcpy(&r.xmm0, &d, 8);
        } else {
            using FnT = double (*)(uint64_t);
            const double d = reinterpret_cast<FnT>(fnAddr)(args[0].value);
            std::memcpy(&r.xmm0, &d, 8);
        }
    } else {
        if (args[0].type == ArgType::Double && args[1].type == ArgType::Double) {
            using FnT = double (*)(double, double);
            const double d = reinterpret_cast<FnT>(fnAddr)(d0, d1);
            std::memcpy(&r.xmm0, &d, 8);
        } else if (args[0].type == ArgType::Double) {
            using FnT = double (*)(double, uint64_t);
            const double d = reinterpret_cast<FnT>(fnAddr)(d0, args[1].value);
            std::memcpy(&r.xmm0, &d, 8);
        } else if (args[1].type == ArgType::Double) {
            using FnT = double (*)(uint64_t, double);
            const double d = reinterpret_cast<FnT>(fnAddr)(args[0].value, d1);
            std::memcpy(&r.xmm0, &d, 8);
        } else {
            using FnT = double (*)(uint64_t, uint64_t);
            const double d = reinterpret_cast<FnT>(fnAddr)(args[0].value, args[1].value);
            std::memcpy(&r.xmm0, &d, 8);
        }
    }
    return r;
}

// ---------- 统一入口 ----------
inline constexpr size_t kMaxArgs = 8;

inline Result invoke(uint64_t fnAddr, const Arg* args, size_t nargs, ArgType retType) {
    if (fnAddr == 0) return Result{};

    // 浮点返回单独处理（返回值在 XMM0）
    if (retType == ArgType::Float) return invoke_float_ret(fnAddr, args, nargs);
    if (retType == ArgType::Double) return invoke_double_ret(fnAddr, args, nargs);

    switch (nargs) {
        case 0: return invoke0(fnAddr);
        case 1: return invoke1(fnAddr, args[0]);
        case 2: return invoke2(fnAddr, args[0], args[1]);
        case 3: return invoke3(fnAddr, args[0], args[1], args[2]);
        case 4: return invoke4(fnAddr, args[0], args[1], args[2], args[3]);
        case 5: return invoke5(fnAddr, args[0], args[1], args[2], args[3], args[4]);
        default: break;
    }

    // 6-8 个参数：继续用编译器生成的压栈逻辑
    if (nargs == 6) {
        using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        Result r;
        r.rax = reinterpret_cast<FnT>(fnAddr)(args[0].value, args[1].value, args[2].value,
                                              args[3].value, args[4].value, args[5].value);
        return r;
    }
    if (nargs == 7) {
        using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t);
        Result r;
        r.rax = reinterpret_cast<FnT>(fnAddr)(args[0].value, args[1].value, args[2].value,
                                              args[3].value, args[4].value, args[5].value,
                                              args[6].value);
        return r;
    }
    {
        using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t);
        Result r;
        r.rax = reinterpret_cast<FnT>(fnAddr)(args[0].value, args[1].value, args[2].value,
                                              args[3].value, args[4].value, args[5].value,
                                              args[6].value, args[7].value);
        return r;
    }
}

}  // namespace call
}  // namespace ik

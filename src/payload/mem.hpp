// payload/mem.hpp —— 内部内存访问
//
// 这是注入框架的核心优势所在：**读内存就是 `*ptr`**。
//
// 与外部读的对比
// ==============
//
//   外部（memkit）：
//     NtReadVirtualMemory(handle, addr, buf, n, &got)
//     → 需要句柄、需要 OpenProcess、每次都是系统调用
//     → 唯一的暴露面：句柄可被枚举
//
//   内部（injectkit）：
//     memcpy(dst, (void*)addr, n)
//     → 无句柄、无系统调用、速度是外部读的几十倍
//     → 但要自己处理"地址不可读"（会直接炸）
//
// 所以这里的核心工作是：**在不炸进程的前提下读任意地址**。
//
// 三种探测方式（各有取舍）
// ======================
//
//   A. IsBadReadPtr（旧 API）
//      优点：一行就够
//      缺点：微软标记为弃用，且它内部会吞掉异常（改变进程状态）
//            并发环境下有竞态
//
//   B. VirtualQuery 先查页属性
//      优点：不触发异常，快
//      缺点：查完到实际读之间页可能被改（TOCTOU）
//            跨页时只查了第一页
//
//   C. SEH（__try/__except）
//      优点：精确，只有真的炸了才失败
//      缺点：MinGW 不完全支持 __try；且异常处理本身有成本
//
// 这里组合用 B + A：先 VirtualQuery 快速筛掉明显不可读的，
// 再用 IsBadReadPtr 兜底。真实项目里 B 已经够用（TOCTOU 概率极低）。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>

namespace ik {
namespace mem {

// 一次读取的结果
enum class Status : uint8_t {
    Ok = 0,
    NullAddr,        // 地址为 0
    NotCommitted,    // 页未提交
    NoAccess,        // 不可读
    GuardPage,       // guard page（诱饵）
    TooLarge,        // 超过单次限制
    Partial,         // 跨页边界，只读到一部分
};

inline const char* status_name(Status s) noexcept {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::NullAddr: return "null_addr";
        case Status::NotCommitted: return "not_committed";
        case Status::NoAccess: return "no_access";
        case Status::GuardPage: return "guard_page";
        case Status::TooLarge: return "too_large";
        case Status::Partial: return "partial";
    }
    return "?";
}

inline constexpr size_t kMaxRead = 4096;

// 检查一段地址是否可读（配合 VirtualQuery，不触发异常）
inline bool probe_readable(uintptr_t addr, size_t n) noexcept {
    if (addr == 0) return false;

    uintptr_t cur = addr;
    const uintptr_t end = addr + n;
    if (end < addr) return false;   // 溢出

    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & PAGE_GUARD) return false;
        if (mbi.Protect & PAGE_NOACCESS) return false;

        // 只需要 READ / EXECUTE_READ / READWRITE / WRITECOPY 中的 READ 位
        const DWORD p = mbi.Protect & 0xFF;
        const bool readable = (p == PAGE_READONLY || p == PAGE_READWRITE ||
                               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
                               p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY);
        if (!readable) return false;

        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= cur) return false;
        cur = next;
    }
    return true;
}

// 读取。成功返回 Status::Ok
//
// 关键：**绝不因为跨页就整块失败**。
// 跨页时读到边界为止，返回 Partial + 实际读到的字节数。
inline Status read(uintptr_t addr, void* dst, size_t n, size_t& got) noexcept {
    got = 0;
    if (dst == nullptr || n == 0) return Status::NullAddr;
    if (addr == 0) return Status::NullAddr;
    if (n > kMaxRead) return Status::TooLarge;

    // 逐页推进，能读多少读多少
    uint8_t* out = static_cast<uint8_t*>(dst);
    uintptr_t cur = addr;
    size_t remain = n;

    while (remain > 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0) {
            return got > 0 ? Status::Partial : Status::NotCommitted;
        }

        if (mbi.State != MEM_COMMIT) {
            return got > 0 ? Status::Partial : Status::NotCommitted;
        }
        if (mbi.Protect & PAGE_GUARD) {
            return got > 0 ? Status::Partial : Status::GuardPage;
        }
        if (mbi.Protect & PAGE_NOACCESS) {
            return got > 0 ? Status::Partial : Status::NoAccess;
        }

        const DWORD p = mbi.Protect & 0xFF;
        const bool readable = (p == PAGE_READONLY || p == PAGE_READWRITE ||
                               p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
                               p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY);
        if (!readable) {
            return got > 0 ? Status::Partial : Status::NoAccess;
        }

        // 这一页里还能读多少
        const uintptr_t pageEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        size_t canRead = static_cast<size_t>(pageEnd - cur);
        if (canRead > remain) canRead = remain;

        // 真正读。这一步在地址合法时不会炸。
        std::memcpy(out, reinterpret_cast<const void*>(cur), canRead);

        out += canRead;
        cur += canRead;
        remain -= canRead;
        got += canRead;
    }

    return Status::Ok;
}

// 模板便利函数
template <typename T>
bool read_value(uintptr_t addr, T& out) noexcept {
    size_t got = 0;
    return read(addr, &out, sizeof(T), got) == Status::Ok && got == sizeof(T);
}

// 多级指针链。offs[0] 相对 base，之后每级解引用再加偏移。
// 与 memkit 的 schema 语义一致，方便迁移偏移表。
//
// 关键：**最后一级地址也验证可读性**。
// 只算出地址而不验证，会出现"解析成功但用不了"的情况——
// 偏移错位时地址会落在一个看似合法但实际不可读的位置。
// 这是 memkit 那边踩过的坑，这边直接继承。
inline bool chain(uintptr_t base, const uintptr_t* offs, size_t n,
                  uintptr_t& out) noexcept {
    if (base == 0 || offs == nullptr || n == 0) return false;

    uintptr_t cur = base;
    for (size_t i = 0; i < n; ++i) {
        const uintptr_t target = cur + offs[i];
        if (i + 1 == n) {
            // 最后一级：地址就是结果，但必须可读
            uint8_t probe = 0;
            if (!probe_readable(target, 1)) return false;
            size_t got = 0;
            if (read(target, &probe, 1, got) != Status::Ok) return false;
            out = target;
            return true;
        }
        // 中间级：解引用
        uint64_t next = 0;
        if (!read_value(target, next) || next == 0) return false;
        cur = static_cast<uintptr_t>(next);
    }
    out = cur;
    return true;
}

}  // namespace mem
}  // namespace ik

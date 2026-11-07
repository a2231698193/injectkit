# P3：调用任意函数

## 端到端实测（决定性证据）

通过 RPC 在**目标进程里**执行函数，并链式传递返回值：

```
1. GetProcessHeap()                     → 0x2CBF0BD0000
2. HeapAlloc(那个堆, 0, 256)            → 0x2CBF0BDBA80
```

**第 2 步在目标进程里真实分配了 256 字节内存。**

完整的验证链：

```
外部程序 → 命名管道 → JSON-RPC → payload → call 目标函数 → 返回结果
```

还有这些也验证过：

```
GetTickCount64()                        → 42867031      （系统运行时间）
Sleep(300)                              → 0             （2 参数，阻塞 300ms）
CreateFileW(7 参数)                     → INVALID_HANDLE （7 参数压栈）
pow(2.0, 10.0)                          → 1024.0        （double 参数 + double 返回）
sqrtf(16.0f)                            → 4.0           （float 参数 + float 返回）
```

---

## 这是注入最核心的价值

外部读（memkit 那类）永远做不到这件事：

| 能力 | 外部读 | 内部调用 |
|---|---|---|
| 读内存 | ✅ | ✅ |
| 写内存 | ⚠️ 需 VM_WRITE 权限，句柄表里很显眼 | ✅ |
| **调用游戏函数** | ❌ **做不到** | ✅ |
| **拿函数返回值** | ❌ | ✅ |
| **链式调用**（用 A 的返回值喂 B） | ❌ | ✅ |

最后一条最关键：`GetProcessHeap` → `HeapAlloc` 这个链条，外部读模拟不了。

---

## x64 调用约定的三个坑

### 坑 1：函数指针的声明类型必须匹配实际参数

```cpp
// 实际函数：double pow(double, double)
// 参数走 XMM0/XMM1

// ❌ 错：声明成整型，编译器放 RDX/R8
using FnT = double (*)(uint64_t, uint64_t);
reinterpret_cast<FnT>(addr)(a0, a1);    // → 返回 0.0

// ✅ 对：声明成 double
using FnT = double (*)(double, double);
reinterpret_cast<FnT>(addr)(d0, d1);    // → 返回 1024.0
```

**这个错误不会崩，只会静默返回 0。** 是最难查的一类 bug。

`float` / `double` / `int` 参数在 x64 走**不同的寄存器组**：

```
整型/指针 → RCX, RDX, R8, R9
浮点      → XMM0, XMM1, XMM2, XMM3
```

所以必须按参数实际类型分派，不能全当 `uint64_t` 传。

### 坑 2：5+ 参数需要压栈

前 4 个走寄存器，第 5 个开始压栈。

**好消息**：不需要手写汇编。声明一个 5/6/7/8 参数的函数指针类型，
编译器会自动生成正确的压栈代码：

```cpp
using FnT = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
reinterpret_cast<FnT>(addr)(a0, a1, a2, a3, a4);
```

验证：`CreateFileW` 有 7 个参数，调用返回 `INVALID_HANDLE_VALUE`（正确）。

### 坑 3：影子空间（Shadow Space）

即使函数只有 1 个参数，调用者也必须在栈上留 32 字节空位。

**这个坑不用管**——只要我们声明正确的函数指针类型并让编译器生成调用代码，
它会自动处理影子空间。

**只有手写汇编时才会踩这个坑。** 我们没手写。

---

## 实现结构

```cpp
// 参数：类型 + 64 位原始值
struct Arg {
    ArgType type;    // Int / Float / Double
    uint64_t value;  // 位模式
};

// 按参数个数 + 类型分派
Result invoke(uint64_t fnAddr, const Arg* args, size_t nargs, ArgType retType);
```

分派逻辑：

| 参数个数 | 实现 |
|---|---|
| 0 | 直接调 |
| 1 | 按类型分 3 种 |
| 2 | 按类型分 4 种组合 |
| 3-4 | 全整型（游戏 API 最常见） |
| 5-8 | 编译器生成压栈 |

浮点返回单独处理（`invoke_float_ret` / `invoke_double_ret`），
因为返回值在 XMM0 而不是 RAX。

---

## RPC 接口

```json
{"jsonrpc":"2.0","id":1,"method":"game.call","params":{
    "addr":"0x7FF832A33C10",
    "args":[{"t":"i","v":"0x10"},{"t":"f","v":1.5},{"t":"d","v":2.5}],
    "ret":"d"
}}
```

| 字段 | 说明 |
|---|---|
| `addr` | 函数地址（hex 字符串） |
| `args` | 参数数组。可写简写 `[1,2,3]`（全整型）或显式 `[{"t":"f","v":1.5}]` |
| `t` | `i`=整型/指针 / `f`=float / `d`=double |
| `ret` | 返回类型，默认 `i` |

响应：

```json
{"result":{"ok":true,"ret_u":"0x2CBF0BDBA80","ret_i":3074940582528}}
```

浮点返回时额外给 `ret_f` / `ret_d`。整型返回值一律给 `ret_u`（hex）和 `ret_i`（十进制）。

限制：最多 8 个参数。

---

## 安全边界（重要）

**调用 ≠ hook。**

| | 调用 | hook |
|---|---|---|
| 修改游戏字节 | ❌ 不修改 | ✅ 修改 |
| Warden Mem 检查 | ✅ 不受影响 | ❌ 一次 Mismatch 就定罪 |
| 能力 | 执行已有函数 | 拦截/修改行为 |

Warden 的 `Mem` 检查是**逐字节比对**（`expectedBytes` 是原始字节），
且取证类别是 `IntegrityInvariant` —— **一次不匹配就够定罪**。

所以"调用游戏函数"是安全的，"改函数开头"是自杀。

这个能力可以用来做：

```
✅ 调用游戏的寻路函数
✅ 调用游戏的计算函数（伤害/命中）
✅ 调用游戏的读数据接口（比自己解析结构体更可靠）
❌ 拦截/修改游戏行为
```

---

## 拿到游戏函数地址之后

现在只需要一个地址就能调：

```bash
ikclient.exe <pid> call 0x<函数地址> <参数1>,<参数2>,...
```

地址来源：

| 来源 | 需要什么 |
|---|---|
| AOB 扫描 | 需要 exe 文件（可以在 payload 里扫） |
| 硬编码偏移 | 需要对应版本的 exe |
| 调试器手工找 | 需要运行中的游戏 |

**这部分需要真实客户端。** 但机制已经完全就绪。

---

## 当前状态

```
84 项离线自检全绿
  · call 基础（零参数/单参数/空地址）
  · 影子空间与多参数（CreateFileW 7 参数）
  · 浮点（pow / sqrtf / _finite）
  · RPC 集成（含错误路径）
```

二进制：

```
ikpayload.dll   敏感导入 0，依赖 KERNEL32 + msvcrt
ikclient.exe    敏感导入 0
ikloader.exe    敏感导入 4（注入必需）
```

---

## 下一步

| 项 | 需要游戏 | 价值 |
|---|---|---|
| AOB 扫描（在 payload 内） | ⚠️ 需要 exe 验证 | 高 —— 自动找函数地址 |
| CreateTimerQueueTimer 驱动 | ❌ | 高 —— 解决 APC 无自驱动力 |
| manual map | ❌ | 中 —— 消除模块痕迹 |
| 偏移表 + schema | ⚠️ 需要真实偏移 | 高 |

**AOB 扫描**最有价值——它能把"拿到函数地址"这一步也自动化。
实现上可以直接用 memkit 那套 `scanpattern`（逻辑通用，但要改成在目标进程内跑，
不需要 `NtReadVirtualMemory`）。

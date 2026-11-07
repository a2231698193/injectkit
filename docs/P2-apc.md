# P2：消除新线程（用 APC）

## 实测数据

| 场景 | 线程数 | 模块数 |
|---|---|---|
| 基线（iktarget.exe） | 2 | 5 |
| **thread 模式**（payload 自己 CreateThread） | **3** (+1) | 6 (+1) |
| **apc 模式**（APC 在已有线程上跑） | **2**（不变） | 6 (+1) |

**APC 模式完全消除了线程痕迹。**

模块数 +1 是 `ikpayload.dll` 自己，无法避免（除非 manual map）。

---

## 关键是先发现了一个隐形代价

第一版 apc 模式实测出来是 `threads=4 modules=13` —— 比预期糟糕得多。

查出来的原因是 **`wsprintfW`**：

```
wsprintfW  → USER32.dll
USER32.dll → IMM32.dll + 5 个其他依赖
```

拼个字符串付出了 8 个模块 + 2 个线程（USER32 初始化时创建的）的代价。

改成手写十进制拼接后：

```
依赖：KERNEL32.dll + msvcrt.dll      （只有两个）
模块：5 → 6                          （只多 payload 自己）
```

**这是内部挂最容易忽略的一类问题**：你以为某个函数"只是个字符串格式化"，
实际上它拉进来一整个 GUI 库。

---

## 技术原理

### APC 是什么

`NtQueueApcThread` 把回调塞进目标线程的 APC 队列。那个线程下次调用
**alertable 等待函数**时（`SleepEx` / `WaitForSingleObjectEx` /
`MsgWaitForMultipleObjectsEx`），系统先执行队列里的 APC。

```
传统：CreateRemoteThread → 目标多一个线程
APC ：QueueApcThread    → 复用目标已有的线程
```

### alertable 前提怎么满足

**`NtAlertThread`** —— 这是关键 API，之前不知道它存在。

```
如果线程正在 alertable wait → 立刻返回并执行 APC
如果线程不在 alertable wait → 设置 Alerted 标志，
                              下次进入时立刻执行
```

这意味着**不需要等目标自然进入 alertable wait**。任何线程都能被 alert。

代价：被 alert 的线程如果后来调 `SleepEx`，会立刻返回（不睡满）。
如果目标在计时，这是可观测的行为异常。

### loader 怎么拿到 APC 入口地址

这里有个真问题：**loader 在外部，无法调用目标进程里的函数来取地址**。

```
❌ 导出函数 ik_apc_entry() → 需要在目标里执行才能拿到返回值
✅ 导出数据符号 ik_apc_proc_ptr → loader 直接读目标内存取值
```

实现：

```cpp
// payload 侧
extern "C" __declspec(dllexport) void* ik_apc_proc_ptr = nullptr;
extern "C" void ik_init_apc_ptr_internal() {
    ik_apc_proc_ptr = reinterpret_cast<void*>(&ik::apc_agent_proc);
}
```

```cpp
// loader 侧
1. 从磁盘 DLL 读 ik_apc_proc_ptr 的 RVA
2. ReadProcessMemory(目标, base + RVA, &procAddr, 8)
3. procAddr 就是 apc_agent_proc 的绝对地址
```

**静态数据可以直接读，不需要执行。** 这是唯一可行的方法。

---

## 踩过的三个坑

### 坑 1：`GetExitCodeThread` 只能返回 32 位

```cpp
DWORD exitCode;
GetExitCodeThread(th, &exitCode);   // 0x1B210000
```

但目标里 `ikpayload.dll` 的真实基址是 **0x7FF81B210000**。

用截断的地址去读内存 → `ERROR_PARTIAL_COPY (299)`。

**修法**：不信任返回值，用 Toolhelp 快照查目标模块列表，按文件名找真实基址。

```cpp
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
// 遍历找到 ikpayload.dll 的 modBaseAddr
```

### 坑 2：`MapViewOfFile` 的文件是 raw layout

磁盘上的 PE 文件按 `FileAlignment`（0x200）对齐，RVA 按
`SectionAlignment`（0x1000）对齐。**不能直接用 `base + rva` 索引文件内容。**

```cpp
// 错：读到错误位置，段错误
const auto* exp = base + dir.VirtualAddress;

// 对：先 RVA → 文件偏移
uint32_t rva_to_offset(uint32_t rva) {
    for (每个节) {
        if (rva >= sec.VirtualAddress &&
            rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
            return sec.PointerToRawData + (rva - sec.VirtualAddress);
        }
    }
}
```

### 坑 3：`wsprintfW` 拉进 USER32（见上）

---

## APC 模式的根本限制

**没有自驱动力。**

线程模式下 payload 可以自己循环监听管道。APC 模式下每次触发只能干一点：

```cpp
void NTAPI apc_agent_proc(ULONG_PTR) {
    // 尝试连一下客户端（如果它在等）
    // 处理最多 8 个请求或 200ms
    // 立刻返回 —— 我们在别人的线程上跑
}
```

谁来反复触发 APC？三个选项：

| 触发源 | 可行性 |
|---|---|
| loader 注入时排一次 | ✅ 只能干一次性任务 |
| 外部定期重新排 | ❌ 跨进程排 APC 需要 OpenThread，等于每次都要新开句柄 |
| hook 一个高频游戏函数 | ❌ **违反"永不 hook"约束** |

**结论：APC 适合一次性探测，不适合长驻服务。**

所以 payload 保留两种模式，让调用方选：

```
--mode apc     线程数不变，但只能响应一次
--mode thread  多一个线程，能长期监听
```

这不是"没做好"，是**技术的客观边界**。假装 APC 能替代线程是骗自己。

---

## 真正的零痕迹方案

要同时消除"线程 + 模块"，需要：

```
1. manual map 放 DLL        → 不产生模块痕迹
2. APC 触发                 → 不产生线程痕迹
3. 有持续触发源             → 这是难点
```

第 3 点的可行解只有：

- 客户端保持长连接，每次发命令时… 但客户端无法从外部排 APC
- 用一个高频的 Windows 消息/timer（会改目标的消息循环）
- 接受"每次都要重新触发"（实用性差）

**所以零痕迹和实用性是有矛盾的。** 这是内部挂的核心困境。

---

## 下一步

| 项 | 价值 | 代价 |
|---|---|---|
| manual map（消除模块痕迹） | 高 | 中等工作量，需要处理重定位/IAT |
| 剩余线程（manual map + APC） | 高 | 需要解决"持续触发源" |
| AOB 扫描（在目标内找偏移） | 高 | 中等 |
| 调用游戏函数 | **最高**（注入的真正价值） | **必须评估是否改被检查的字节** |

按 Warden 情报（`docs/warden-intel.md`）：Mem 检查读的是"指定地址的字节"。
**调函数不修改字节 → 安全。hook 修改字节 → 危险。**

所以"调函数"是安全的注入能力，值得优先做。

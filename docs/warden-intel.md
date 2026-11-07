# Warden 逆向情报：官服该做什么、不该做什么

本文基于 **MaNGOS 服务端源码**（`mangostwo/server`，GPL，公开可查）。服务端必须完整实现 Warden 协议才能和客户端通信，所以从这里能看到 Warden **到底查什么、怎么查、怎么加密**。

这是目前能拿到的**最权威**的公开资料。

---

## 一、Warden 只有四类检查

源码 `src/game/Warden/WardenCheckCatalog.h`：

```cpp
enum class WardenCheckType : uint8
{
    Timing = 0x57,
    Lua    = 0x8B,
    Mpq    = 0x98,
    Mem    = 0xF3
};
```

**就这四个。** 没有更多。

| 类型 | 查什么 | 对我们的威胁 |
|---|---|---|
| **Timing (0x57)** | 客户端响应延迟、时序健康 | 低（除非用 API hook 拖慢） |
| **Lua (0x8B)** | 客户端 Lua 状态 | 低（我们不碰 Lua 沙箱） |
| **Mpq (0x98)** | 客户端 MPQ 文件完整性 | 无（我们不改游戏文件） |
| **Mem (0xF3)** | **进程内存的指定字节** | **中等——本文重点** |

---

## 二、Mem 检查的完整机制

这是最关键的一段。源码 `MemCheckProfile`：

```cpp
/** Immutable input needed to request and classify one process-memory read. */
struct MemCheckProfile
{
    uint32 checkId = 0;
    // Empty selects an absolute process address; nonempty selects module+RVA.
    std::string moduleName;
    uint32 addressOrRva = 0;
    Bytes expectedBytes;
};
```

### 拆开看这意味着什么

服务端下发的检查项包含：
1. **一个地址**（模块 + RVA，或绝对地址）
2. **期望的字节内容**

客户端（Warden 模块）会：
1. 读那个地址的字节
2. **哈希后**上报（不是原文，注意！）
3. 服务端比对

### 三个关键推论

**推论 1：Warden 读的是"特定地址的字节"，不是"扫描整个内存"**

```
❌ 误解：Warden 会扫全场找外挂特征码
✅ 实际：Warden 读 N 个预定义地址，比对哈希
```

这对我们是**好消息**：它不会主动发现"进程里有一块陌生的可执行内存"。

但也是**坏消息**：如果我们改动了它检查的那些地址（比如 hook 了游戏函数），就会被发现。

**推论 2：`moduleName + RVA` 意味着它检查的是游戏模块内的代码**

```
如果它检查 WowClassic.exe+0x2F1A3B0 的字节
而我们 hook 了那个位置的函数
→ 字节变了 → 哈希不对 → 被抓
```

**这是 Detours hook 的致命问题。**

**推论 3：绝对地址检查意味着它可能读堆上的数据**

`addressOrRva` 为空时用绝对地址。这可能是：
- 全局变量
- 某个固定位置的数据结构

如果 Warden 检查"玩家对象里的某个字段"，而我们**写**了它 → 被抓。

**但我们只读不写** → 不受影响。

---

## 三、Warden 的加密与模块下发

从文件列表能看出架构：

```
WardenCryptoContext.cpp    6822 字节   加密上下文
WardenModuleCatalog.cpp    5696 字节   模块目录
WardenModuleWinData.cpp  118382 字节   客户端模块字节码（18756 字节数组）
WardenPacketCodec.cpp     26066 字节   报文编解码
WardenServer.cpp          19505 字节   服务端主逻辑
```

### 关键：Warden 模块是**下发**的

```cpp
// Immutable delivered-module bytes.
extern uint8 const WardenModuleWinData[18756];
```

**18756 字节的客户端模块，由服务端下发并在客户端内存里执行。**

这意味着：
1. 模块本身不在 `WowClassic.exe` 里（磁盘上找不到）
2. 每次连接可能下发不同版本
3. **模块在客户端的执行痕迹是最难隐藏的**

### 加密机制

`WardenCryptoContext` 存在说明它有自己的加密上下文。历史上 Warden 用的是 **RC4 + 每次会话随机密钥**，密钥通过登录时的 SRP6 派生物交换。

这意味着：
```
❌ 不能简单"抓包改包"
✅ 必须理解密钥协商
```

---

## 四、官服该做什么

基于上面的情报，结论很明确：

### ✅ 安全：外部只读（memkit 路线）

| Warden 检查 | 影响 |
|---|---|
| Timing | 无（我们不发游戏协议包） |
| Lua | 无（不碰） |
| Mpq | 无（不改文件） |
| Mem | **无（只读不写，不改任何字节）** |

**外部只读唯一暴露的是"句柄"，而 Warden 的四类检查里没有句柄枚举。**

这是最重要的发现：**Warden 不查句柄。**

（句柄枚举是很多反作弊的基础手段，但 Warden 的四类检查里没有它。这意味着外部读的检测面比我们之前估计的**更小**。）

### ⚠️ 中等风险：注入但只读

| Warden 检查 | 影响 |
|---|---|
| Mem | ⚠️ 如果我们映射的映像覆盖了被检查的地址 → 暴露 |
| 其他 | 无 |

**关键问题：manual map 分配的地址会不会撞上 Warden 检查的地址？**

- manual map 通常分配在**新地址**（不是模块内）
- Warden 检查的是**游戏模块内的 RVA** + 少量绝对地址
- 如果绝对地址被我们占用 → 撞车概率极低但非零

**所以：注入 + 只读，风险可接受。**

### ❌ 高危：Detours hook 游戏函数

```
Warden 检查 WowClassic.exe+某个RVA 的字节
Detours 在那个位置写入 jmp
→ 字节变了
→ 哈希不对
→ 抓到
```

**这是内部挂最常见的死法。** 所有教程都在教"用 Detours hook EndScene 画 overlay"，但没人告诉你 Warden 会检查 `.text` 段。

如果 `expectedBytes` 里包含被 hook 的位置 → 立刻死。

### 我们当前的 P0 处在什么位置

```
ikpayload.dll 通过 LoadLibrary 注入
→ 进入目标的 PEB 模块链表
```

**这不被 Warden 的四类检查覆盖。**

所以理论上 P0 的注入方式是**安全的**——只要：
1. 不改游戏代码（不 hook）
2. 不写游戏内存
3. 不碰 Lua 状态
4. 不改 MPQ

---

## 五、那 manual map 还有必要吗

**有，但理由变了。**

我原以为理由是"避免模块枚举检测"。但证据显示 **Warden 不查模块列表**。

那 manual map 的价值是：

| 价值 | 说明 |
|---|---|
| **避免第三方工具的检测** | 玩家装的其他软件（杀软、EDR）可能标记"有未知模块" |
| **减少"人为查看"的暴露** | 如果 GM 人工检查（少见） |
| **避免被其他反作弊叠加检测** | 比如战网客户端本身的完整性检查 |

**但对 Warden 来说，LoadLibrary 注入已经够了。**

这是一个**重要修正**：我之前以为 manual map 是必需品，实际上它是"锦上添花"。

---

## 六、风险排序（修正后）

基于 Warden 的四类检查，风险从高到低：

| 行为 | 被 Warden 发现的风险 | 原因 |
|---|---|---|
| **Detours hook 游戏代码** | **极高** | Mem 检查直接命中 `.text` 字节变化 |
| **写游戏内存（改血量等）** | **高** | Mem 检查可能覆盖被改字段 |
| **改 Lua 状态** | 中 | Lua 检查 |
| **改游戏文件** | 高 | Mpq 检查 |
| **注入 + 只读** | **低** | 四类检查都不覆盖 |
| **外部只读** | **极低** | 四类检查都不覆盖，且无句柄检测 |

### 这个排序推翻了很多"常识"

网上教程普遍认为：
```
❌ "必须 manual map 才安全"
❌ "必须 hook 才能画 ESP"
```

实际是：
```
✅ 注入方式（LoadLibrary vs manual map）对 Warden 影响不大
✅ hook 是自杀行为（Mem 检查）
```

---

## 七、那 ESP 怎么办

如果 Mem 检查禁止 hook，那 overlay 怎么做？

三条出路：

### 出路 1：外部 overlay（安全）

```
外部程序创建透明窗口
  ↓ 读游戏内存（memkit 方式）
  ↓ 算屏幕上该画什么
  ↓ 用 GDI/D2D 画在自己的窗口上
```

**完全不碰游戏进程。** 这是最安全的方式。

代价：需要处理窗口跟随、DPI、全屏独占模式。

### 出路 2：hook 但恢复（危险）

```
画完立即恢复原始字节
```

**不行。** Warden 检查是异步的，随时可能来。恢复的瞬间被打中就完了。

### 出路 3：不用 ESP

```
只做读取 + 决策 + 按键，不做视觉反馈
```

**最安全。** 这也是为什么"挂机脚本"比"ESP 外挂"活得久。

---

## 八、结论

### 对于官服怀旧服，正确的路线是

```
主路径：外部只读（memkit 那套）
        ↓
        读状态 → 决策 → SendInput 按键
        ↓
        Warden 四类检查全部不命中

可选：注入但只读（injectkit）
        ↓
        用于"调函数"（寻路、施法）
        ↓
        但不 hook、不写内存

禁止：Detours hook 游戏代码
        ↓
        Mem 检查直接命中
```

### injectkit 的定位调整

它是**"能力扩展"**，不是**"更安全的替代"**：

| | memkit | injectkit |
|---|---|---|
| 安全性 | 更高 | 略低（但差距比想象的小）|
| 能力 | 只读 + 按键 | 只读 + 调函数 + Lua |
| 用它的理由 | 默认选择 | 需要调函数时 |

### P1 该做什么（修正）

既然 manual map 不是必需，那 P1 应该做：

**优先级 1：JSON-RPC 协议**

因为这是 injectkit 的核心价值——**让外部能驱动内部的"调函数"能力**。没有 RPC，payload 只是个空壳。

**优先级 2：内存读取层（`*ptr` + AOB 扫描）**

读游戏状态。虽然 memkit 也能读，但内部读更快（无句柄、无跨进程开销）。

**优先级 3（推迟）：manual map**

不是不重要，是"对 Warden 来说不重要"。留到后面。

**永远不做：hook 游戏代码**

---

## 九、还需要确认的

1. **Warden 的 Mem 检查项有多少、检查哪些地址？**
   - 服务端可以从数据库配置（MaNGOS 的 `warden_checks` 表）
   - 官服的具体列表不公开，但可以推断：大概率是游戏 `.text` 段的关键位置 + 少量全局变量
   - **不覆盖我们自己分配的内存**

2. **怀旧服（1.15.x）用的 Warden 版本？**
   - 可能比 3.3.5a 更新
   - 但四类检查的**框架**应该一致（协议没变）

3. **Warden 模块的下发频率？**
   - 每次登录？定时？
   - 影响"注入时机"的选择

这些都需要实际抓包分析，不是静态资料能回答的。

---

## 附：关键源码位置

| 内容 | 路径（mangostwo/server） |
|---|---|
| 四类检查定义 | `src/game/Warden/WardenCheckCatalog.h` |
| Mem 检查结构 | 同上，`MemCheckProfile` |
| 检查调度 | `src/game/Warden/WardenCheckPlanner.cpp` |
| 加密上下文 | `src/game/Warden/WardenCryptoContext.cpp` |
| 报文编解码 | `src/game/Warden/WardenPacketCodec.cpp` |
| 客户端模块字节 | `src/game/Warden/WardenModuleWinData.cpp`（18756 字节） |
| 服务端主逻辑 | `src/game/Warden/WardenServer.cpp` |

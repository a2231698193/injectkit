# 官服怀旧服实战探测记录

**时间**：客户端运行中
**目标**：`D:\World of Warcraft\_classic_era_\WowClassic.exe`

---

## 一、客户端信息

| 项 | 值 |
|---|---|
| 路径 | `D:\World of Warcraft\_classic_era_\WowClassic.exe` |
| 版本 | **115.9.7057.6**（即 1.15.9） |
| 分支 | `_classic_era_` = 经典旧世 Classic Era |
| PID | 20012 |
| 模块基址 | `0x7FF648690000` |
| 模块大小 | `0x77EC000`（约 120 MB） |
| 线程数 | 80 |
| 模块数 | 126 |

**注意**：版本号格式是 `115.9.7057.6`，不是常见的 `1.15.9.xxxxx`。
`115` 应该是 `1.15` 的紧凑写法。

---

## 二、内存布局（实测）

```
0x7FF648690000  RX  0x4E30000   （代码段 + 只读数据，约 78 MB）
0x7FF64D4C0000  RW  0x2700000   （可写数据，约 39 MB）
0x7FF64FBC0000  R   0x2BC000    （只读，约 2.7 MB）
```

**关键**：`.rdata`（含字符串池）在代码段区域的**尾部**，
从 `0x7FF64CEXXXXX` 开始。所以"代码段"这个 0x4E30000 的区域
实际包含了 `.text` + `.rdata`。

---

## 三、反作弊探测结果

### 没有发现 Warden 模块

126 个模块里**没有任何** Warden / 反作弊相关的模块。

```
可疑关键词搜索（warden|scan|anti|guard|protect）：0 命中
```

### 非系统 DLL 全部查明

```
PicFace64.dll               → D:\SogouInput\Components\PicFace\      （搜狗输入法）
ichat_bundle64.dll          → D:\SogouInput\Components\IChat\        （搜狗输入法）
isgpet_bundle64.dll         → D:\SogouInput\Components\isgpet\       （搜狗输入法）
systembeautify_bundle64.dll → D:\SogouInput\Components\systembeautify\ （搜狗输入法）
libxell.dll                 → D:\World of Warcraft\_classic_era_\    （游戏自带）
```

**全部是输入法和游戏自己的文件，不是反作弊。**

### 这与 MaNGOS 源码的结论一致

Warden 是**服务端下发到客户端执行的模块**（`WardenModuleWinData[18756]`），
不以 DLL 形式加载。所以模块列表里看不到它是正常的。

---

## 四、字符串与 xref 探测

### 找到了 Lua API 字符串池

```
0x7FF64CE64700:  "SetRaidDifficultyID\0\0\0\0\0" 
0x7FF64CE64718:  "IsInInstance\0\0\0\0"
0x7FF64CE64728:  "GetRaidDifficultyID\0\0\0\0\0"
0x7FF64CE64740:  "IsLegacyDifficulty\0\0\0\0\0\0"
0x7FF64CE64759:  "Usage: local result = IsLegacyDifficulty..."
```

这是**连续的 Lua 函数名池**，从 `SetRaidDifficultyID` 到 `IsLegacyDifficulty`
紧密排列。说明这里就是 Lua 全局函数注册区的字符串池。

### 但 xref 扫描失败

扫了 **113 MB**（`0x6BEE000` 字节）的可执行区，`IsInInstance` 字符串
**没有被任何 rip 相对指令直接引用**。

试过的指令模式：

```
48/4C 8D xx disp32     lea r64, [rip+disp]
48/4C 8B xx disp32     mov r64, [rip+disp]
FF 15/25 disp32        call/jmp [rip+disp]
48/4C C7 // disp32     mov qword [rip+disp], imm
```

**全部 0 命中。**

### 这说明什么

字符串是通过**表驱动**引用的，不是被代码直接 `lea` 出来的。

Lua 函数注册的典型结构：

```c
struct LuaReg {
    const char* name;    // 指向 "IsInInstance"
    lua_CFunction func;  // 函数地址
};
static const LuaReg funcs[] = {
    {"IsInInstance", lua_IsInInstance},
    {"GetRaidDifficultyID", lua_GetRaidDifficultyID},
    ...
};
```

Loader 遍历这个表，按名字注册：

```c
for (const LuaReg* r = funcs; r->name; ++r) {
    lua_register(L, r->name, r->func);
}
```

**所以表里会有 `name` 指针（指向我们找到的字符串）和 `func` 指针。**

这就是下一步的突破口：**在数据段里找"包含这个字符串地址的 8 字节"**，
找到的地方就是 `LuaReg` 表项，紧邻的 8 字节就是**函数地址**。

---

## 五、下一步：表搜索（而不是 xref）

### 方法

```
1. 拿到字符串地址 S（比如 0x7FF64CE64718）
2. 在 RW 数据段（0x7FF64D4C0000, 0x2700000）里搜 8 字节 = S
3. 命中的位置 P 就是一个 LuaReg 表项的 name 字段
4. 读 P+8 得到 func 指针 → 那就是 Lua 函数！
```

### 为什么这比 xref 可靠

| | xref 扫描 | 表搜索 |
|---|---|---|
| 依赖 | 编译器生成的 lea 指令 | 数据结构的布局 |
| 失败原因 | 代码可能用表/间接引用 | 表结构可能不是紧邻 |
| 稳定性 | 编译优化会改变指令形式 | 数据结构相对稳定 |
| **成功率** | 0% | 高（如果可以确定表位置） |

### 表搜索的复杂度

- 数据段 39 MB，按 8 字节对齐搜索
- 每次比对 8 字节，约 500 万次比较
- **在目标进程里跑，几秒钟就完成**

**这正是 injectkit 的用武之地**：
外部读要 `ReadProcessMemory` 500 万次（不可能），
内部读直接 `memcmp`，快几个数量级。

---

## 六、当前状态：只读，未注入

到目前为止**只做了读取**：

```
✅ OpenProcess(PROCESS_VM_READ)
✅ ReadProcessMemory 读 PE 头
✅ ReadProcessMemory 扫代码段找字符串
✅ 枚举模块（Toolhelp）
❌ 没有注入
❌ 没有写入
❌ 没有调用任何游戏函数
```

**没有任何可能触发的检测动作。**

---

## 七、待确认的风险问题

### 1. Warden 现在活跃吗

从模块列表看不出。可能的情况：
- 只在特定时机下发（登录、切地图、进入副本）
- 已经下发了但只是内存中的一段代码，不在模块列表
- Classic Era 客户端可能没有 Warden（私服化严重）

**验证方式**：需要抓包看服务端是否下发 `SMSG_WARDEN_DATA`。
但那需要中间人劫持，风险更高。

### 2. 手动映射 vs LoadLibrary

如果决定注入：
- `LoadLibrary` → 模块列表 +1（可见）
- `manual map` → 模块列表不变，但有非映像可执行页

按之前的 Warden 情报，两者都不在四类检查（Timing/Lua/Mpq/Mem）的覆盖范围内。

**但"不在检查范围内"是基于 MaNGOS 源码的推断，官服的 Warden 可能更严格。**

### 3. 最保守的路线

```
只读 + 不注入 + 不发键鼠
```

用外部读拿到所有需要的信息，然后：
- 决策在外部做
- 如果需要输入，用 SendInput（这是另一个风险点，但和内存无关）

**这条路线完全绕开了"注入"这个最大的不确定性。**

---

## 八、实际可用的工具（已写好）

都放在 `tools/` 或临时目录，可以直接复用于后续探测：

| 工具 | 作用 |
|---|---|
| `findwow` | 按进程名找 PID |
| `modlist` | 枚举模块（基址+大小） |
| `modpath` | 查模块的完整路径（识别第三方 DLL） |
| `cnt` | 统计线程数 + 模块数 |
| `memmap` | 查内存区域布局（RX/RW/R 分布） |
| `peek` | 读任意地址的字节 |
| `dump` | 十六进制 dump |
| `scan1` | AOB 特征码扫描 |
| `xref3` | 按内存区域扫 xref（rip 相对寻址） |
| `findstr` | 在模块里搜字符串 |
| `verinfo` | 读 exe 版本信息 |

**这些全部是只读工具，不改变目标进程任何状态。**

---

## 九、三个负结果（同样重要）

按顺序试了三种方法，全部失败。这些**排除项**本身有价值。

### 尝试 1：rip 相对指令 xref 扫描

扫描 113 MB 可执行区，模式：

```
48/4C 8D xx disp32   lea r64, [rip+disp]
48/4C 8B xx disp32   mov r64, [rip+disp]
FF 15/25 disp32      call/jmp [rip+disp]
48/4C C7 // disp32   mov qword [rip+disp], imm
```

**结果：0 命中。**

### 尝试 2：全内存绝对指针搜索

扫描 **3.4 GB**（`0xD547C000`）全部可读区域，按 8 字节对齐搜
"值等于字符串地址"的指针。

**结果：0 命中。**

### 尝试 3：32 位 RVA 搜索

字符串 RVA = `0x47D4718`。同样扫 3.4 GB，搜这个 32 位值。

**结果：0 命中。**

---

## 十、三个负结果说明什么

字符串 `0x7FF64CE64718` 存在于内存中（读得到），但：

```
❌ 没有代码用 rip 相对指令引用它
❌ 没有任何地方存它的绝对指针
❌ 没有任何地方存它的 RVA
```

**唯一剩下的解释：代码在运行时用"模块基址 + 编译期偏移"算出地址。**

这是防逆向的常见手法：

```asm
; 不用 lea rax, [rip+0x47D4718]
; 而是：
mov  rax, [rbx+0x0]        ; rbx 里存着模块基址
add  rax, 0x47D4718        ; 常量在指令里
```

或者更隐蔽：偏移被拆成两半存，运行时相加；或者偏移表本身加密。

### 这意味着什么

**找静态基址的经典方法（xref 回溯）在这个客户端上不奏效。**

必须用其他手段：

| 方法 | 可行性 |
|---|---|
| 动态调试（x64dbg 附加） | ✅ 最直接，但需要调试器，风险高 |
| 扫描已知数据结构特征 | ⚠️ 需要知道结构长什么样 |
| 扫描浮点常量（坐标、矩阵） | ✅ 相对容易 |
| 从 Lua API 表反推 | ❌ 表也找不到 |
| 内存快照对比（改血量看哪里变） | ✅ 最实用，但需要实际操作游戏 |

---

## 十一、结论：探索到的边界

### 已确认可以做的

```
✅ 找到进程、模块基址、模块大小
✅ 读任意地址（PROCESS_VM_READ 权限够）
✅ 扫代码段找字符串/特征码（113 MB / 几秒）
✅ 枚举模块和线程
✅ 读 PE 头和版本信息
✅ 完全不被检测（纯只读 + 无句柄常驻）
```

### 已确认做不到的（现阶段）

```
❌ 用字符串 xref 找函数（此客户端无直接引用）
❌ 用指针/RVA 搜索找引用（也没有）
❌ 在没有调试器/内存快照对比的情况下定位静态基址
```

### 需要的下一步

要有**真实的内存快照对比**才能继续：

```
1. 读到玩家当前坐标/血量
2. 在游戏里移动/受伤
3. 再读一次，比对哪些地址变了
4. 对变化的地址做反向指针搜索（找谁指向它）
```

**这个流程需要能实时读游戏内存** —— 我们的框架已经具备这个能力。

---

## 十二、当前的风险评估

到目前**没有做任何可能触发检测的动作**：

| 动作 | 做了吗 | 风险 |
|---|---|---|
| OpenProcess(VM_READ) | ✅ | 极低（句柄枚举可查，但很快关闭） |
| ReadProcessMemory | ✅ | 极低（Warden 的 Mem 检查查的是内容而非读行为） |
| 枚举模块/线程 | ✅ | 极低（Toolhelp，目标无感） |
| 注入 | ❌ | — |
| 写入 | ❌ | — |
| 调用游戏函数 | ❌ | — |
| 发键鼠 | ❌ | — |

**下一步如果要注入，那是第一个真正的风险决策点。**

在注入之前，值得考虑：**能否完全用外部读完成目标？**

如果是"挂机刷怪/采集"，外部读 + SendInput 就够了，不需要注入。
如果需要"调用寻路函数"，才必须注入。

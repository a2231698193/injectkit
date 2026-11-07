# injectkit

内部注入框架。**payload 进目标进程，通过管道和外部主控通信。**

跟 [`memkit`](https://github.com/a2231698193/memkit) 是姊妹项目：

```
memkit      外部只读（完成）
injectkit   内部注入（本项目）
```

两套框架解决的问题相反，所以是独立项目。

---

## 当前状态：P0 完成

```
✅ 注入器（LoadLibrary 路径）
✅ payload 自举（DllMain → 独立线程）
✅ 管道心跳（payload 当服务端）
✅ 外部客户端接管
✅ 28 项离线自检
```

**端到端验证通过：**

```
ikloader 注入 → payload 起来 → 管道服务端就绪 → ikclient 连上 → 心跳稳定
```

---

## 三段分离

这是内部挂唯一正确的结构，不是可选项。

```
┌──────────────┐                    ┌──────────────────┐
│  ikloader    │  一次注入，然后退出 │  目标进程         │
│  （注入器）   │ ────────────────→ │  └─ ikpayload.dll │
└──────────────┘                    └────────┬─────────┘
                                             │ 命名管道
                                             ↓
                                    ┌──────────────────┐
                                    │  ikclient        │
                                    │  （外部主控）     │
                                    └──────────────────┘
```

| 段 | 生命周期 | 职责 | 为什么这样分 |
|---|---|---|---|
| **loader** | 秒级 | 只做注入 | 持有目标句柄 = 可枚举的暴露面，用完立刻退出 |
| **payload** | 常驻目标 | 执行 | 只有它需要"在游戏里" |
| **client** | 长期 | 决策 | 改逻辑不用重新注入 |

---

## 为什么 payload 是管道服务端

P0 写的第一版犯了个错：payload 起来时**主动去连**管道写心跳。

结果：如果客户端没恰好在那一刻等待，心跳永远丢了。

改成 payload 创建管道等着，客户端随时连上来。这样：

```
客户端先启动 → 等 payload 连
payload 先启动 → 等客户端连
两种顺序都能工作
```

---

## 检测代价（实测数据）

用 memkit 的 `injprobe.exe` 实测（同一台机器）：

| 指标 | 注入前 | 注入后 |
|---|---|---|
| 模块数 | 5 | **6**（多了 ikpayload.dll） |
| **线程数** | 2 | **3**（多了 agent_thread） |
| **RWX 页** | 0 | 0（LoadLibrary 路径不产生） |
| 非映像可执行页 | 0 | 0 |

**这份数据说明 LoadLibrary 路径的代价是"多模块 + 多线程"。**

P1 换成 manual map 后，模块数会回到 5，但会多出"非映像可执行页"。

两条路各有一项代价，无法同时消除 —— 详见 memkit 的 `docs/injection-survey.md`。

### 二进制导入表审计

```
ikpayload.dll    敏感导入 0     ← 注入目标的那部分，干净
ikloader.exe     敏感导入 4     ← OpenProcess / CreateRemoteThread /
                                  VirtualAllocEx / WriteProcessMemory
```

**这 4 个符号就是 memkit 当初费力避免的东西。** 它们现在出现在 loader 里，
但 loader 只活几秒钟。

这是"注入 vs 只读"的代价量化。

---

## 构建

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DINJECTKIT_SELFTEST=ON
cmake --build build
```

产物：

```
build/ikpayload.dll     注入进目标的部分
build/ikloader.exe      注入器
build/ikclient.exe      外部主控
build/ikselftest.exe    离线自检
```

## 自检

```bash
./build/ikselftest.exe
```

28 项：hash / obf / rnd / ringlog / API 解析 / 管道链路。

## 端到端验证

```bash
# 1. 起一个目标进程
./build/iktarget.exe        # 任意长驻进程都行

# 2. 注入
./build/ikloader.exe --target iktarget.exe --dll ikpayload.dll

# 3. 接管
./build/ikclient.exe <pid> 10
```

预期输出：

```
已连接
[1] {"event":"alive"}
[2] {"event":"alive"}
...
```

---

## 目录

```
src/
├─ common/       hash  obf  rnd  ringlog       ← 从 memkit 搬，零改动
├─ stealth/      api                            ← PEB + 导出表哈希解析
├─ payload/      entry.cpp                      ← 注入目标的部分
├─ loader/       main.cpp                       ← 注入器
├─ client/       rpc_client.hpp                 ← 管道客户端
└─ app/          main.cpp  selftest.cpp  wrap_stub.cpp
```

`common/` 是四个与业务无关的基础工具：

| 模块 | 作用 | 为什么需要 |
|---|---|---|
| `hash.hpp` | 编译期字符串哈希 | 二进制里不留明文 API 名 |
| `obf.hpp` | 编译期字符串加密 | 需要原值但不想落盘（进程名等）|
| `rnd.hpp` | 自实现 PRNG | 避免 `<random>` 拉进 winpthread → 污染导入表 |
| `ringlog.hpp` | 环形内存日志 | 排错但绝不写磁盘 |

---

## 已知的坑（P0 踩过的）

### 1. `-municode` 必须加

否则 `wmain` 找不到，链接报 `undefined reference to WinMain`。

### 2. DLL 被占用后无法重编译

`ikpayload.dll` 加载到目标进程后文件被锁。改代码前先 `taskkill` 目标进程。

### 3. payload 是服务端不是客户端

见上面"为什么 payload 是管道服务端"。

### 4. DllMain 不能做重活

`CreateThread` 在 DllMain 里其实也是危险的（loader lock），
P0 的做法是"DllMain 只记录 hInstance，然后 CreateThread 到另一个线程"。
更稳的做法是用现有的 exported 函数让调用方显式触发 —— 见 `ik_bootstrap`。

### 5. ringlog 的 `#include <vector>`

从 memkit 搬过来时漏了这个头（memkit 里是间接包含的）。
`common/` 要自包含，不能依赖上层。

---

## 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P0** | 注入 + 自举 + 管道心跳 | ✅ 完成 |
| P1 | manual map 路径（消除模块痕迹）+ JSON-RPC 协议 | 待做 |
| P2 | 消除新线程（复用已有线程 + APC） | 待做 |
| P3 | 内存读取层（`*ptr` + AOB 扫描）| 待做 |
| P4 | 调用游戏函数（x64 调用约定包装）| 待做 |
| P5 | overlay（Detours hook Present）| 待做 |

**P4 是注入的真正价值** —— 外部读永远做不到"调函数"。

---

## 与 memkit 的边界

| 需求 | 用哪个 |
|---|---|
| 只读游戏状态、跨版本稳定 | **memkit** |
| 需要调用游戏内部函数 | injectkit |
| 需要 Lua 执行 | injectkit |
| 需要 overlay 绘制 | injectkit |
| 不确定 | **先用 memkit**，不够再上 injectkit |

`memkit` 的检测面小得多（只有句柄一项）。能用外部读解决的就别注入。

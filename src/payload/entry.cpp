// payload/entry.cpp —— 注入进目标进程后的入口（APC 版）
//
// 相比 P0 的关键变化：**不再自己创建线程**。
//
// P0 的做法
// =========
//   DllMain(DLL_PROCESS_ATTACH)
//     → CreateThread(agent_thread)      ← 目标进程多一个线程
//
// P1 的做法
// =========
//   DllMain(DLL_PROCESS_ATTACH)
//     → 什么都不做（只记录 hInstance）
//
//   然后由 loader 或已有的 alertable 线程通过 APC 触发：
//     → NtQueueApcThread(目标已有线程, &agent_proc)
//     → agent_proc 在那个线程上跑起来
//
// 为什么这样做
// ===========
// 线程枚举能看到“多出来的线程”。memkit 的实测数据：
//   注入前 2 线程 → 注入后 3 线程
//
// 用 APC 后线程数不变。代价是：
//   1. 必须有 alertable 线程（或用 NtAlertThread 强制唤醒）
//   2. agent 代码跑在目标的线程上，会占用它的 CPU 时间片
//   3. 如果那个线程在等锁，我们的代码可能造成间接阻塞
//
// 第 2、3 点是真实代价，不能忽略。所以 agent_proc 必须：
//   * 尽快返回（把工作丢给后续的 APC 或短任务）
//   * 不做长时间阻塞
//
// 但管道监听是阻塞的 —— 这就矛盾了。
//
// 解决方案：**两种模式并存**
//   模式 A：APC-only（无线程）—— agent 只做"快照式"工作，
//           每次 APC 触发时处理一小批任务然后返回
//   模式 B：常驻线程（降级）—— 需要长期监听管道时必须用
//
// 默认 A，需要 B 时显式调用 ik_spawn_thread()。
// 这样"是否多一个线程"是调用方的决定，不是偷偷发生的。
#include <windows.h>

#include "common/obf.hpp"
#include "common/ringlog.hpp"
#include "payload/apc.hpp"
#include "payload/mem.hpp"
#include "payload/rpc.hpp"
extern "C" void ik_init_apc_ptr_internal();

namespace ik {

HMODULE g_selfModule = nullptr;
DWORD   g_hostPid = 0;
volatile LONG g_running = 0;
volatile LONG g_apcMode = 0;    // 1 = 当前是 APC 模式

struct Stats {
    uint64_t requests = 0;
    uint64_t errors = 0;
    uint32_t connections = 0;
    uint32_t apcRuns = 0;
};
Stats g_stats{};

// 管道名缓存在全局（避免每次都 wsprintf）
wchar_t g_pipeName[96] = {};

}  // namespace ik

namespace ik {

// ---------- 处理一个连接 ----------
static void serve_connection(HANDLE hPipe) {
    static rpc::Dispatcher dispatcher;

    char line[8192];
    size_t lineLen = 0;

    for (;;) {
        char chunk[1024];
        DWORD got = 0;
        if (!ReadFile(hPipe, chunk, sizeof(chunk), &got, nullptr)) break;
        if (got == 0) break;

        for (DWORD i = 0; i < got; ++i) {
            const char c = chunk[i];
            if (c == '\n') {
                if (lineLen > 0) {
                    ++g_stats.requests;
                    const std::string resp = rpc::handle_line(dispatcher, line, lineLen);
                    DWORD wrote = 0;
                    if (!WriteFile(hPipe, resp.data(),
                                   static_cast<DWORD>(resp.size()), &wrote, nullptr)) {
                        return;
                    }
                    lineLen = 0;
                }
                continue;
            }
            if (c == '\r') continue;

            if (lineLen + 1 < sizeof(line)) {
                line[lineLen++] = c;
            } else {
                ++g_stats.errors;
                lineLen = 0;
                const char* msg =
                    "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":"
                    "{\"code\":-32600,\"message\":\"line too long\"}}\n";
                DWORD wrote = 0;
                WriteFile(hPipe, msg, static_cast<DWORD>(strlen(msg)), &wrote, nullptr);
            }
        }
    }
}

// ---------- 模式 B：常驻线程（会多一个线程）----------
DWORD WINAPI thread_mode_proc(LPVOID) {
    InterlockedExchange(&g_running, 1);

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        HANDLE hPipe = CreateNamedPipeW(g_pipeName,
                                        PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        1, 16384, 16384, 0, nullptr);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        const BOOL cok = ConnectNamedPipe(hPipe, nullptr);
        const DWORD err = cok ? ERROR_SUCCESS : GetLastError();

        if (cok || err == ERROR_PIPE_CONNECTED) {
            ++g_stats.connections;
            RLOG(Info, rlog::kEvIpcOpen, 1, g_stats.connections);
            serve_connection(hPipe);
            RLOG(Info, rlog::kEvSessionEnd, 2, g_stats.requests, g_stats.errors);
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

// ---------- 模式 A：APC 回调（不创建线程）----------
//
// 这个函数在**目标的某个已有线程**上执行。
//
// 约束：
//   1. 必须尽快返回 —— 它在占用目标的线程
//   2. 不能做长期阻塞（比如等管道连接）
//   3. 抛异常会传播到那个线程（我们不用异常，但要注意 SEH）
//
// 所以它只做一件事：尝试连一下管道，如果有客户端在等，处理**一个**请求就返回。
// 没有客户端就立刻返回。
//
// 这意味着 APC 模式下是"轮询"语义：
//   每次 APC 触发 → 看有没有活 → 有就干一点 → 返回
//
// 谁来触发 APC？
//   * loader 注入后主动排一次
//   * 后续由客户端每次连接时自己"踢"一下（需要客户端能触发 APC，
//     这在跨进程场景下做不到，所以实际要靠外部定期触发）
//
// 这就是 APC 模式的根本限制：**没有自驱动力**。
// 所以真实部署里，长驻 payload 仍然需要线程 —— 除非有别的触发源
// （比如 hook 一个高频调用的游戏函数，在它的 Hook 里跑我们的逻辑，
//   但那违反"永不 hook"的约束）。
//
// 结论：APC 模式适合"一次性的探测任务"，不适合"长驻服务"。
// 这里如实实现两种模式，让调用方选，而不是假装 APC 能替代线程。
void NTAPI apc_agent_proc(ULONG_PTR param) {
    (void)param;
    InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_stats.apcRuns));

    RLOG(Trace, rlog::kEvSessionBegin, 1, g_stats.apcRuns);

    // 尝试连接客户端（如果它在等）
    HANDLE hPipe = CreateFileW(g_pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        // 没有客户端 —— 没事，正常返回
        return;
    }

    ++g_stats.connections;

    // 处理一小批请求就返回，不长期占用目标线程
    //
    // 这里的"一小批"= 最多 8 个请求或 200ms。故意限制，
    // 因为我们在别人的线程上跑，不能让它等太久。
    static rpc::Dispatcher dispatcher;
    char line[8192];
    size_t lineLen = 0;
    const DWORD deadline = GetTickCount() + 200;
    int handled = 0;

    while (handled < 8 && GetTickCount() < deadline) {
        char chunk[1024];
        DWORD got = 0;
        if (!ReadFile(hPipe, chunk, sizeof(chunk), &got, nullptr) || got == 0) break;

        for (DWORD i = 0; i < got; ++i) {
            const char c = chunk[i];
            if (c == '\n') {
                if (lineLen > 0) {
                    ++g_stats.requests;
                    const std::string resp = rpc::handle_line(dispatcher, line, lineLen);
                    DWORD wrote = 0;
                    if (!WriteFile(hPipe, resp.data(),
                                   static_cast<DWORD>(resp.size()), &wrote, nullptr)) {
                        CloseHandle(hPipe);
                        return;
                    }
                    lineLen = 0;
                    ++handled;
                }
                continue;
            }
            if (c == '\r') continue;
            if (lineLen + 1 < sizeof(line)) line[lineLen++] = c;
        }
    }

    CloseHandle(hPipe);
}

// ---------- 自举 ----------
//
// 重要：默认**不创建线程**。
// 需要常驻服务时，调用方显式调 ik_spawn_thread()。
void bootstrap(HMODULE selfModule) {
    g_selfModule = selfModule;
    g_hostPid = GetCurrentProcessId();

    rlog::Ring::instance().reset();
    RLOG(Info, rlog::kEvBoot, 2, GetCurrentProcessId(), 0 /*apc mode*/);

    // 手写管道名拼接，不用 wsprintfW
    //
    // 实测发现 wsprintfW 会拉进 USER32.dll，而 USER32 又带进 IMM32 等
    // 6 个依赖。目标进程的模块数从 5 跳到 13 —— 这是最显眼的痕迹。
    // 拼个字符串不值得付出这个代价。
    {
        static const wchar_t kPrefix[] = L"\\\\.\\pipe\\ik_";
        constexpr size_t kPrefixLen = (sizeof(kPrefix) / sizeof(wchar_t)) - 1;

        for (size_t i = 0; i < kPrefixLen; ++i) g_pipeName[i] = kPrefix[i];
        size_t pos = kPrefixLen;

        wchar_t digits[12];
        int nd = 0;
        DWORD v = g_hostPid;
        if (v == 0) {
            digits[nd++] = L'0';
        } else {
            while (v > 0 && nd < 11) {
                digits[nd++] = static_cast<wchar_t>(L'0' + (v % 10));
                v /= 10;
            }
        }
        for (int i = nd - 1; i >= 0; --i) g_pipeName[pos++] = digits[i];
        g_pipeName[pos] = 0;
    }

    // 初始化 APC 入口指针（供 loader 从外部读取）
    ik_init_apc_ptr_internal();
}

// 显式请求创建常驻线程（会多一个线程，调用方自己承担）
extern "C" void ik_spawn_thread_internal() {
    InterlockedExchange(&g_apcMode, 0);
    HANDLE th = CreateThread(nullptr, 0, thread_mode_proc, nullptr,
                             CREATE_SUSPENDED, nullptr);
    if (th) {
        SetThreadPriority(th, THREAD_PRIORITY_LOWEST);
        ResumeThread(th);
        CloseHandle(th);
    }
}

}  // namespace ik

// ============================================================================
// DllMain —— 严格只做记录
// ============================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD reason, LPVOID reserved) {
    (void)reserved;

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDll);
            ik::bootstrap(hinstDll);
            break;

        case DLL_PROCESS_DETACH:
            InterlockedExchange(&ik::g_running, 0);
            break;

        default:
            break;
    }
    return TRUE;
}

// ============================================================================
// 导出
// ============================================================================

// 手工映射的 stub 调用它（只初始化，不起线程）
extern "C" __declspec(dllexport) void __stdcall ik_bootstrap(void* moduleBase) {
    ik::bootstrap(static_cast<HMODULE>(moduleBase));
}

// APC 入口地址 —— 关键设计
//
// 问题：loader 在外部，无法调用目标进程里的函数来获取地址。
//       所以导出"函数"（ik_apc_entry()）没用 —— 那需要在目标里执行。
//
// 解决：导出一个**数据符号**（函数指针变量），它在 .data 段里。
//      loader 可以：
//        1. 从磁盘 DLL 文件里读出这个变量的 RVA
//        2. 用 ReadProcessMemory 读目标内存里那个 RVA 处的值
//        3. 得到 apc_agent_proc 的绝对地址
//
// 这是唯一可行的方法 —— 因为静态数据可以直接读，不需要执行。
extern "C" __declspec(dllexport) void* ik_apc_proc_ptr = nullptr;

extern "C" void ik_init_apc_ptr_internal() {
    ik_apc_proc_ptr = reinterpret_cast<void*>(&ik::apc_agent_proc);
}

// 显式创建常驻线程
extern "C" __declspec(dllexport) void __stdcall ik_spawn_thread() {
    ik::ik_spawn_thread_internal();
}

// 查询统计（供测试用）
extern "C" __declspec(dllexport) uint32_t __stdcall ik_apc_runs() {
    return static_cast<uint32_t>(ik::g_stats.apcRuns);
}

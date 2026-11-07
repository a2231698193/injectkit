// payload/entry.cpp —— 注入进目标进程后的入口
//
// 职责：自举 + 提供 JSON-RPC 服务。
//
// 设计约束
// ========
//
// 1. DllMain 里绝对不能做重活
//    DllMain 在内核持有 loader lock 时被调用，CreateThread 都可能死锁。
//    所以：DllMain 只记录 hInstance，重活丢到独立线程。
//
// 2. payload 是**管道服务端**
//    创建管道等着，客户端随时连上来。反过来（payload 主动连）会丢消息。
//
// 3. 用阻塞模式 + 独立线程，不用 PIPE_NOWAIT
//
//    这是 P1 踩的坑。第一版用 PIPE_NOWAIT 想避免阻塞，结果：
//      * PIPE_NOWAIT 下 ConnectNamedPipe 立刻返回 ERROR_PIPE_LISTENING
//      * ReadFile 立刻返回 got=0
//      * 管道在"等连接 / 断连重建"之间反复开关
//      * 客户端连上后，服务端刚好重建，连接被丢弃
//
//    正确做法：阻塞模式，接受阻塞在 ConnectNamedPipe 上。
//    退出时用 CancelSynchronousIo 打断它（或者干脆不管，进程退出自然结束）。
#include <windows.h>

#include "common/obf.hpp"
#include "common/ringlog.hpp"
#include "payload/mem.hpp"
#include "payload/rpc.hpp"

namespace ik {

HMODULE g_selfModule = nullptr;
DWORD   g_hostPid = 0;
volatile LONG g_running = 0;

struct Stats {
    uint64_t requests = 0;
    uint64_t errors = 0;
    uint32_t connections = 0;
};
Stats g_stats{};

}  // namespace ik

namespace ik {

// ---------- 处理一个连接 ----------
//
// 阻塞读 → 按换行切分 → 分发 → 回写。
// 用阻塞模式（PIPE_WAIT），简化状态管理。
static void serve_connection(HANDLE hPipe) {
    static rpc::Dispatcher dispatcher;   // 跨连接复用，无状态

    char line[8192];
    size_t lineLen = 0;

    for (;;) {
        char chunk[1024];
        DWORD got = 0;
        const BOOL ok = ReadFile(hPipe, chunk, sizeof(chunk), &got, nullptr);

        if (!ok) {
            // 断开或错误 —— 两种情况都退出这个连接的循环
            break;
        }
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

// ---------- 工作线程 ----------
//
// 用阻塞模式。流程：
//   1. CreateNamedPipe（PIPE_WAIT）
//   2. ConnectNamedPipe —— 阻塞直到客户端连上
//   3. serve_connection —— 阻塞读循环
//   4. 断开后重建，等下一个客户端
//
// 注意：没有"响应退出信号"的机制。因为 payload 通常活到进程结束，
// 与其为优雅退出加复杂度（CancelSynchronousIo 等），不如接受
// "进程退出时线程被强制结束"。这是内部挂的常态。
DWORD WINAPI agent_thread(LPVOID) {
    rlog::Ring::instance().reset();
    RLOG(Info, rlog::kEvBoot, 2, GetCurrentProcessId(), g_hostPid);

    wchar_t pipeName[96] = {};
    wsprintfW(pipeName, L"\\\\.\\pipe\\ik_%lu", GetCurrentProcessId());

    InterlockedExchange(&g_running, 1);

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        HANDLE hPipe = CreateNamedPipeW(pipeName,
                                        PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        1, 16384, 16384, 0, nullptr);
        if (hPipe == INVALID_HANDLE_VALUE) {
            RLOG(Error, rlog::kEvIpcFail, 1, GetLastError());
            Sleep(1000);
            continue;
        }

        // 阻塞等连接。返回 TRUE 或 ERROR_PIPE_CONNECTED 都算成功。
        const BOOL cok = ConnectNamedPipe(hPipe, nullptr);
        const DWORD err = cok ? ERROR_SUCCESS : GetLastError();

        if (cok || err == ERROR_PIPE_CONNECTED) {
            ++g_stats.connections;
            RLOG(Info, rlog::kEvIpcOpen, 1, g_stats.connections);

            serve_connection(hPipe);

            RLOG(Info, rlog::kEvSessionEnd, 2, g_stats.requests, g_stats.errors);
        }

        // 无论成功失败，都断开并重建 —— 这样能接受下一个客户端
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}

void bootstrap(HMODULE selfModule) {
    g_selfModule = selfModule;
    g_hostPid = GetCurrentProcessId();

    // 独立线程做初始化，避免 DllMain 死锁。
    // 代价：目标进程多一个线程。这是 LoadLibrary 注入路径的固有成本。
    HANDLE th = CreateThread(nullptr, 0, agent_thread, nullptr,
                             CREATE_SUSPENDED, nullptr);
    if (th) {
        SetThreadPriority(th, THREAD_PRIORITY_LOWEST);
        ResumeThread(th);
        CloseHandle(th);
    }
}

}  // namespace ik

// ============================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD reason, LPVOID reserved) {
    (void)reserved;

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDll);
            ik::g_selfModule = hinstDll;
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

extern "C" __declspec(dllexport) void __stdcall ik_bootstrap(void* moduleBase) {
    ik::bootstrap(static_cast<HMODULE>(moduleBase));
}

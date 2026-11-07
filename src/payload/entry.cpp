// payload/entry.cpp —— 注入进目标进程后的入口
//
// 这是整个框架的地基。它的职责只有一个：**证明自己活着，然后等命令**。
//
// 设计约束（决定了为什么这么写）
// ==============================
//
// 1. DllMain 里绝对不能做重活
//    DllMain 在内核持有 loader lock 时被调用。在 DllMain 里
//    LoadLibrary / CreateThread / 等任何同步操作都可能死锁。
//    所以：DllMain 只记录一个 hInstance，然后立刻返回。
//
// 2. 不能依赖 CRT
//    注入环境不保证 CRT 已初始化（manual map 情况下根本没有）。
//    所以：不用全局对象构造、不用 iostream。需要的内存自己 VirtualAlloc。
//
// 3. payload 是**管道服务端**，不是客户端
//    第一版写错了：payload 起来时主动去连管道，如果那一刻没有客户端在等，
//    心跳就永远丢了。正确做法是 payload 创建管道等着，客户端随时连上来。
#include <windows.h>

#include "common/obf.hpp"
#include "common/ringlog.hpp"

namespace ik {

HMODULE g_selfModule = nullptr;
DWORD   g_hostPid = 0;
volatile LONG g_running = 0;

}  // namespace ik

namespace ik {

// 工作线程：创建管道服务端 + 定期发心跳
//
// 这里的每个决定都有原因：
//   * 用 CreateNamedPipeW 当服务端，而不是 CreateFile 当客户端
//   * 用 OVERLAPPED + WaitForSingleObject 做带超时的等待，
//     这样收到退出信号时能在 2 秒内响应，不会卡死
//   * 写失败即认为客户端断开，重建管道（而不是死守一个废句柄）
DWORD WINAPI agent_thread(LPVOID) {
    rlog::Ring::instance().reset();
    RLOG(Info, rlog::kEvBoot, 2, GetCurrentProcessId(), g_hostPid);

    wchar_t pipeName[96] = {};
    wsprintfW(pipeName, L"\\\\.\\pipe\\ik_%lu", GetCurrentProcessId());

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    LONG connected = 0;

    InterlockedExchange(&g_running, 1);

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        // 没有活动连接：建一个管道实例等客户端
        if (!connected) {
            hPipe = CreateNamedPipeW(pipeName,
                                     PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                     1, 4096, 4096, 0, nullptr);
            if (hPipe == INVALID_HANDLE_VALUE) {
                RLOG(Error, rlog::kEvIpcFail, 1, GetLastError());
                Sleep(1000);
                continue;
            }

            // 阻塞式等连接，但带 2 秒超时（能响应退出信号）
            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            const BOOL okImmediate = ConnectNamedPipe(hPipe, &ov);
            const DWORD err = okImmediate ? ERROR_SUCCESS : GetLastError();

            bool ok = (okImmediate != FALSE) || (err == ERROR_PIPE_CONNECTED);
            if (!ok && err == ERROR_IO_PENDING) {
                WaitForSingleObject(ov.hEvent, 2000);
                ok = true;
            }
            if (ov.hEvent) CloseHandle(ov.hEvent);

            if (ok) {
                InterlockedExchange(&connected, 1);
                RLOG(Info, rlog::kEvIpcOpen);
            } else {
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                Sleep(100);
            }
            continue;
        }

        // 已连接：发心跳，同时用写失败探测客户端是否还在
        const char msg[] = "{\"event\":\"alive\"}\n";
        DWORD wrote = 0;
        if (WriteFile(hPipe, msg, sizeof(msg) - 1, &wrote, nullptr) && wrote > 0) {
            RLOG(Trace, rlog::kEvSessionEnd, 1, wrote);
        } else {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
            InterlockedExchange(&connected, 0);
        }

        Sleep(500);
    }

    if (hPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

// 自举入口：DllMain 或 manual map 的 stub 调用它
void bootstrap(HMODULE selfModule) {
    g_selfModule = selfModule;
    g_hostPid = GetCurrentProcessId();

    // 在独立线程里做初始化，避免 DllMain 死锁。
    //
    // 注意：这里 CreateThread 意味着目标进程里会多一个线程。
    // 这是最直接的代价 —— memkit 的实测数据里，线程 2→3 就是它。
    // P2 会改用"复用已有线程 + APC"来消除这个痕迹。
    HANDLE th = CreateThread(nullptr, 0, agent_thread, nullptr,
                             CREATE_SUSPENDED, nullptr);
    if (th) {
        SetThreadPriority(th, THREAD_PRIORITY_LOWEST);   // 尽量不抢游戏 CPU
        ResumeThread(th);
        CloseHandle(th);
    }
}

}  // namespace ik

// ============================================================================
// DllMain —— 只做最小的事
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

// ============================================================================
// 导出：给 manual map 的 stub 调用
// ============================================================================
extern "C" __declspec(dllexport) void __stdcall ik_bootstrap(void* moduleBase) {
    ik::bootstrap(static_cast<HMODULE>(moduleBase));
}

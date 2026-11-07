// payload/apc.hpp —— APC 队列执行（不创建新线程）
//
// 为什么用 APC
// ===========
// CreateThread 会让目标进程多一个线程。memkit 的实测数据：
//
//   注入前：线程 2
//   注入后：线程 3   ← 多出来的就是它
//
// 线程枚举是反作弊的基础手段之一。虽然 Warden 的四类检查里没有它，
// 但其他工具（杀软、EDR、玩家自己装的监控）会看到。
//
// APC 的原理
// =========
// QueueUserAPC 把一个函数塞进目标线程的 APC 队列。那个线程下次调用
// **alertable 等待函数**时（SleepEx / WaitForSingleObjectEx /
// MsgWaitForMultipleObjectsEx / SignalObjectAndWait），系统会先执行队列里的 APC。
//
// 所以：
//   ✅ 不创建新线程
//   ✅ 不需要挂起线程（挂起本身是强信号）
//   ❌ 要求目标线程处于 alertable wait —— 这是硬前提
//
// alertable 前提怎么满足
// =====================
// 三条路：
//
//   A. 目标本来就有 alertable 线程
//      WoW 的主循环用 MsgWaitForMultipleObjectsEx（消息泵），天然 alertable。
//      这是最理想的情况 —— 什么都不用做。
//
//   B. 找到处于 alertable wait 的线程，等它被唤醒
//      需要枚举线程 + 判断等待状态。判断方法有限（NtQueryInformationThread
//      能拿 ThreadBasicInformation，但拿不到"是否 alertable"）。
//
//   C. 劫持一个线程，临时让它进入 alertable wait
//      这就是线程劫持，属于另一种技术。
//
// 本文件实现 A + B 的可用部分：**检测**目标是否有 alertable 线程，
// 有就排队 APC，没有就返回失败（让调用方决定降级到 CreateThread）。
//
// 不自动降级的原因：降级意味着"有时候多一个线程，有时候不多"，
// 这种不确定性比明确失败更难处理。
#pragma once

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <cstdint>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace ik {
namespace apc {

// NtQueueApcThread —— 比 QueueUserAPC 更底层，但语义一样
using NtQueueApcFn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG);

inline NtQueueApcFn nt_queue_apc() noexcept {
    static auto fn = api::get<NtQueueApcFn>(api::mod::ntdll, hash::ascii("NtQueueApcThread"));
    return fn;
}

// NtAlertThread —— 强制把一个线程标记为 alertable
//
// 这是关键 API。正常情况下线程只在调用 alertable wait 函数时才检查
// APC 队列，但 NtAlertThread 能把它「踢醒」：
//   如果线程正在 alertable wait → 立刻返回并执行 APC
//   如果线程不在 alertable wait → 设置 Alerted 标志，下次进入时立刻执行
//
// 这意味着：**不需要等目标自然进入 alertable wait**。
// 任何线程都能被 alert。
//
// 代价：被 alert 的线程如果后来调 SleepEx，会立刻返回（不睡满）。
// 这会造成可观测的行为异常（如果目标在计时）。
using NtAlertThreadFn = LONG(NTAPI*)(HANDLE);

inline NtAlertThreadFn nt_alert_thread() noexcept {
    static auto fn = api::get<NtAlertThreadFn>(api::mod::ntdll, hash::ascii("NtAlertThread"));
    return fn;
}

using NtOpenThreadFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
using NtCloseFn = LONG(NTAPI*)(HANDLE);

inline NtOpenThreadFn nt_open_thread() noexcept {
    static auto fn = api::get<NtOpenThreadFn>(api::mod::ntdll, hash::ascii("NtOpenThread"));
    return fn;
}
inline NtCloseFn nt_close() noexcept {
    static auto fn = api::get<NtCloseFn>(api::mod::ntdll, hash::ascii("NtClose"));
    return fn;
}

// ---------- 线程句柄（作用域内自动关）----------
class ThreadHandle {
public:
    ThreadHandle() = default;
    ~ThreadHandle() { close(); }
    ThreadHandle(const ThreadHandle&) = delete;
    ThreadHandle& operator=(const ThreadHandle&) = delete;

    bool open(DWORD tid, ACCESS_MASK mask) {
        const auto openFn = nt_open_thread();
        if (!openFn || tid == 0) return false;

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueProcess = nullptr;
        cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tid));

        HANDLE h = nullptr;
        if (openFn(&h, mask, &oa, &cid) < 0 || !h) return false;
        h_ = h;
        tid_ = tid;
        return true;
    }

    void close() noexcept {
        if (!h_) return;
        const auto closeFn = nt_close();
        if (closeFn) closeFn(h_);
        h_ = nullptr;
        tid_ = 0;
    }

    HANDLE get() const noexcept { return h_; }
    DWORD tid() const noexcept { return tid_; }
    bool valid() const noexcept { return h_ != nullptr; }

private:
    HANDLE h_ = nullptr;
    DWORD tid_ = 0;
};

// ---------- 结果 ----------
enum class Status : uint8_t {
    Ok = 0,
    NoThreadFound,
    OpenFailed,
    QueueFailed,
    AlertFailed,
};

inline const char* status_name(Status s) noexcept {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::NoThreadFound: return "no_thread_found";
        case Status::OpenFailed: return "open_failed";
        case Status::QueueFailed: return "queue_failed";
        case Status::AlertFailed: return "alert_failed";
    }
    return "?";
}

// ---------- APC 回调签名 ----------
// NtQueueApcThread 的回调是：
//   VOID NTAPI APCProc(ULONG_PTR Parameter)
// 注意：不是标准 APC 的三参数形式。QueueUserAPC 的签名是
//   VOID CALLBACK(ULONG_PTR)  —— 只有一个参数。
using ApcRoutine = void(NTAPI*)(ULONG_PTR);

// ---------- 向指定线程排队 APC ----------
//
// 参数：
//   tid        目标线程
//   routine    APC 回调（在目标线程上下文执行）
//   param      传给回调的参数
//   forceAlert 是否调 NtAlertThread 强制唤醒
//
// 权限要求：THREAD_SET_CONTEXT (0x0010)
inline Status queue(DWORD tid, ApcRoutine routine, ULONG_PTR param, bool forceAlert) {
    ThreadHandle th;
    // THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME（alert 需要后者）
    constexpr ACCESS_MASK kMask = 0x0010 | 0x0002 | 0x0008;
    if (!th.open(tid, kMask)) return Status::OpenFailed;

    const auto q = nt_queue_apc();
    if (!q) return Status::QueueFailed;

    const LONG st = q(th.get(),
                      reinterpret_cast<PVOID>(routine),
                      reinterpret_cast<PVOID>(param),
                      nullptr,
                      0);
    if (st < 0) return Status::QueueFailed;

    if (forceAlert) {
        const auto alert = nt_alert_thread();
        if (!alert) return Status::AlertFailed;
        if (alert(th.get()) < 0) return Status::AlertFailed;
    }

    return Status::Ok;
}

// ---------- 从进程内枚举线程 ----------
//
// 在 payload 里运行时，可以直接用 Toolhelp（对自身进程）。
struct ThreadInfo {
    DWORD tid;
    bool isSelf;
};

inline int enum_threads(ThreadInfo* out, int maxOut) {
    if (!out || maxOut <= 0) return 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    const DWORD myPid = GetCurrentProcessId();
    const DWORD myTid = GetCurrentThreadId();

    int n = 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != myPid) continue;
            if (n >= maxOut) break;
            out[n].tid = te.th32ThreadID;
            out[n].isSelf = (te.th32ThreadID == myTid);
            ++n;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

// ---------- 挑一个"最可能 alertable"的线程 ----------
//
// 判断依据很有限（Windows 不暴露"是否 alertable"）。可用的启发：
//
//   1. 排除调用者自己（我们不能给自己排 APC 然后等自己 —— 死锁）
//   2. 排除当前正在跑的线程（CPU 时间高的）
//   3. 优先选等待时间长的（用 NtQueryInformationThread 拿不到，
//      所以退回：用 GetThreadTimes 看谁的用户态时间少 = 更可能在等）
//
// 这些都是启发式，不是判定。真正的保证只有 NtAlertThread。
inline DWORD pick_target_thread() {
    ThreadInfo threads[128];
    const int n = enum_threads(threads, 128);
    if (n <= 0) return 0;

    // 我们自己（agent 线程）不选
    const DWORD myTid = GetCurrentThreadId();

    DWORD best = 0;
    uint64_t bestUserTime = ~0ull;

    for (int i = 0; i < n; ++i) {
        if (threads[i].tid == myTid) continue;

        ThreadHandle th;
        if (!th.open(threads[i].tid, 0x0040 /*THREAD_QUERY_INFORMATION*/)) continue;

        FILETIME create{}, exit{}, kernel{}, user{};
        if (GetThreadTimes(th.get(), &create, &exit, &kernel, &user)) {
            const uint64_t ut = (static_cast<uint64_t>(user.dwHighDateTime) << 32) |
                                user.dwLowDateTime;
            // 用户态时间最少 = 最可能在等
            if (ut < bestUserTime) {
                bestUserTime = ut;
                best = threads[i].tid;
            }
        }
    }

    return best;
}

}  // namespace apc
}  // namespace ik

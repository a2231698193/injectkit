// app/wrap_stub.cpp —— 链接期拦截 MinGW 运行库对敏感 API 的间接引用
//
// 背景同 memkit：libwinpthread 的 sched.o / thread.o 内部引用了
// OpenProcess / DuplicateHandle / SuspendThread / ResumeThread /
// Get|SetThreadContext，即使业务代码一行没调，导入表里也会出现。
//
// 手段：--wrap=__imp_XXX 把引用重定向，运行时从 kernel32 导出表
// 解析真函数再转发。语义 100% 一致，但不产生静态导入。
//
// 注意：本文件内严禁 function-local static —— __cxa_guard_acquire
// 用的是被包装的 pthread 锁，会自死锁。
#include <windows.h>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace {

using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using DuplicateHandleFn = BOOL(WINAPI*)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
using SuspendThreadFn = DWORD(WINAPI*)(HANDLE);
using ResumeThreadFn = DWORD(WINAPI*)(HANDLE);
using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const CONTEXT*);

OpenProcessFn      g_openProcess      = nullptr;
DuplicateHandleFn  g_duplicateHandle  = nullptr;
SuspendThreadFn    g_suspendThread    = nullptr;
ResumeThreadFn     g_resumeThread     = nullptr;
GetThreadContextFn g_getThreadContext = nullptr;
SetThreadContextFn g_setThreadContext = nullptr;

HANDLE WINAPI impl_OpenProcess(DWORD a, BOOL b, DWORD c) {
    if (!g_openProcess)
        g_openProcess = api::get<OpenProcessFn>(api::mod::kernel32, hash::ascii("OpenProcess"));
    return g_openProcess ? g_openProcess(a, b, c) : nullptr;
}

BOOL WINAPI impl_DuplicateHandle(HANDLE a, HANDLE b, HANDLE c, LPHANDLE d, DWORD e, BOOL f, DWORD g) {
    if (!g_duplicateHandle)
        g_duplicateHandle =
            api::get<DuplicateHandleFn>(api::mod::kernel32, hash::ascii("DuplicateHandle"));
    return g_duplicateHandle ? g_duplicateHandle(a, b, c, d, e, f, g) : FALSE;
}

DWORD WINAPI impl_SuspendThread(HANDLE h) {
    if (!g_suspendThread)
        g_suspendThread =
            api::get<SuspendThreadFn>(api::mod::kernel32, hash::ascii("SuspendThread"));
    return g_suspendThread ? g_suspendThread(h) : static_cast<DWORD>(-1);
}

DWORD WINAPI impl_ResumeThread(HANDLE h) {
    if (!g_resumeThread)
        g_resumeThread = api::get<ResumeThreadFn>(api::mod::kernel32, hash::ascii("ResumeThread"));
    return g_resumeThread ? g_resumeThread(h) : static_cast<DWORD>(-1);
}

BOOL WINAPI impl_GetThreadContext(HANDLE h, LPCONTEXT c) {
    if (!g_getThreadContext)
        g_getThreadContext =
            api::get<GetThreadContextFn>(api::mod::kernel32, hash::ascii("GetThreadContext"));
    return g_getThreadContext ? g_getThreadContext(h, c) : FALSE;
}

BOOL WINAPI impl_SetThreadContext(HANDLE h, const CONTEXT* c) {
    if (!g_setThreadContext)
        g_setThreadContext =
            api::get<SetThreadContextFn>(api::mod::kernel32, hash::ascii("SetThreadContext"));
    return g_setThreadContext ? g_setThreadContext(h, c) : FALSE;
}

}  // namespace

extern "C" {

HANDLE(WINAPI* __wrap___imp_OpenProcess)(DWORD, BOOL, DWORD) = impl_OpenProcess;
BOOL(WINAPI* __wrap___imp_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) =
    impl_DuplicateHandle;
DWORD(WINAPI* __wrap___imp_SuspendThread)(HANDLE) = impl_SuspendThread;
DWORD(WINAPI* __wrap___imp_ResumeThread)(HANDLE) = impl_ResumeThread;
BOOL(WINAPI* __wrap___imp_GetThreadContext)(HANDLE, LPCONTEXT) = impl_GetThreadContext;
BOOL(WINAPI* __wrap___imp_SetThreadContext)(HANDLE, const CONTEXT*) = impl_SetThreadContext;

}  // extern "C"

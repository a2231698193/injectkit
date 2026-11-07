// loader/main.cpp —— 注入器（只做一次性工作）
//
// 职责：把 payload DLL 放进目标进程，然后**立刻退出**。
//
// 为什么 loader 要短命
// ===================
// loader 是外部进程，持有目标进程句柄。句柄是可枚举的（见 memkit 的
// handles.hpp —— 全系统句柄表能反查持有者 PID）。
//
// 所以 loader 的正确行为是：
//   打开 → 注入 → 关句柄 → 退出
//
// 注入完成后 payload 自己活着，loader 没必要留。
//
// 两条注入路径
// ===========
//   A. LoadLibrary 路径（简单，但目标 PEB 里会出现模块）
//   B. Manual map（不留 PEB 痕迹，但需要更多代码）
//
// 这个 P0 版本先做 A —— 目的是验证"注入 → payload 起来 → 心跳通"。
// B 在 P1 接进来（memkit 的 manualmap.hpp 已有 7 阶段实现）。
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <string>

// ============================================================================
// 进程查找
// ============================================================================
namespace {

struct ProcInfo {
    DWORD pid = 0;
    std::wstring name;
};

// 按 exe 名（不区分大小写）找进程；多开时返回第一个
DWORD find_process(const wchar_t* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ============================================================================
// 路径 A：LoadLibrary 注入
// ============================================================================
//
// 步骤：
//   1. 打开目标进程（最小权限）
//   2. 在目标里分配一块内存存 DLL 路径
//   3. 写路径
//   4. CreateRemoteThread(kernel32!LoadLibraryW, 路径)
//   5. 等线程结束，读返回值（DLL 基址）
//   6. 释放路径内存
//   7. 关句柄
//
// 明确代价：
//   * 目标进程多一个模块（EnumProcessModules 可见）
//   * 目标进程多一个线程（短暂存在）
//   * 如果 DLL 是磁盘上的文件，目标会打开它（文件句柄可见）
bool inject_loadlibrary(DWORD pid, const wchar_t* dllPath, HMODULE* outBase) {
    // 只申请注入必需的权限。
    // 注意：CREATE_THREAD 是注入必需的，无法省略。
    constexpr DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    HANDLE hProc = OpenProcess(kAccess, FALSE, pid);
    if (!hProc) {
        printf("  OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    // 路径长度（字节）
    const size_t pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    void* remotePath = VirtualAllocEx(hProc, nullptr, pathBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        printf("  VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(hProc, remotePath, dllPath, pathBytes, &wrote) ||
        wrote != pathBytes) {
        printf("  WriteProcessMemory 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // LoadLibraryW 在目标进程内的地址。
    // 注意：kernel32 的基址在同一个 Windows 上是固定的（ASLR 对系统 DLL
    // 使用固定的基址集合），所以本进程拿到的地址在目标里也有效。
    // 这不是"猜"，是 Windows 的已知行为；不走运时（极少数情况）会在
    // CreateRemoteThread 失败，那时退回 manual map。
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    const auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(k32, "LoadLibraryW"));
    if (!loadLib) {
        printf("  找不到 LoadLibraryW\n");
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, loadLib, remotePath, 0, nullptr);
    if (!th) {
        printf("  CreateRemoteThread 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(th, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(th, &exitCode);
    CloseHandle(th);

    // 清理
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode == 0) {
        printf("  LoadLibraryW 返回 0（DLL 加载失败）\n");
        return false;
    }

    if (outBase) *outBase = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(exitCode));
    return true;
}

}  // namespace

// ============================================================================
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(936);

    printf("=== injectkit loader (P0) ===\n\n");

    // 参数：--target <exe名> --dll <路径>
    const wchar_t* targetExe = nullptr;
    const wchar_t* dllPath = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            targetExe = argv[++i];
        } else if (wcscmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            printf("用法：\n");
            printf("  ikloader.exe --target <exe名> --dll <payload路径>\n\n");
            printf("示例：\n");
            printf("  ikloader.exe --target notepad.exe --dll ikpayload.dll\n");
            return 0;
        }
    }

    if (!targetExe || !dllPath) {
        printf("缺少参数。用 --help 看用法。\n");
        return 1;
    }

    // 检查 DLL 存在
    {
        DWORD attr = GetFileAttributesW(dllPath);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            printf("DLL 不存在: %ls\n", dllPath);
            return 1;
        }
    }

    // 转成绝对路径（目标进程的工作目录可能不同）
    wchar_t fullPath[MAX_PATH * 2] = {};
    if (!GetFullPathNameW(dllPath, MAX_PATH * 2, fullPath, nullptr)) {
        printf("路径解析失败\n");
        return 1;
    }

    printf("目标进程: %ls\n", targetExe);
    printf("payload : %ls\n\n", fullPath);

    const DWORD pid = find_process(targetExe);
    if (pid == 0) {
        printf("找不到进程: %ls\n", targetExe);
        return 1;
    }
    printf("找到 pid = %lu\n", pid);

    HMODULE base = nullptr;
    if (!inject_loadlibrary(pid, fullPath, &base)) {
        printf("\n注入失败\n");
        return 1;
    }

    printf("\n注入成功\n");
    printf("  payload 基址 = 0x%p\n", (void*)base);
    printf("  （这个地址在目标进程的地址空间里）\n\n");

    printf("预期：payload 起来后会尝试连 \\\\.\\pipe\\ik_%lu 写心跳\n", pid);
    printf("      用 ikclient 连那个管道就能看到\n");

    return 0;
}

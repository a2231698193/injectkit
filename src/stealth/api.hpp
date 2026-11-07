// stealth/api.hpp —— 通过 PEB 遍历 + 导出表解析动态取 API
// 目的：不产生静态导入项，进程导入表里看不到 Nt*/工具函数名
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <string_view>

#include "common/hash.hpp"

namespace api {

// ---- 与 ntdll 内部布局对齐的结构（winternl.h 的 LDR 结构字段不足，自行定义）----
struct LdrEntryFull {
    LIST_ENTRY InLoadOrderLinks;              // 0x00
    LIST_ENTRY InMemoryOrderLinks;            // 0x10  <-- 我们沿这条链走
    LIST_ENTRY InInitializationOrderLinks;    // 0x20
    void*      DllBase;                       // 0x30
    void*      EntryPoint;                    // 0x38
    ULONG      SizeOfImage;                   // 0x40
    UNICODE_STRING FullDllName;               // 0x48
    UNICODE_STRING BaseDllName;               // 0x58
};

inline uint32_t hash_unicode_lower(const UNICODE_STRING& n) noexcept {
    uint32_t h = hash::kOffset;
    const USHORT chars = static_cast<USHORT>(n.Length / sizeof(wchar_t));
    for (USHORT i = 0; i < chars; ++i) {
        wchar_t c = n.Buffer[i];
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        const uint16_t v = static_cast<uint16_t>(c);
        h ^= static_cast<uint8_t>(v & 0xFF); h *= hash::kPrime;
        h ^= static_cast<uint8_t>(v >> 8);   h *= hash::kPrime;
    }
    return h;
}

// 按小写模块名哈希取基址（记得传 "ntdll.dll" / "kernel32.dll" / "user32.dll"）
inline void* module(uint32_t nameHash) noexcept {
#ifndef _WIN64
    return nullptr;  // 本框架只支持 x64
#else
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return nullptr;
    const auto* head = reinterpret_cast<const LIST_ENTRY*>(
        &reinterpret_cast<const PEB_LDR_DATA*>(peb->Ldr)->InMemoryOrderModuleList);
    for (auto it = head->Flink; it != head; it = it->Flink) {
        const auto* e = CONTAINING_RECORD(it, LdrEntryFull, InMemoryOrderLinks);
        if (!e->BaseDllName.Buffer || e->BaseDllName.Length == 0) continue;
        if (hash_unicode_lower(e->BaseDllName) == nameHash) return e->DllBase;
    }
    return nullptr;
#endif
}

// 按函数名 FNV-1a 哈希在导出表里查地址（支持转发导出的直接地址）
inline void* proc(void* base, uint32_t procHash) noexcept {
    if (!base) return nullptr;
    const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        static_cast<const BYTE*>(base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;

    const auto img = static_cast<const BYTE*>(base);
    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(img + dir.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(img + exp->AddressOfNames);
    const auto* funcs = reinterpret_cast<const DWORD*>(img + exp->AddressOfFunctions);
    const auto* ords  = reinterpret_cast<const WORD*>(img + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* nm = reinterpret_cast<const char*>(img + names[i]);
        uint32_t h = hash::kOffset;
        for (const char* p = nm; *p; ++p) {
            h ^= static_cast<uint8_t>(*p);
            h *= hash::kPrime;
        }
        if (h == procHash) return const_cast<BYTE*>(img + funcs[ords[i]]);
    }
    return nullptr;
}

template <class Fn>
inline Fn get(uint32_t modHash, uint32_t procHash) noexcept {
    return reinterpret_cast<Fn>(proc(module(modHash), procHash));
}

// ---- 常用模块哈希（编译期常量，无明文）----
namespace mod {
inline constexpr uint32_t ntdll    = hash::wide(L"ntdll.dll");
inline constexpr uint32_t kernel32 = hash::wide(L"kernel32.dll");
inline constexpr uint32_t user32   = hash::wide(L"user32.dll");
inline constexpr uint32_t kernelbase = hash::wide(L"kernelbase.dll");
}  // namespace mod

// ---- 廉价缓存：首次解析后常驻函数指针（不是字符串，不构成特征）----
template <uint32_t ModHash, uint32_t ProcHash, class Fn>
struct Static {
    static Fn ptr() noexcept {
        static Fn fn = get<Fn>(ModHash, ProcHash);
        return fn;
    }
};

}  // namespace api

// 便捷宏：RESOLVE(api::mod::ntdll, "NtReadVirtualMemory", FnType)
#define RESOLVE(modHash, procName, FnType) \
    ((FnType)::api::proc(::api::module(modHash), ::hash::ascii(procName)))

// 缓存版
#define RESOLVE_S(modHash, procName, FnType) \
    (::api::Static<modHash, ::hash::ascii(procName), FnType>::ptr())

// common/hash.hpp —— 编译期字符串哈希，供 API / 模块名动态解析使用
// 目的：二进制中不出现 "NtReadVirtualMemory"、"Game.exe" 之类明文串
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace hash {

inline constexpr uint32_t kOffset = 2166136261u;  // FNV-1a offset basis
inline constexpr uint32_t kPrime  = 16777619u;

// ANSI：用于导出函数名
constexpr uint32_t fnv1a(const char* s, std::size_t n) noexcept {
    uint32_t h = kOffset;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= kPrime;
    }
    return h;
}

constexpr uint32_t ascii(std::string_view s) noexcept { return fnv1a(s.data(), s.size()); }

template <std::size_t N>
constexpr uint32_t ascii(const char (&s)[N]) noexcept {
    return fnv1a(s, N - 1);
}

// 宽字符小写：用于 PEB->Ldr 的 BaseDllName 比较（大小写不敏感，UTF-16 逐字节参与）
constexpr uint32_t wide(std::wstring_view s) noexcept {
    uint32_t h = kOffset;
    for (wchar_t c : s) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        const uint16_t v = static_cast<uint16_t>(c);
        h ^= static_cast<uint8_t>(v & 0xFF); h *= kPrime;
        h ^= static_cast<uint8_t>(v >> 8);   h *= kPrime;
    }
    return h;
}

template <std::size_t N>
constexpr uint32_t wide(const wchar_t (&s)[N]) noexcept {
    return wide(std::wstring_view(s, N - 1));
}

}  // namespace hash

// common/obf.hpp —— 编译期常量异或，防止明文串落进 .rdata
// 用法：std::string exe = OBF("Game.exe", 0x9E37u);
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace obf {

constexpr uint8_t stream(uint32_t seed, std::size_t i) noexcept {
    uint32_t x = seed * 1103515245u + 12345u + static_cast<uint32_t>(i * 2654435761u);
    x ^= x >> 15; x *= 2246822519u;
    x ^= x >> 13; x *= 3266489917u;
    x ^= x >> 16;
    return static_cast<uint8_t>(x);
}

template <uint32_t Seed, std::size_t N>
constexpr std::array<char, N> enc(const char (&s)[N]) noexcept {
    std::array<char, N> a{};
    for (std::size_t i = 0; i < N; ++i)
        a[i] = static_cast<char>(static_cast<uint8_t>(s[i]) ^ stream(Seed, i));
    return a;
}

inline std::string dec(const char* p, std::size_t n, uint32_t seed) {
    std::string out(n > 0 ? n - 1 : 0, '\0');
    for (std::size_t i = 0; i + 1 < n; ++i)
        out[i] = static_cast<char>(static_cast<uint8_t>(p[i]) ^ stream(seed, i));
    return out;
}

inline std::wstring widen(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    return w;
}

}  // namespace obf

#define OBF(s, seed)                                                            \
    ([] {                                                                       \
        constexpr auto e_ = ::obf::enc<static_cast<uint32_t>(seed)>(s);         \
        return ::obf::dec(e_.data(), sizeof(s), static_cast<uint32_t>(seed));   \
    }())

#define OBFW(s, seed) ::obf::widen(OBF(s, seed))

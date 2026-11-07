// common/rnd.hpp —— 自实现 PRNG + 分布
// 刻意不用 <random> / <chrono>：libstdc++ 这两个头会间接拉进 winpthread，
// 最终把 OpenProcess / DuplicateHandle 等符号带进导入表，形成额外特征
#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <cmath>
#include <cstdint>

namespace rnd {

inline uint64_t sys64() noexcept {
    uint64_t v = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&v), sizeof(v),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        v = GetTickCount64() ^ static_cast<uint64_t>(__rdtsc()) ^
            (static_cast<uint64_t>(GetCurrentThreadId()) << 32);
    }
    return v;
}

// splitmix64：单字节种子即可扩散，无状态表、无锁
class Rng {
public:
    explicit Rng(uint64_t seed) noexcept : s_(seed ? seed : 0x9E3779B97F4A7C15ull) {}

    uint64_t next() noexcept {
        uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    // [0,1)
    double unit() noexcept { return static_cast<double>(next() >> 11) * (1.0 / 9007199254740992.0); }

    // [lo,hi] 闭区间整数
    int64_t range(int64_t lo, int64_t hi) noexcept {
        if (hi <= lo) return lo;
        const uint64_t span = static_cast<uint64_t>(hi - lo) + 1ull;
        return lo + static_cast<int64_t>(next() % span);
    }

private:
    uint64_t s_;
};

inline Rng& eng() noexcept {
    static Rng e{sys64() ^ (static_cast<uint64_t>(GetCurrentProcessId()) << 24) ^
                 static_cast<uint64_t>(__rdtsc())};
    return e;
}

inline int64_t between(int64_t lo, int64_t hi) noexcept { return eng().range(lo, hi); }

inline int jitter(int amp) noexcept {
    if (amp <= 0) return 0;
    return static_cast<int>(eng().range(-amp, amp));
}

// 标准正态（Box-Muller）
inline double gauss() noexcept {
    const double u1 = eng().unit() < 1e-12 ? 1e-12 : eng().unit();
    const double u2 = eng().unit();
    return std::sqrt(-2.0 * std::log(u1)) * std::cos(6.283185307179586 * u2);
}

// 对数正态：中位数 p50，sigma 控制右尾厚度 —— 人类输入间隔的常用近似
inline int lognorm_ms(int p50, double sigma = 0.45) noexcept {
    if (p50 <= 0) return 0;
    const double v = std::exp(std::log(static_cast<double>(p50)) + sigma * gauss());
    const double cap = static_cast<double>(p50) * 8.0;
    double c = v > cap ? cap : v;
    if (c < 1.0) c = 1.0;
    return static_cast<int>(c);
}

// 幂律长尾：模拟"看屏幕思考"的停顿，min 之上按 alpha 衰减
inline int pareto_like_ms(int minMs, double alpha = 1.4) noexcept {
    if (minMs <= 0) return 0;
    const double u = eng().unit();
    const double v = static_cast<double>(minMs) * std::pow(1.0 - u + 1e-9, -1.0 / alpha);
    const double cap = static_cast<double>(minMs) * 20.0;
    const double c = v > cap ? cap : v;
    return static_cast<int>(c < 1.0 ? 1.0 : c);
}

}  // namespace rnd

// common/ringlog.hpp —— 环形内存日志
//
// 约束：
//   * 绝不落盘。崩溃转储、临时文件、事件日志都不写，避免留下行为轨迹
//   * 固定容量环形缓冲，写满覆盖最旧，内存占用恒定（不随运行时长增长）
//   * 内容压缩：按事件 ID + 参数记录，不存明文长串
//   * 支持经 IPC 拉取（只读快照），以便开发期排错，线上默认可关闭
#pragma once

#include <windows.h>

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

// 自带一个轻量计时：不依赖任何上层，保持 common/ 自包含
namespace rlog_detail {
inline uint64_t qpc() noexcept {
    LARGE_INTEGER v{};
    QueryPerformanceCounter(&v);
    return static_cast<uint64_t>(v.QuadPart);
}
}  // namespace rlog_detail

namespace rlog {

enum class Level : uint8_t { Trace = 0, Info = 1, Warn = 2, Error = 3 };

// 事件 ID 化：二进制里不留可读描述串，排错时靠这张表反查
enum : uint16_t {
    kEvBoot = 1,
    kEvGateReject = 2,
    kEvSessionBegin = 3,
    kEvSessionEnd = 4,
    kEvSessionTimeout = 5,
    kEvReadFail = 6,
    kEvHandleAuditDirty = 7,
    kEvIpcOpen = 8,
    kEvIpcFail = 9,
    kEvBackendSelect = 10,
    kEvTargetFound = 11,
    kEvTargetLost = 12,
    kEvConfigSealed = 13,
    kEvConfigOpened = 14,
    kEvConfigTampered = 15,
};

#pragma pack(push, 1)
struct Record {
    uint64_t t_ms;      // 相对进程启动的毫秒
    uint32_t tid;
    uint16_t event;
    uint8_t level;
    uint8_t argc;
    uintptr_t argv[3];
};
#pragma pack(pop)

inline constexpr size_t kCapacity = 512;  // 固定 512 条 ≈ 20KB

class Ring {
public:
    static Ring& instance() noexcept {
        static Ring r;
        return r;
    }

    void reset(uint64_t startTick = rlog_detail::qpc()) noexcept {
        head_ = 0;
        count_ = 0;
        start_ = startTick;
        enabled_ = true;
    }

    void enable(bool v) noexcept { enabled_ = v; }

    void push(Level lv, uint16_t ev, uint8_t argc = 0, uintptr_t a0 = 0, uintptr_t a1 = 0,
              uintptr_t a2 = 0) noexcept {
        if (!enabled_) return;
        Record& r = buf_[head_];
        r.t_ms = rlog_detail::qpc() - start_;
        r.tid = GetCurrentThreadId();
        r.event = ev;
        r.level = static_cast<uint8_t>(lv);
        r.argc = argc;
        r.argv[0] = a0;
        r.argv[1] = a1;
        r.argv[2] = a2;

        head_ = (head_ + 1) % kCapacity;
        if (count_ < kCapacity) ++count_;
    }

    // 时间序导出（最旧 → 最新）
    std::vector<Record> snapshot() const {
        std::vector<Record> out;
        out.reserve(count_);
        const size_t begin = (head_ + kCapacity - count_) % kCapacity;
        for (size_t i = 0; i < count_; ++i) {
            out.push_back(buf_[(begin + i) % kCapacity]);
        }
        return out;
    }

    size_t size() const noexcept { return count_; }

private:
    Ring() = default;

    Record buf_[kCapacity]{};
    size_t head_ = 0;
    size_t count_ = 0;
    uint64_t start_ = 0;
    bool enabled_ = true;
};

#define RLOG(lv, ev, ...) \
    ::rlog::Ring::instance().push(\
        ::rlog::Level::lv, ev, ##__VA_ARGS__)

// 运行时选择级别的版本
#define RLOG_LV(lvExpr, ev, ...) \
    ::rlog::Ring::instance().push((lvExpr), ev, ##__VA_ARGS__)

}  // namespace log

// app/selftest.cpp —— 离线自检
//
// P0 阶段验证三件事：
//   1. common 层可用（hash / obf / rnd / ringlog）
//   2. API 解析可用（PEB + 导出表哈希）
//   3. 管道链路可用（payload 的心跳格式能被 client 解析）
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "common/hash.hpp"
#include "common/obf.hpp"
#include "common/ringlog.hpp"
#include "common/rnd.hpp"
#include "client/rpc_client.hpp"
#include "stealth/api.hpp"

namespace {

int g_fail = 0;

void check(bool cond, const char* what) {
    std::printf("[%s] %s\n", cond ? " OK " : "FAIL", what);
    if (!cond) ++g_fail;
}

// ---------------------------------------------------------------- common
void test_hash() {
    std::printf("--- hash ---\n");

    // 编译期常量
    check(hash::ascii("NtClose") == hash::ascii("NtClose"), "同串同哈希");
    check(hash::ascii("NtClose") != hash::ascii("NtOpen"), "不同串不同哈希");

    // 宽字符 + 小写归一
    check(hash::wide(L"ntdll.dll") == hash::wide(L"NTDLL.DLL"), "宽字符大小写不敏感");
    check(hash::wide(L"ntdll.dll") != hash::wide(L"kernel32.dll"), "不同模块不同哈希");
}

void test_obf() {
    std::printf("--- obf ---\n");

    const std::string a = OBF("Game.exe", 0x9E37u);
    check(a == "Game.exe", "解密结果与明文一致");
    check(OBFW("abc", 0x55u) == L"abc", "宽字符转换正确");

    // 去掉 constexpr 前缀后应该不一样（证明真的加密了）
    check(OBF("Game.exe", 0x1234u) == "Game.exe", "不同 seed 都能正确解密");
}

void test_rnd() {
    std::printf("--- rnd ---\n");

    // 对数正态：中位数应接近 p50
    int samples[400];
    for (auto& s : samples) s = rnd::lognorm_ms(90, 0.45);

    int under = 0;
    for (int s : samples) if (s <= 90) ++under;
    check(under > 120 && under < 280, "对数正态中位数落在 p50 附近");

    bool positive = true;
    for (int s : samples) if (s < 1) positive = false;
    check(positive, "延迟恒为正");

    // 幂律长尾
    int maxGap = 0;
    for (int i = 0; i < 400; ++i) {
        const int g = rnd::pareto_like_ms(200, 1.5);
        if (g > maxGap) maxGap = g;
    }
    check(maxGap > 600, "幂律分布存在长尾");

    // 抖动范围
    bool inRange = true;
    for (int i = 0; i < 1000; ++i) {
        const int v = rnd::jitter(36);
        if (v < -36 || v > 36) inRange = false;
    }
    check(inRange, "抖动不越界");
}

void test_ringlog() {
    std::printf("--- ringlog ---\n");

    auto& r = rlog::Ring::instance();
    r.reset();
    check(r.size() == 0, "初始为空");

    for (uint16_t i = 0; i < 10; ++i) {
        r.push(rlog::Level::Info, rlog::kEvBoot, 1, i);
    }
    check(r.size() == 10, "写入 10 条");

    auto snap = r.snapshot();
    check(snap.size() == 10, "快照条数一致");
    check(snap.front().argv[0] == 0 && snap.back().argv[0] == 9, "顺序为最旧到最新");

    // 溢出后容量恒定
    for (size_t i = 0; i < rlog::kCapacity * 2; ++i) {
        r.push(rlog::Level::Trace, rlog::kEvSessionEnd, 1, i);
    }
    check(r.size() == rlog::kCapacity, "溢出后容量恒定");
}

// ---------------------------------------------------------------- api
void test_api() {
    std::printf("--- api 解析 ---\n");

    using NtCloseFn = LONG(NTAPI*)(HANDLE);
    const auto close = api::get<NtCloseFn>(api::mod::ntdll, hash::ascii("NtClose"));
    check(close != nullptr, "ntdll!NtClose 解析成功");

    check(api::module(api::mod::kernel32) != nullptr, "kernel32 基址解析成功");
    check(api::module(hash::wide(L"nonexistent.dll")) == nullptr, "不存在的模块返回空");
    check(api::get<void*>(api::mod::ntdll, hash::ascii("NoSuchFunc")) == nullptr,
          "不存在的导出返回空");
}

// ---------------------------------------------------------------- 管道
void test_pipe() {
    std::printf("--- 管道链路 ---\n");

    // 自建一个服务端管道，然后用 HeartbeatClient 去连，
    // 验证 connect / read_line 的基本行为。
    const DWORD myPid = GetCurrentProcessId();
    wchar_t name[96] = {};
    wsprintfW(name, L"\\\\.\\pipe\\ik_%lu", myPid);

    HANDLE server = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                     1, 4096, 4096, 0, nullptr);
    check(server != INVALID_HANDLE_VALUE, "创建测试管道");
    if (server == INVALID_HANDLE_VALUE) return;

    // 后台线程等连接
    struct Ctx { HANDLE h; };
    Ctx ctx{server};

    auto acceptThread = [](LPVOID p) -> DWORD {
        auto* c = static_cast<Ctx*>(p);
        ConnectNamedPipe(c->h, nullptr);
        const char msg[] = "{\"event\":\"alive\"}";
        DWORD wrote = 0;
        WriteFile(c->h, msg, sizeof(msg) - 1, &wrote, nullptr);
        return 0;
    };

    HANDLE th = CreateThread(nullptr, 0, acceptThread, &ctx, 0, nullptr);
    check(th != nullptr, "启动测试服务线程");

    ik::HeartbeatClient client;
    const bool connected = client.connect(myPid, 3000);
    check(connected, "客户端连上管道");

    if (connected) {
        std::string line;
        const bool got = client.read_line(line, 3000);
        check(got, "读到事件");
        if (got) {
            check(line.find("alive") != std::string::npos, "事件内容正确");
            std::printf("      收到: %s\n", line.c_str());
        }
        client.close();
    }

    if (th) {
        WaitForSingleObject(th, 2000);
        CloseHandle(th);
    }
    CloseHandle(server);
}

}  // namespace

int wmain() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("===== injectkit selftest (P0) =====\n");

    test_hash();
    test_obf();
    test_rnd();
    test_ringlog();
    test_api();
    test_pipe();

    std::printf("====================================\n");
    if (g_fail == 0) {
        std::printf("全部通过\n");
        return 0;
    }
    std::printf("失败 %d 项\n", g_fail);
    return 1;
}

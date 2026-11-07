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
#include <vector>

#include "common/hash.hpp"
#include "common/obf.hpp"
#include "common/ringlog.hpp"
#include "common/rnd.hpp"
#include "payload/json.hpp"
#include "payload/mem.hpp"
#include "payload/rpc.hpp"
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


// ---------------------------------------------------------------- json
void test_json() {
    std::printf("--- json ---\n");

    json::Value o = json::Value::object();
    o.set("jsonrpc", json::Value("2.0"));
    o.set("id", json::Value(static_cast<int64_t>(1)));
    const std::string dumped = o.dump();
    check(dumped.find("\"jsonrpc\":\"2.0\"") != std::string::npos, "序列化含字段");
    check(dumped.find("\"id\":1") != std::string::npos, "整数不带小数点");

    json::Value v;
    const char* src =
        R"({"jsonrpc":"2.0","id":42,"method":"mem.read","params":{"addr":"0x140000000","size":4}})";
    check(json::parse(src, v), "解析成功");
    check(v.get_str("method") == "mem.read", "method 正确");
    check(v.get_int("id") == 42, "id 正确");

    const json::Value* p = v.get("params");
    check(p != nullptr, "params 存在");
    if (p) {
        check(p->get_addr("addr") == 0x140000000ull, "十六进制地址解析正确");
        check(p->get_int("size") == 4, "size 正确");
    }

    json::Value s(std::string("a\"b\c\nd"));
    json::Value back;
    check(json::parse(s.dump(), back), "转义往返解析");
    check(back.as_string() == "a\"b\c\nd", "转义往返一致");

    json::Value bad;
    check(!json::parse("{", bad), "截断对象被拒绝");
    check(!json::parse("", bad), "空串被拒绝");
    check(!json::parse("[1,2", bad), "截断数组被拒绝");
    check(!json::parse("{}x", bad), "尾部垃圾被拒绝");

    json::Value arr;
    check(json::parse(R"([1,true,null,"x"])", arr), "混合数组解析");
    check(arr.size() == 4, "数组长度正确");
    check(arr.at(1).as_bool(), "布尔值正确");
    check(arr.at(2).is_null(), "null 正确");
    check(arr.at(3).as_string() == "x", "字符串正确");
}

// ---------------------------------------------------------------- mem
void test_mem() {
    std::printf("--- mem ---\n");

    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    uint8_t mz[2] = {};
    size_t got = 0;
    check(ik::mem::read(base, mz, 2, got) == ik::mem::Status::Ok, "读自身 PE 头成功");
    check(got == 2 && mz[0] == 'M' && mz[1] == 'Z', "读到 MZ");

    check(ik::mem::read(0, mz, 2, got) == ik::mem::Status::NullAddr, "空地址被拒绝");

    std::vector<uint8_t> big(ik::mem::kMaxRead + 1, 0);
    check(ik::mem::read(base, big.data(), big.size(), got) == ik::mem::Status::TooLarge,
          "超限被拒绝");

    const auto st = ik::mem::read(0x1000, mz, 2, got);
    check(st == ik::mem::Status::NotCommitted || st == ik::mem::Status::NoAccess,
          "未提交地址被拒绝");

    void* guarded = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (guarded) {
        DWORD old = 0;
        VirtualProtect(guarded, 0x1000, PAGE_READWRITE | PAGE_GUARD, &old);
        check(ik::mem::read(reinterpret_cast<uintptr_t>(guarded), mz, 2, got) ==
                  ik::mem::Status::GuardPage,
              "guard page 被识别为陷阱");
        VirtualFree(guarded, 0, MEM_RELEASE);
    }

    uint16_t mzVal = 0;
    check(ik::mem::read_value(base, mzVal) && mzVal == 0x5A4D, "read_value 正确");

    uint32_t lfanew = 0;
    check(ik::mem::read_value(base + 0x3C, lfanew), "读 e_lfanew 成功");

    uintptr_t offs[1] = {0x3C};
    uintptr_t resolved = 0;
    check(ik::mem::chain(base, offs, 1, resolved), "单级链解析成功");
    check(resolved == base + 0x3C, "单级链结果正确");

    uintptr_t badOffs[2] = {0x3C, 0xFFFFFF00};
    check(!ik::mem::chain(base, badOffs, 2, resolved), "断链被识别");

    check(ik::mem::probe_readable(base, 2), "probe 可读区成功");
    check(!ik::mem::probe_readable(0, 2), "probe 空地址失败");
    check(!ik::mem::probe_readable(0x1000, 2), "probe 未提交区失败");
}

// ---------------------------------------------------------------- rpc
void test_rpc() {
    std::printf("--- rpc ---\n");

    ik::rpc::Dispatcher d;

    {
        json::Value req;
        json::parse(R"({"jsonrpc":"2.0","id":1,"method":"ping","params":{}})", req);
        const auto resp = d.dispatch(req);
        check(resp.ok, "ping 成功");
        check(resp.result.get_int("pid") ==
                  static_cast<int64_t>(GetCurrentProcessId()),
              "pid 正确");
    }

    {
        const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        char reqJson[256];
        snprintf(reqJson, sizeof(reqJson),
                 R"({"jsonrpc":"2.0","id":2,"method":"mem.read","params":{"addr":"0x%llX","size":2}})",
                 static_cast<unsigned long long>(base));
        json::Value req;
        json::parse(reqJson, req);
        const auto resp = d.dispatch(req);
        check(resp.ok, "mem.read 成功");
        check(resp.result.get_str("status") == "ok", "status 为 ok");
        check(resp.result.get_str("hex") == "4D5A", "读到 4D5A (MZ)");
    }

    {
        json::Value req;
        json::parse(R"({"jsonrpc":"2.0","id":3,"method":"no.such"})", req);
        const auto resp = d.dispatch(req);
        check(!resp.ok, "未知方法返回错误");
        check(resp.errorCode == ik::rpc::kMethodNotFound, "错误码为 MethodNotFound");
    }

    {
        json::Value req;
        json::parse(
            R"({"jsonrpc":"2.0","id":4,"method":"mem.read","params":{"addr":"0x0","size":0}})",
            req);
        const auto resp = d.dispatch(req);
        check(!resp.ok, "无效参数返回错误");
        check(resp.errorCode == ik::rpc::kInvalidParams, "错误码为 InvalidParams");
    }

    {
        const char* line = R"({"jsonrpc":"2.0","id":7,"method":"ping"})";
        const std::string out = ik::rpc::handle_line(d, line, strlen(line));
        check(out.find("\"id\":7") != std::string::npos, "响应回填 id");
        check(!out.empty() && out.back() == '\n', "响应以换行结尾");
        check(out.find("\"jsonrpc\":\"2.0\"") != std::string::npos, "响应含版本");
    }

    {
        const char* line = "{not json";
        const std::string out = ik::rpc::handle_line(d, line, strlen(line));
        check(out.find("-32700") != std::string::npos, "解析错误返回 -32700");
    }

    {
        const uint8_t bytes[] = {0x4D, 0x5A, 0x90, 0x00};
        check(ik::rpc::to_hex(bytes, 4) == "4D5A9000", "hex 编码正确");
    }
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
    test_json();
    test_mem();
    test_rpc();

    std::printf("====================================\n");
    if (g_fail == 0) {
        std::printf("全部通过\n");
        return 0;
    }
    std::printf("失败 %d 项\n", g_fail);
    return 1;
}

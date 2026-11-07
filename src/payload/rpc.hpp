// payload/rpc.hpp —— JSON-RPC 2.0 服务端
//
// 协议选择：JSON-RPC 2.0，因为它是标准（不用自己发明），
// 且任何语言都有现成客户端。
//
// 报文格式（换行分隔，一行一条）
// ============================
//   ← {"jsonrpc":"2.0","id":1,"method":"mem.read","params":{...}}
//   → {"jsonrpc":"2.0","id":1,"result":{...}}
//   → {"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"..."}}
//
// 为什么用换行分隔而不是长度前缀
// -----------------------------
// 长度前缀更严谨，但换行分隔：
//   * 人肉调试直接 telnet 就能试
//   * Python/JS 客户端实现简单
//   * 我们的 payload 不处理二进制数据（读到的字节用 hex 编码）
//
// 代价：字符串里如果有换行必须转义。JSON 序列化已经处理了。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "payload/call.hpp"
#include "payload/json.hpp"
#include "payload/mem.hpp"

namespace ik {
namespace rpc {

// JSON-RPC 2.0 标准错误码
enum : int {
    kParseError = -32700,
    kInvalidRequest = -32600,
    kMethodNotFound = -32601,
    kInvalidParams = -32602,
    kInternalError = -32603,
};

// ---------- 请求处理结果 ----------
struct Response {
    json::Value result;
    bool ok = true;
    int errorCode = 0;
    std::string errorMessage;

    static Response make_error(int code, const char* msg) {
        Response r;
        r.ok = false;
        r.errorCode = code;
        r.errorMessage = msg;
        return r;
    }
};

// ---------- hex 编码（读到的字节用这个传）----------
inline std::string to_hex(const uint8_t* p, size_t n) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out += kHex[p[i] >> 4];
        out += kHex[p[i] & 0xF];
    }
    return out;
}

// ---------- 方法分发表 ----------
//
// P1 阶段只有三个方法，都是"验证链路"用的：
//   ping        —— 连通性测试
//   mem.read    —— 读内存（核心能力）
//   mem.chain   —— 多级指针链（验证偏移表能直接迁移）
//
// 后续会加：
//   mem.scan    —— AOB 扫描
//   game.call   —— 调用游戏函数（P4，注入的真正价值）
class Dispatcher {
public:
    Response dispatch(const json::Value& req) {
        if (!req.is_object()) {
            return Response::make_error(kInvalidRequest, "request must be an object");
        }

        const std::string method = req.get_str("method");
        if (method.empty()) {
            return Response::make_error(kInvalidRequest, "missing method");
        }

        // 分发
        if (method == "ping") return handle_ping(req);
        if (method == "mem.read") return handle_mem_read(req);
        if (method == "mem.chain") return handle_mem_chain(req);
        if (method == "mem.info") return handle_mem_info(req);
        if (method == "game.call") return handle_game_call(req);

        return Response::make_error(kMethodNotFound, "unknown method");
    }

private:
    static const json::Value* params(const json::Value& req) { return req.get("params"); }

    Response handle_ping(const json::Value&) {
        Response r;
        r.result = json::Value::object();
        r.result.set("pong", json::Value(1));
        r.result.set("pid", json::Value(static_cast<int64_t>(GetCurrentProcessId())));
        r.result.set("uptime_ms", json::Value(static_cast<int64_t>(GetTickCount64())));
        return r;
    }

    Response handle_mem_read(const json::Value& req) {
        const json::Value* p = params(req);
        if (!p) return Response::make_error(kInvalidParams, "missing params");

        const uint64_t addr = p->get_addr("addr");
        int64_t size = p->get_int("size", 0);

        if (addr == 0) return Response::make_error(kInvalidParams, "addr is 0");
        if (size <= 0) return Response::make_error(kInvalidParams, "size <= 0");
        if (size > static_cast<int64_t>(mem::kMaxRead)) {
            return Response::make_error(kInvalidParams, "size too large");
        }

        uint8_t buf[mem::kMaxRead] = {};
        size_t got = 0;
        const mem::Status st = mem::read(static_cast<uintptr_t>(addr), buf,
                                         static_cast<size_t>(size), got);

        Response r;
        r.result = json::Value::object();
        r.result.set("status", json::Value(mem::status_name(st)));
        r.result.set("got", json::Value(static_cast<int64_t>(got)));
        if (got > 0) {
            r.result.set("hex", json::Value(to_hex(buf, got)));
        }
        return r;
    }

    Response handle_mem_chain(const json::Value& req) {
        const json::Value* p = params(req);
        if (!p) return Response::make_error(kInvalidParams, "missing params");

        const uint64_t base = p->get_addr("base");
        const json::Value* offsArr = p->get("offs");
        if (base == 0) return Response::make_error(kInvalidParams, "base is 0");
        if (!offsArr || !offsArr->is_array() || offsArr->size() == 0) {
            return Response::make_error(kInvalidParams, "offs must be a non-empty array");
        }
        if (offsArr->size() > 8) {
            return Response::make_error(kInvalidParams, "chain too deep (max 8)");
        }

        uintptr_t offs[8] = {};
        for (size_t i = 0; i < offsArr->size(); ++i) {
            offs[i] = static_cast<uintptr_t>(offsArr->at(i).as_addr());
        }

        uintptr_t resolved = 0;
        const bool ok = mem::chain(static_cast<uintptr_t>(base), offs, offsArr->size(),
                                   resolved);

        Response r;
        r.result = json::Value::object();
        r.result.set("ok", json::Value(ok));
        if (ok) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llX",
                     static_cast<unsigned long long>(resolved));
            r.result.set("addr", json::Value(buf));
        }
        return r;
    }

    // 调用任意函数
    //
    // 参数格式：
    //   {"method":"game.call","params":{
    //       "addr":"0x140123456",
    //       "args":[{"t":"i","v":"0x10"},{"t":"f","v":1.5}],
    //       "ret":"i"}}
    //
    // t: i=整型/指针, f=float, d=double
    // ret: i=整型(默认), f=float, d=double
    //
    // 安全边界：只执行、不修改任何字节。
    // Warden 的 Mem 检查逐字节比对，所以"调用"安全，"hook"危险。
    Response handle_game_call(const json::Value& req) {
        const json::Value* p = params(req);
        if (!p) return Response::make_error(kInvalidParams, "missing params");

        const uint64_t addr = p->get_addr("addr");
        if (addr == 0) return Response::make_error(kInvalidParams, "addr is 0");

        call::ArgType retType = call::ArgType::Int;
        const std::string retStr = p->get_str("ret", "i");
        if (retStr == "f") retType = call::ArgType::Float;
        else if (retStr == "d") retType = call::ArgType::Double;

        call::Arg argv[call::kMaxArgs];
        size_t argc = 0;
        const json::Value* argsArr = p->get("args");
        if (argsArr && argsArr->is_array()) {
            const size_t n = argsArr->size();
            if (n > call::kMaxArgs) {
                return Response::make_error(kInvalidParams, "too many args (max 8)");
            }
            for (size_t i = 0; i < n; ++i) {
                const json::Value& a = argsArr->at(i);

                if (a.is_object()) {
                    const std::string t = a.get_str("t", "i");
                    const json::Value* v = a.get("v");
                    const double dv = v ? v->as_number() : 0.0;
                    const uint64_t iv = v ? v->as_addr() : 0;

                    if (t == "f") argv[argc++] = call::Arg::f(static_cast<float>(dv));
                    else if (t == "d") argv[argc++] = call::Arg::d(dv);
                    else argv[argc++] = call::Arg::i(iv);
                } else {
                    argv[argc++] = call::Arg::i(a.as_addr());
                }
            }
        }

        const call::Result r = call::invoke(addr, argv, argc, retType);

        Response resp;
        resp.result = json::Value::object();
        resp.result.set("ok", json::Value(true));

        if (retType == call::ArgType::Float) {
            resp.result.set("ret_f", json::Value(static_cast<double>(r.as_float())));
        } else if (retType == call::ArgType::Double) {
            resp.result.set("ret_d", json::Value(r.as_double()));
        }

        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(r.rax));
        resp.result.set("ret_u", json::Value(buf));
        resp.result.set("ret_i", json::Value(static_cast<int64_t>(r.rax)));

        return resp;
    }

    Response handle_mem_info(const json::Value& req) {
        const json::Value* p = params(req);
        const uint64_t addr = p ? p->get_addr("addr") : 0;
        if (addr == 0) return Response::make_error(kInvalidParams, "addr is 0");

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(addr)),
                         &mbi, sizeof(mbi)) == 0) {
            return Response::make_error(kInternalError, "VirtualQuery failed");
        }

        Response r;
        r.result = json::Value::object();
        r.result.set("base", json::Value(static_cast<int64_t>(
                                 reinterpret_cast<uintptr_t>(mbi.BaseAddress))));
        r.result.set("size", json::Value(static_cast<int64_t>(mbi.RegionSize)));
        r.result.set("state", json::Value(static_cast<int64_t>(mbi.State)));
        r.result.set("protect", json::Value(static_cast<int64_t>(mbi.Protect)));
        r.result.set("type", json::Value(static_cast<int64_t>(mbi.Type)));
        r.result.set("readable",
                     json::Value(mem::probe_readable(static_cast<uintptr_t>(addr), 1)));
        return r;
    }
};

// ---------- 把一行请求变成一行响应 ----------
//
// 输入：一行 JSON（不含换行）
// 输出：一行 JSON 响应（含换行）
inline std::string handle_line(Dispatcher& d, const char* line, size_t len) {
    json::Value req;
    if (!json::parse(line, len, req)) {
        json::Value err = json::Value::object();
        err.set("jsonrpc", json::Value("2.0"));
        err.set("id", json::Value::null());
        json::Value e = json::Value::object();
        e.set("code", json::Value(kParseError));
        e.set("message", json::Value("parse error"));
        err.set("error", std::move(e));
        return err.dump() + "\n";
    }

    // 提取 id（可能是 0，也可能是字符串；原样回填）
    const json::Value* idv = req.get("id");

    Response resp = d.dispatch(req);

    json::Value out = json::Value::object();
    out.set("jsonrpc", json::Value("2.0"));
    if (idv) {
        out.set("id", *idv);
    } else {
        out.set("id", json::Value::null());
    }

    if (resp.ok) {
        out.set("result", std::move(resp.result));
    } else {
        json::Value e = json::Value::object();
        e.set("code", json::Value(resp.errorCode));
        e.set("message", json::Value(resp.errorMessage));
        out.set("error", std::move(e));
    }

    return out.dump() + "\n";
}

}  // namespace rpc
}  // namespace ik

// client/rpc_client.hpp —— 外部主控侧的 JSON-RPC 客户端
//
// 协议：换行分隔的 JSON-RPC 2.0
//   → {"jsonrpc":"2.0","id":1,"method":"mem.read","params":{"addr":"0x...","size":4}}\n
//   ← {"jsonrpc":"2.0","id":1,"result":{"status":"ok","hex":"..."}}\n
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "payload/json.hpp"

namespace ik {

class RpcClient {
public:
    ~RpcClient() { close(); }

    bool connect(DWORD pid, DWORD timeoutMs = 5000) {
        wchar_t name[96] = {};
        wsprintfW(name, L"\\\\.\\pipe\\ik_%lu", pid);

        const DWORD deadline = GetTickCount() + timeoutMs;
        while (GetTickCount() < deadline) {
            h_ = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, 0, nullptr);
            if (h_ != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
                SetNamedPipeHandleState(h_, &mode, nullptr, nullptr);
                return true;
            }
            Sleep(100);
        }
        return false;
    }

    bool connected() const noexcept { return h_ != INVALID_HANDLE_VALUE; }

    // 发一行，等一行回复
    //
    // 用 PeekNamedPipe 轮询而不是阻塞读，这样能设超时也能检查取消。
    bool call(const std::string& request, std::string& response, DWORD timeoutMs = 5000) {
        response.clear();
        if (!connected()) return false;

        std::string line = request;
        if (line.empty() || line.back() != '\n') line += '\n';

        DWORD wrote = 0;
        if (!WriteFile(h_, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr) ||
            wrote != line.size()) {
            return false;
        }

        const DWORD deadline = GetTickCount() + timeoutMs;
        while (GetTickCount() < deadline) {
            DWORD avail = 0;
            if (!PeekNamedPipe(h_, nullptr, 0, nullptr, &avail, nullptr)) {
                return false;   // 断开
            }
            if (avail == 0) {
                Sleep(5);
                continue;
            }

            char buf[4096];
            DWORD got = 0;
            const DWORD want = avail < sizeof(buf) - 1 ? avail : sizeof(buf) - 1;
            if (!ReadFile(h_, buf, want, &got, nullptr) || got == 0) return false;

            response.append(buf, got);
            if (response.find('\n') != std::string::npos) {
                // 只取第一行
                const size_t nl = response.find('\n');
                response.resize(nl);
                return true;
            }
        }
        return false;
    }

    void close() {
        if (h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
            h_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// ---------- 便利封装 ----------
class Api {
public:
    explicit Api(RpcClient& c) : c_(c) {}

    // ping
    bool ping(int64_t& pidOut, int64_t& uptimeOut) {
        std::string resp;
        if (!c_.call(R"({"jsonrpc":"2.0","id":1,"method":"ping","params":{}})", resp)) {
            return false;
        }
        json::Value v;
        if (!json::parse(resp, v)) return false;
        const json::Value* r = v.get("result");
        if (!r) return false;
        pidOut = r->get_int("pid");
        uptimeOut = r->get_int("uptime_ms");
        return true;
    }

    // 读内存，返回 hex 字符串
    bool read(uint64_t addr, int size, std::string& hexOut, std::string& statusOut,
              int64_t& gotOut) {
        char req[256];
        snprintf(req, sizeof(req),
                 R"({"jsonrpc":"2.0","id":2,"method":"mem.read","params":{"addr":"0x%llX","size":%d}})",
                 static_cast<unsigned long long>(addr), size);

        std::string resp;
        if (!c_.call(req, resp)) return false;

        json::Value v;
        if (!json::parse(resp, v)) return false;
        const json::Value* r = v.get("result");
        if (!r) return false;

        statusOut = r->get_str("status");
        gotOut = r->get_int("got");
        hexOut = r->get_str("hex");
        return true;
    }

    // 多级指针链
    bool chain(uint64_t base, const std::vector<uint64_t>& offs, bool& okOut,
               uint64_t& addrOut) {
        std::string offsJson;
        for (size_t i = 0; i < offs.size(); ++i) {
            if (i) offsJson += ",";
            char b[32];
            snprintf(b, sizeof(b), "\"0x%llX\"", static_cast<unsigned long long>(offs[i]));
            offsJson += b;
        }

        char req[512];
        snprintf(req, sizeof(req),
                 R"({"jsonrpc":"2.0","id":3,"method":"mem.chain","params":{"base":"0x%llX","offs":[%s]}})",
                 static_cast<unsigned long long>(base), offsJson.c_str());

        std::string resp;
        if (!c_.call(req, resp)) return false;

        json::Value v;
        if (!json::parse(resp, v)) return false;
        const json::Value* r = v.get("result");
        if (!r) return false;

        okOut = r->get("ok") ? r->get("ok")->as_bool() : false;
        if (okOut) addrOut = r->get_addr("addr");
        return true;
    }

private:
    RpcClient& c_;
};

}  // namespace ik

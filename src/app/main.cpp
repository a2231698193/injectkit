// app/main.cpp —— 外部主控入口
//
// P1 阶段：通过 JSON-RPC 驱动 payload 读内存。
// 这是注入框架的第一个"有用"能力。
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "client/rpc_client.hpp"
#include "payload/json.hpp"
#include "common/obf.hpp"

namespace {

// hex 转字节（用于校验读到的内容）
size_t hex_to_bytes(const std::string& hex, uint8_t* out, size_t maxOut) {
    size_t n = 0;
    for (size_t i = 0; i + 1 < hex.size() && n < maxOut; i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return n;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(936);
    printf("=== injectkit client (P1) ===\n\n");

    if (argc < 2) {
        printf("用法：\n");
        printf("  ikclient.exe <pid>                  交互模式\n");
        printf("  ikclient.exe <pid> read <addr> <n>  读内存\n");
        printf("  ikclient.exe <pid> chain <base> <off1,off2,...>\n\n");
        printf("示例：\n");
        printf("  ikclient.exe 1234 read 0x140000000 16\n");
        return 1;
    }

    const DWORD pid = static_cast<DWORD>(_wtoi(argv[1]));
    if (pid == 0) {
        printf("pid 无效\n");
        return 1;
    }

    ik::RpcClient client;
    printf("连接 pid=%lu ...\n", pid);
    if (!client.connect(pid, 5000)) {
        printf("连不上 \\\\.\\pipe\\ik_%lu\n", pid);
        printf("检查：payload 是否注入成功、目标是否还在\n");
        return 1;
    }
    printf("已连接\n\n");

    ik::Api api(client);

    // ---- ping ----
    {
        int64_t rpid = 0, uptime = 0;
        if (api.ping(rpid, uptime)) {
            printf("[ping] pid=%lld uptime=%lldms\n", (long long)rpid, (long long)uptime);
        } else {
            printf("[ping] 失败\n");
            return 1;
        }
    }

    // ---- 命令行模式 ----
    if (argc >= 3 && wcscmp(argv[2], L"read") == 0) {
        if (argc < 4) { printf("需要地址\n"); return 1; }
        const uint64_t addr = _wcstoui64(argv[3], nullptr, 0);
        const int size = (argc > 4) ? _wtoi(argv[4]) : 16;

        std::string hex, status;
        int64_t got = 0;
        if (!api.read(addr, size, hex, status, got)) {
            printf("读取失败（RPC 层）\n");
            return 1;
        }

        printf("\n[mem.read] 0x%llX + %d\n", (unsigned long long)addr, size);
        printf("  status = %s\n", status.c_str());
        printf("  got    = %lld\n", (long long)got);

        if (!hex.empty()) {
            uint8_t bytes[4096];
            const size_t n = hex_to_bytes(hex, bytes, sizeof(bytes));
            printf("  hex    = %s\n", hex.c_str());
            printf("  ascii  = ");
            for (size_t i = 0; i < n; ++i) {
                const uint8_t b = bytes[i];
                putchar(b >= 0x20 && b < 0x7F ? b : '.');
            }
            printf("\n");
        }
        return 0;
    }

    if (argc >= 3 && wcscmp(argv[2], L"call") == 0) {
        if (argc < 4) { printf("需要函数地址\n"); return 1; }
        const uint64_t addr = _wcstoui64(argv[3], nullptr, 0);

        // 可选：参数列表（逗号分隔的十六进制/十进制）
        std::string argsJson;
        if (argc >= 5) {
            std::wstring s(argv[4]);
            size_t start = 0;
            bool first = true;
            while (start <= s.size()) {
                const size_t comma = s.find(L',', start);
                const std::wstring tok = s.substr(start, comma == std::wstring::npos
                                                             ? std::wstring::npos
                                                             : comma - start);
                if (!tok.empty()) {
                    if (!first) argsJson += ',';
                    first = false;
                    char b[32];
                    snprintf(b, sizeof(b), "\"0x%llX\"",
                             (unsigned long long)_wcstoui64(tok.c_str(), nullptr, 0));
                    argsJson += b;
                }
                if (comma == std::wstring::npos) break;
                start = comma + 1;
            }
        }

        char req[768];
        snprintf(req, sizeof(req),
                 R"({"jsonrpc":"2.0","id":4,"method":"game.call","params":{"addr":"0x%llX","args":[%s]}})",
                 (unsigned long long)addr, argsJson.c_str());

        std::string resp;
        if (!client.call(req, resp)) { printf("RPC 失败\n"); return 1; }

        json::Value v;
        if (!json::parse(resp, v)) { printf("响应解析失败\n"); return 1; }

        const json::Value* r = v.get("result");
        if (r) {
            printf("\n[game.call] 0x%llX\n", (unsigned long long)addr);
            printf("  ret_u = %s\n", r->get_str("ret_u").c_str());
            printf("  ret_i = %lld\n", (long long)r->get_int("ret_i"));
            const json::Value* rf = r->get("ret_f");
            if (rf) printf("  ret_f = %.6f\n", rf->as_number());
            const json::Value* rd = r->get("ret_d");
            if (rd) printf("  ret_d = %.10f\n", rd->as_number());
        } else {
            const json::Value* e = v.get("error");
            printf("\n[game.call] 错误: %s\n",
                   e ? e->get_str("message").c_str() : "unknown");
            return 1;
        }
        return 0;
    }

    if (argc >= 3 && wcscmp(argv[2], L"chain") == 0) {
        if (argc < 5) { printf("需要 base 和 offs\n"); return 1; }
        const uint64_t base = _wcstoui64(argv[3], nullptr, 0);

        std::vector<uint64_t> offs;
        {
            std::wstring s(argv[4]);
            size_t start = 0;
            while (start <= s.size()) {
                const size_t comma = s.find(L',', start);
                const std::wstring tok = s.substr(start, comma == std::wstring::npos
                                                             ? std::wstring::npos
                                                             : comma - start);
                if (!tok.empty()) offs.push_back(_wcstoui64(tok.c_str(), nullptr, 0));
                if (comma == std::wstring::npos) break;
                start = comma + 1;
            }
        }

        bool ok = false;
        uint64_t resolved = 0;
        if (!api.chain(base, offs, ok, resolved)) {
            printf("链解析失败（RPC 层）\n");
            return 1;
        }

        printf("\n[mem.chain] base=0x%llX 深度=%zu\n",
               (unsigned long long)base, offs.size());
        if (ok) {
            printf("  解析结果 = 0x%llX\n", (unsigned long long)resolved);
        } else {
            printf("  链断了（某一级指针为 0 或不可读）\n");
        }
        return 0;
    }

    // ---- 交互模式 ----
    printf("交互模式。命令：\n");
    printf("  read <addr> [n]       读内存\n");
    printf("  chain <base> <offs>   指针链\n");
    printf("  quit                  退出\n\n");

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        // 去尾换行
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
        if (len == 0) continue;

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) break;

        if (strncmp(line, "read ", 5) == 0) {
            unsigned long long addr = 0;
            int n = 16;
            if (sscanf(line + 5, "%lli %d", &addr, &n) >= 1) {
                std::string hex, status;
                int64_t got = 0;
                if (api.read(addr, n, hex, status, got)) {
                    printf("  %s: %s (%lld bytes)\n", status.c_str(),
                           hex.empty() ? "-" : hex.c_str(), (long long)got);
                } else {
                    printf("  RPC 失败\n");
                }
            }
            continue;
        }

        if (strncmp(line, "chain ", 6) == 0) {
            unsigned long long base = 0;
            char offsStr[256] = {};
            if (sscanf(line + 6, "%lli %255s", &base, offsStr) == 2) {
                std::vector<uint64_t> offs;
                char* tok = strtok(offsStr, ",");
                while (tok) {
                    offs.push_back(strtoull(tok, nullptr, 0));
                    tok = strtok(nullptr, ",");
                }
                bool ok = false;
                uint64_t resolved = 0;
                if (api.chain(base, offs, ok, resolved)) {
                    printf("  %s 0x%llX\n", ok ? "->" : "断链", (unsigned long long)resolved);
                }
            }
            continue;
        }

        printf("未知命令\n");
    }

    return 0;
}

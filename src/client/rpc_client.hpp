// client/rpc_client.hpp —— 外部主控侧的管道客户端
//
// 职责：连上 payload 的心跳管道，读事件，打印。
//
// P0 阶段只做"收"，不做"发命令"。发命令需要 JSON 序列化层，
// 那是 P1 的事。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <string>

namespace ik {

class HeartbeatClient {
public:
    ~HeartbeatClient() { close(); }

    // 连上指定 pid 的心跳管道
    bool connect(DWORD pid, DWORD timeoutMs = 5000) {
        char name[64] = {};
        // 用 wsprintf 避免依赖 CRT 的 snprintf 格式化行为差异
        wchar_t wide[96] = {};
        wsprintfW(wide, L"\\\\.\\pipe\\ik_%lu", pid);

        const DWORD deadline = GetTickCount() + timeoutMs;
        while (GetTickCount() < deadline) {
            h_ = CreateFileW(wide, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h_ != INVALID_HANDLE_VALUE) {
                // 切到阻塞读（默认行为），但要设超时避免永久卡住
                DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
                SetNamedPipeHandleState(h_, &mode, nullptr, nullptr);
                return true;
            }
            Sleep(100);
        }
        (void)name;
        return false;
    }

    bool connected() const noexcept { return h_ != INVALID_HANDLE_VALUE; }

    // 读一行（简易：读到换行或缓冲满）
    // 返回 false 表示管道断开或超时
    bool read_line(std::string& out, DWORD timeoutMs = 3000) {
        out.clear();
        if (!connected()) return false;

        // 用 PeekNamedPipe 做非阻塞等待，避免 ReadFile 永久阻塞
        const DWORD deadline = GetTickCount() + timeoutMs;
        while (GetTickCount() < deadline) {
            DWORD avail = 0;
            if (!PeekNamedPipe(h_, nullptr, 0, nullptr, &avail, nullptr)) {
                return false;   // 断开
            }
            if (avail == 0) {
                Sleep(50);
                continue;
            }

            char buf[512] = {};
            DWORD got = 0;
            const DWORD want = avail < sizeof(buf) - 1 ? avail : sizeof(buf) - 1;
            if (!ReadFile(h_, buf, want, &got, nullptr) || got == 0) return false;
            out.assign(buf, got);
            return true;
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

}  // namespace ik

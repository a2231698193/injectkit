// app/main.cpp —— 外部主控入口
//
// P0 阶段：连上 payload 的心跳管道，打印收到的事件。
// 不做任何游戏逻辑。
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "client/rpc_client.hpp"
#include "common/ringlog.hpp"

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(936);
    printf("=== injectkit client (P0) ===\n\n");

    // 参数：<pid> [等待秒数]
    if (argc < 2) {
        printf("用法：\n");
        printf("  ikclient.exe <pid> [超时秒数]\n\n");
        printf("示例：\n");
        printf("  ikclient.exe 1234 10\n");
        return 1;
    }

    const DWORD pid = static_cast<DWORD>(_wtoi(argv[1]));
    const DWORD timeoutSec = (argc > 2) ? static_cast<DWORD>(_wtoi(argv[2])) : 15;

    if (pid == 0) {
        printf("pid 无效\n");
        return 1;
    }

    printf("等待 pid=%lu 的 payload 心跳（最多 %lu 秒）...\n", pid, timeoutSec);

    ik::HeartbeatClient client;
    if (!client.connect(pid, timeoutSec * 1000)) {
        printf("\n连不上管道 \\\\.\\pipe\\ik_%lu\n", pid);
        printf("可能原因：\n");
        printf("  1. payload 还没起来（DLL 注入失败）\n");
        printf("  2. payload 起来了但没连上（管道名不对）\n");
        printf("  3. 目标进程已退出\n");
        return 1;
    }

    printf("已连接\n\n");

    std::string line;
    int count = 0;
    while (count < 10) {
        if (!client.read_line(line, 3000)) {
            printf("（%d 秒无数据，退出）\n", 3);
            break;
        }
        printf("[%d] %s\n", ++count, line.c_str());
    }

    printf("\n收到 %d 条事件\n", count);
    return 0;
}

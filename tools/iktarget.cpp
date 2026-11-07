#include <windows.h>
#include <cstdio>
int main(){
    printf("iktarget pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);
    for(;;) Sleep(500);
}

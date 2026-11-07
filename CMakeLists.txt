cmake_minimum_required(VERSION 3.20)
project(injectkit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ============================================================================
# 三段分离：payload / loader / client
#
#   payload  注入到目标进程里的部分（DLL）
#   loader  留在外面的部分：只做一次性注入
#   client  长期运行的外部主控：通过管道和 payload 通信
#
# 为什么必须分离：
#   * loader 崩了不影响游戏
#   * client 改逻辑不用重新注入
#   * payload 只负责"执行"，不负责"决策"
# ============================================================================

option(INJECTKIT_BUILD_PAYLOAD "Build the injected payload DLL" ON)
option(INJECTKIT_BUILD_LOADER  "Build the injector executable"   ON)
option(INJECTKIT_BUILD_CLIENT  "Build the external controller"   ON)
option(INJECTKIT_SELFTEST      "Build offline selftest"          OFF)

# ---------------- 公共编译约束 ----------------
set(IK_COMMON_DEFS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    set(IK_COMPILE_OPTS
        /MT /O2 /Oi /Gy /GR- /GS- /guard:cf-
        /permissive- /W4 /utf-8 /Zc:inline
    )
    set(IK_LINK_OPTS /DEBUG:NONE /OPT:REF /OPT:ICF /INCREMENTAL:NO /MANIFEST:NO)
else()
    set(IK_COMPILE_OPTS
        -O2 -ffunction-sections -fdata-sections
        -fno-rtti -fno-exceptions -fno-threadsafe-statics -fno-ident
        -Wall -Wextra -Wno-unused-parameter
    )
    set(IK_LINK_OPTS
        -static -s -municode
        -Wl,--gc-sections
        -Wl,--no-insert-timestamp
        -Wl,--build-id=none
    )
endif()

function(ik_apply target)
    target_include_directories(${target} PRIVATE src)
    target_compile_definitions(${target} PRIVATE ${IK_COMMON_DEFS})
    target_compile_options(${target} PRIVATE ${IK_COMPILE_OPTS})
    target_link_options(${target} PRIVATE ${IK_LINK_OPTS})
    target_link_libraries(${target} PRIVATE bcrypt)
endfunction()

# ---------------- payload（注入目标进程的 DLL）----------------
if(INJECTKIT_BUILD_PAYLOAD)
    add_library(ikpayload SHARED
        src/payload/entry.cpp
        src/payload/wrap_stub.cpp
    )
    ik_apply(ikpayload)
    if(NOT MSVC)
        # 拦掉 MinGW 运行库带进来的 OpenProcess（payload 根本不需要它）
        target_link_options(ikpayload PRIVATE
            -Wl,--wrap=__imp_OpenProcess
            -Wl,--wrap=__imp_DuplicateHandle
            -Wl,--wrap=__imp_SuspendThread
            -Wl,--wrap=__imp_ResumeThread
            -Wl,--wrap=__imp_SetThreadContext
            -Wl,--wrap=__imp_GetThreadContext)
    endif()
    # DLL 不需要 -static（会变大且没必要），但要剥符号
    target_compile_definitions(ikpayload PRIVATE INJECTKIT_PAYLOAD=1)
    set_target_properties(ikpayload PROPERTIES PREFIX "" OUTPUT_NAME "ikpayload")
endif()

# ---------------- loader（注入器）----------------
if(INJECTKIT_BUILD_LOADER)
    add_executable(ikloader
        src/loader/main.cpp
    )
    ik_apply(ikloader)
endif()

# ---------------- client（外部主控）----------------
if(INJECTKIT_BUILD_CLIENT)
    add_executable(ikclient
        src/app/main.cpp
        src/app/wrap_stub.cpp
    )
    ik_apply(ikclient)
    if(NOT MSVC)
        target_link_options(ikclient PRIVATE
            -Wl,--wrap=__imp_OpenProcess
            -Wl,--wrap=__imp_DuplicateHandle
            -Wl,--wrap=__imp_SuspendThread
            -Wl,--wrap=__imp_ResumeThread
            -Wl,--wrap=__imp_SetThreadContext
            -Wl,--wrap=__imp_GetThreadContext)
    endif()
endif()

# ---------------- 离线自检 ----------------
if(INJECTKIT_SELFTEST)
    add_executable(ikselftest
        src/app/selftest.cpp
        src/app/wrap_stub.cpp
    )
    ik_apply(ikselftest)
    target_compile_options(ikselftest PRIVATE -O2)
    if(NOT MSVC)
        # 拦掉 MinGW 运行库偷偷带进的敏感符号（同 memkit 的做法）
        target_link_options(ikselftest PRIVATE
            -Wl,--wrap=__imp_OpenProcess
            -Wl,--wrap=__imp_DuplicateHandle
            -Wl,--wrap=__imp_SuspendThread
            -Wl,--wrap=__imp_ResumeThread
            -Wl,--wrap=__imp_SetThreadContext
            -Wl,--wrap=__imp_GetThreadContext)
    endif()
endif()

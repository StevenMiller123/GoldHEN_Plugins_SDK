cmake_minimum_required(VERSION 3.20)
project(GoldHEN_SDK LANGUAGES C)

option(GOLDHEN_USE_PRINTF "Use printf logging instead of klog" OFF)
option(GOLDHEN_DEBUG      "Enable DEBUG=1 debug logging"       OFF)

add_library(goldhen_sdk_iface INTERFACE)
target_include_directories(goldhen_sdk_iface INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/GoldHEN>
)
if(GOLDHEN_USE_PRINTF)
    target_compile_definitions(goldhen_sdk_iface INTERFACE __USE_PRINTF__)
else()
    target_compile_definitions(goldhen_sdk_iface INTERFACE __USE_KLOG__)
endif()
if(GOLDHEN_DEBUG)
    target_compile_definitions(goldhen_sdk_iface INTERFACE DEBUG=1)
else()
    target_compile_definitions(goldhen_sdk_iface INTERFACE DEBUG=0)
endif()

add_library(goldhen_sdk STATIC
    source/Detour.c
    source/GoldHEN.c
    source/HDE64.c
    source/Patcher.c
    source/Syscall.c
    source/Utilities.c
    include/Common.h
    include/Detour.h
    include/GoldHEN.h
    include/HDE64.h
    include/Patcher.h
    include/Syscall.h
    include/Table64.h
    include/Utilities.h
)

add_library(goldhen_crt STATIC
    crt/crtprx.c
)

add_library(GoldHEN::SDK ALIAS goldhen_sdk)
add_library(GoldHEN::Crt ALIAS goldhen_crt)

target_link_libraries(goldhen_sdk PUBLIC  goldhen_sdk_iface)
target_link_libraries(goldhen_sdk PRIVATE sceLibcInternal kernel sceSysmodule)

set_target_properties(goldhen_sdk PROPERTIES
    OUTPUT_NAME "GoldHEN_SDK"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    STATIC_LIBRARY_OPTIONS   "--format=bsd"
)

set_target_properties(goldhen_crt PROPERTIES
    OUTPUT_NAME "gh_crtprx"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    STATIC_LIBRARY_OPTIONS   "--format=bsd"
)

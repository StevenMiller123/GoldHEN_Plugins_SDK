cmake_minimum_required(VERSION 3.20)
project(GoldHEN_Hook LANGUAGES C)

# ---------------------------------------------------------------------------
# Options (mirror the Makefile's PRINTF / DEBUGFLAGS switches)
# ---------------------------------------------------------------------------
option(GOLDHEN_USE_PRINTF "Use printf logging instead of klog" OFF)
option(GOLDHEN_DEBUG      "Enable DEBUG=1 debug logging"       OFF)

# ---------------------------------------------------------------------------
# Public interface target — include dirs + compile definitions that any
# consumer of this library needs. Carried transitively by the static lib.
# ---------------------------------------------------------------------------
add_library(goldhen_hook_iface INTERFACE)
target_include_directories(goldhen_hook_iface INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/GoldHEN>
)
if(GOLDHEN_USE_PRINTF)
    target_compile_definitions(goldhen_hook_iface INTERFACE __USE_PRINTF__)
else()
    target_compile_definitions(goldhen_hook_iface INTERFACE __USE_KLOG__)
endif()
if(GOLDHEN_DEBUG)
    target_compile_definitions(goldhen_hook_iface INTERFACE DEBUG=1)
else()
    target_compile_definitions(goldhen_hook_iface INTERFACE DEBUG=0)
endif()

add_library(goldhen_hook STATIC
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

add_library(GoldHEN::Hook ALIAS goldhen_hook)
add_library(GoldHEN::Crt ALIAS goldhen_crt)

target_link_libraries(goldhen_hook PUBLIC  goldhen_hook_iface)
target_link_libraries(goldhen_hook PRIVATE SceLibcInternal kernel SceSysmodule)

set_target_properties(goldhen_hook PROPERTIES
    OUTPUT_NAME "GoldHEN_Hook"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    STATIC_LIBRARY_OPTIONS   "--format=bsd"
)

set_target_properties(goldhen_crt PROPERTIES
    OUTPUT_NAME "gh_crtprx"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    STATIC_LIBRARY_OPTIONS   "--format=bsd"
)

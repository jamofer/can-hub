# Builds a pinned picotls at configure time, mirroring openssl.cmake.
#
# picotls is the single TLS stack: MIT, small, and the only ngtcp2 crypto
# backend whose handshake engine we can keep while replacing the crypto
# underneath (see MIGRATION_PICOTLS.md).
#
# ngtcp2 locates it through PICOTLS_INCLUDE_DIR / PICOTLS_LIBRARIES and runs a
# check_symbol_exists against them at configure time, so the archives have to
# exist by then; FetchContent alone would not be enough. Submodules (cifra,
# micro-ecc) are required for the minicrypto binding.

set(CAN_HUB_PICOTLS_COMMIT f07f1c8c68b237f1468bc1f1fe1b68aba3ff23b4)
if(NOT DEFINED CAN_HUB_ROOT_DIR)
    set(CAN_HUB_ROOT_DIR "${CMAKE_SOURCE_DIR}")
endif()
set(CAN_HUB_PICOTLS_PREFIX "${CAN_HUB_ROOT_DIR}/build/picotls-src")
set(CAN_HUB_PICOTLS_BUILD "${CMAKE_BINARY_DIR}/picotls-build")

# picotls guards its POSIX includes with #ifndef _WINDOWS but its CMake build
# never defines it — upstream builds for Windows through a Visual Studio project
# instead. Define it here so the mingw cross build compiles the Windows path,
# where minicrypto's RNG already uses BCrypt.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # picotls's wincompat.h includes <Winsock2.h>, which only resolves on a
    # case-insensitive filesystem: upstream builds Windows with MSVC, where the
    # casing never mattered. mingw on Linux needs the name as written.
    # Upstream's wincompat.h is written for MSVC: it includes <Winsock2.h>,
    # which only resolves on a case-insensitive filesystem, and defines a
    # struct timezone that mingw already provides. mingw supplies everything
    # picotls needs from it, so this replaces it rather than patching it.
    set(_picotls_wincompat "${CMAKE_BINARY_DIR}/picotls-wincompat")
    file(WRITE "${_picotls_wincompat}/wincompat.h"
"#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <malloc.h>
#include <sys/time.h>
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
")
    set(_picotls_platform_flags "-D_WINDOWS -I${_picotls_wincompat}")
else()
    set(_picotls_platform_flags "")
endif()

if(DEFINED CAN_HUB_OPENSSL_PREFIX)
    set(_picotls_openssl_root "-DOPENSSL_ROOT_DIR=${CAN_HUB_OPENSSL_PREFIX}")
else()
    set(_picotls_openssl_root "")
endif()

if(NOT DEFINED CAN_HUB_BUILD_PARALLELISM)
    include(ProcessorCount)
    ProcessorCount(CAN_HUB_BUILD_PARALLELISM)
    if(CAN_HUB_BUILD_PARALLELISM EQUAL 0)
        set(CAN_HUB_BUILD_PARALLELISM 1)
    endif()
endif()

# fusion is picotls's AES-NI engine. It is the only fast AES available once
# OpenSSL is gone, and QUIC needs one whatever suite is negotiated: RFC 9001
# fixes AES-128-GCM for Initial packets, which unauthenticated peers can make
# the hub process. x86-64 only, and gated again at runtime by
# ptls_fusion_is_supported_by_cpu.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(CAN_HUB_TLS_FUSION ON)
    set(_picotls_fusion_option "-DWITH_FUSION=ON")
    set(_picotls_fusion_target picotls-fusion)
else()
    set(CAN_HUB_TLS_FUSION OFF)
    set(_picotls_fusion_option "-DWITH_FUSION=OFF")
    set(_picotls_fusion_target "")
endif()

if(NOT EXISTS "${CAN_HUB_PICOTLS_BUILD}/libpicotls-core.a")
    message(STATUS "Building picotls ${CAN_HUB_PICOTLS_COMMIT}, one-off per build tree")

    if(NOT EXISTS "${CAN_HUB_PICOTLS_PREFIX}/.git")
        execute_process(
            COMMAND git clone --recurse-submodules https://github.com/h2o/picotls.git "${CAN_HUB_PICOTLS_PREFIX}"
            RESULT_VARIABLE _picotls_clone
        )
        if(NOT _picotls_clone EQUAL 0)
            message(FATAL_ERROR "could not clone picotls")
        endif()
    endif()

    execute_process(
        COMMAND git -C "${CAN_HUB_PICOTLS_PREFIX}" checkout --quiet ${CAN_HUB_PICOTLS_COMMIT}
        COMMAND git -C "${CAN_HUB_PICOTLS_PREFIX}" submodule update --init --recursive
        RESULT_VARIABLE _picotls_checkout
    )

    # The nested build has to be told it is cross-compiling, or it probes the
    # host and picks up host headers and host feature detection.
    set(_picotls_cross "")
    if(CMAKE_CROSSCOMPILING)
        list(APPEND _picotls_cross
            "-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
            "-DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}"
        )
        if(CMAKE_TOOLCHAIN_FILE)
            get_filename_component(_picotls_toolchain "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE)
            list(APPEND _picotls_cross "-DCMAKE_TOOLCHAIN_FILE=${_picotls_toolchain}")
        endif()
    endif()

    # cifra takes an MSVC-only branch under _WINDOWS: it calls _BitScanReverse,
    # which clang rejects on the uint32_t argument, and which computes leading
    # zeroes in a function named count_trailing_zeroes. Narrow it to MSVC so
    # mingw uses the GCC builtin. A no-op anywhere _WINDOWS is not defined.
    set(_cifra_bitops "${CAN_HUB_PICOTLS_PREFIX}/deps/cifra/src/bitops.h")
    file(READ "${_cifra_bitops}" _cifra_text)
    string(FIND "${_cifra_text}" "count_trailing_zeroes" _cifra_found)
    if(_cifra_found EQUAL -1)
        message(FATAL_ERROR "cifra changed shape: count_trailing_zeroes is gone, re-derive the mingw fix")
    endif()
    string(REPLACE "#ifdef _WINDOWS\n  uint32_t r = 0;\n  _BitScanReverse"
                   "#if defined(_WINDOWS) && defined(_MSC_VER)\n  uint32_t r = 0;\n  _BitScanReverse"
                   _cifra_text "${_cifra_text}")
    file(WRITE "${_cifra_bitops}" "${_cifra_text}")

    execute_process(
        COMMAND ${CMAKE_COMMAND} -S "${CAN_HUB_PICOTLS_PREFIX}" -B "${CAN_HUB_PICOTLS_BUILD}"
                -DCMAKE_BUILD_TYPE=Release
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                ${_picotls_cross}
                ${_picotls_fusion_option}
                "-DCMAKE_C_FLAGS=-ffunction-sections -fdata-sections ${_picotls_platform_flags}"
        RESULT_VARIABLE _picotls_configure
    )
    if(NOT _picotls_configure EQUAL 0)
        message(FATAL_ERROR "could not configure picotls")
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND} --build "${CAN_HUB_PICOTLS_BUILD}"
                --target picotls-core picotls-minicrypto ${_picotls_fusion_target}
                -j ${CAN_HUB_BUILD_PARALLELISM}
        RESULT_VARIABLE _picotls_build
    )
    if(NOT _picotls_build EQUAL 0)
        message(FATAL_ERROR "could not build picotls")
    endif()
endif()

set(PICOTLS_INCLUDE_DIR "${CAN_HUB_PICOTLS_PREFIX}/include")
set(PICOTLS_LIBRARIES
    "${CAN_HUB_PICOTLS_BUILD}/libpicotls-minicrypto.a"
    "${CAN_HUB_PICOTLS_BUILD}/libpicotls-core.a"
)
if(CAN_HUB_TLS_FUSION)
    list(INSERT PICOTLS_LIBRARIES 0 "${CAN_HUB_PICOTLS_BUILD}/libpicotls-fusion.a")
endif()

add_library(picotls INTERFACE)
if(CAN_HUB_TLS_FUSION)
    target_compile_definitions(picotls INTERFACE CAN_HUB_TLS_FUSION)
endif()
target_include_directories(picotls INTERFACE "${PICOTLS_INCLUDE_DIR}" "${CAN_HUB_PICOTLS_PREFIX}/lib")
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # wincompat.h ships under the Visual Studio project, not under include/
    target_include_directories(picotls INTERFACE "${_picotls_wincompat}")
    target_compile_definitions(picotls INTERFACE _WINDOWS)
endif()
target_link_libraries(picotls INTERFACE ${PICOTLS_LIBRARIES})

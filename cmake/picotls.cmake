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

    execute_process(
        COMMAND ${CMAKE_COMMAND} -S "${CAN_HUB_PICOTLS_PREFIX}" -B "${CAN_HUB_PICOTLS_BUILD}"
                -DCMAKE_BUILD_TYPE=Release
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                -DWITH_MINICRYPTO=ON
                -DWITH_FUSION=OFF
                "-DCMAKE_C_FLAGS=-ffunction-sections -fdata-sections"
        RESULT_VARIABLE _picotls_configure
    )
    if(NOT _picotls_configure EQUAL 0)
        message(FATAL_ERROR "could not configure picotls")
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND} --build "${CAN_HUB_PICOTLS_BUILD}"
                --target picotls-core picotls-minicrypto
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

add_library(picotls INTERFACE)
target_include_directories(picotls INTERFACE "${PICOTLS_INCLUDE_DIR}")
target_link_libraries(picotls INTERFACE ${PICOTLS_LIBRARIES})

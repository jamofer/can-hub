# Monocypher supplies the ED25519 signature primitive.
#
# Nothing else in the stack has it: cifra (behind picotls's minicrypto binding)
# ships X25519 for key exchange but no EdDSA, micro-ecc is NIST-curves only, and
# picotls implements ED25519 certificates only in its OpenSSL binding. Monocypher
# is 2-clause BSD or CC-0, so it works in both arms of the dual licence.
#
# Two translation units: the core, and the optional RFC 8032 (SHA-512) ED25519
# that TLS 1.3 signs with — Monocypher's default EdDSA is the BLAKE2b variant,
# which is not what the wire expects.

set(CAN_HUB_MONOCYPHER_TAG 4.0.2)
if(NOT DEFINED CAN_HUB_ROOT_DIR)
    set(CAN_HUB_ROOT_DIR "${CMAKE_SOURCE_DIR}")
endif()
set(CAN_HUB_MONOCYPHER_PREFIX "${CAN_HUB_ROOT_DIR}/build/monocypher-src")

if(NOT EXISTS "${CAN_HUB_MONOCYPHER_PREFIX}/src/monocypher.c")
    message(STATUS "Fetching Monocypher ${CAN_HUB_MONOCYPHER_TAG}, one-off")
    execute_process(
        COMMAND git clone --depth 1 --branch ${CAN_HUB_MONOCYPHER_TAG}
                https://github.com/LoupVaillant/Monocypher.git "${CAN_HUB_MONOCYPHER_PREFIX}"
        RESULT_VARIABLE _monocypher_clone
    )
    if(NOT _monocypher_clone EQUAL 0)
        message(FATAL_ERROR "could not clone Monocypher")
    endif()
endif()

add_library(monocypher STATIC
    "${CAN_HUB_MONOCYPHER_PREFIX}/src/monocypher.c"
    "${CAN_HUB_MONOCYPHER_PREFIX}/src/optional/monocypher-ed25519.c"
)
target_include_directories(monocypher PUBLIC
    "${CAN_HUB_MONOCYPHER_PREFIX}/src"
    "${CAN_HUB_MONOCYPHER_PREFIX}/src/optional"
)
set_target_properties(monocypher PROPERTIES POSITION_INDEPENDENT_CODE ON)

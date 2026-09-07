cmake_minimum_required(VERSION 3.16)
project(can_hub VERSION 0.3.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_definitions(CAN_HUB_VERSION="${PROJECT_VERSION}")

set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")

add_compile_options(-Wall -Wextra)

option(CAN_HUB_STATIC "Fully static binaries" OFF)

# picotls is the only TLS stack (MIGRATION_PICOTLS.md). The cross-compile,
# static and windows profiles are not wired into it yet; refuse them loudly
# rather than failing deep inside the dependency build.
if(CAN_HUB_STATIC)
    message(FATAL_ERROR "CAN_HUB_STATIC is not wired into the picotls build yet")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "the windows build is not wired into the picotls build yet")
endif()

include(ProcessorCount)
ProcessorCount(CAN_HUB_BUILD_PARALLELISM)
if(CAN_HUB_BUILD_PARALLELISM EQUAL 0)
    set(CAN_HUB_BUILD_PARALLELISM 1)
endif()
if(CAN_HUB_STATIC)
    add_compile_options(-ffunction-sections -fdata-sections)
    # 64K segment alignment so the static binaries load on kernels with any page
    # size (4K/16K/64K). Default 4K-aligned PT_LOAD segments fail to map and
    # SIGSEGV before main on 16K-page kernels (e.g. Raspberry Pi OS arm64 on Pi 5).
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -Wl,--gc-sections -Wl,-z,max-page-size=0x10000")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/picotls.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/monocypher.cmake)

include_directories(src)

include(FetchContent)
set(ENABLE_GNUTLS OFF CACHE BOOL "" FORCE)
# The crypto backend is built from ngtcp2's sources by
# cmake/ngtcp2_picotls_minicrypto.cmake, so ngtcp2 itself needs no TLS stack
# and its configure-time OpenSSL probe is skipped.
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_PICOTLS OFF CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(ngtcp2
    GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
    GIT_TAG 454390edaf6c954a101aa77961a939dd9e338ad2 # v1.23.0
)
FetchContent_MakeAvailable(ngtcp2)

# One name for "the TLS stack and its ngtcp2 backend", so the link lines below
# do not have to know which one is in play.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ngtcp2_picotls_minicrypto.cmake)

add_library(can_hub_tls INTERFACE)
target_link_libraries(can_hub_tls INTERFACE ngtcp2_crypto_picotls_minicrypto picotls monocypher)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(LIBCANHUB_WINDOWS_SOURCES
        src/protocol/wire.c
        src/protocol/message_header.c
        src/protocol/frame_message.c
        src/protocol/hello_message.c
        src/protocol/error_message.c
        src/protocol/list_message.c
        src/protocol/open_message.c
        src/protocol/register_message.c
        src/protocol/subscribe_message.c
        src/protocol/interface_name.c
        src/protocol/interface_status_message.c
        src/shared/egress_shaper.c
        src/client/client.c
        src/platform/windows/clock/clock.c
        src/platform/linux/shared/connect_url.c
        src/platform/linux/shared/message_framer.c
        src/platform/linux/shared/pin_store.c
        src/platform/linux/shared/pinned_server_verifier.c
        src/platform/linux/shared/tls_defaults.c
        src/platform/linux/shared/tls_peer_certificate.c
        src/platform/linux/shared/tls_ed25519.c
    src/platform/linux/shared/tls_ed25519.c
        src/platform/linux/tls/tls_channel.c
        src/platform/linux/tls/tls_client_security.c
        src/platform/linux/quic/quic_client_security.c
        src/platform/linux/quic/quic_connection.c
        src/platform/linux/quic/quic_control_channel.c
        src/platform/linux/quic/quic_egress.c
        src/platform/linux/quic/quic_reliable_streams.c
        src/platform/windows/quic/quic_udp_endpoint.c
        src/platform/windows/quic/quic_client_transport.c
        src/platform/windows/tcp/tcp_channel.c
        src/platform/windows/tcp/tcp_client_transport.c
        src/platform/windows/tls/tls_client_transport.c
        src/platform/windows/shared/tls_identity.c
        src/platform/windows/libcanhub/canhub.c
    )
    set(CAN_HUB_WINDOWS_LIBRARIES ws2_32 crypt32 bcrypt)

    add_library(canhub STATIC ${LIBCANHUB_WINDOWS_SOURCES})
    target_include_directories(canhub PUBLIC include)
    target_link_libraries(canhub PUBLIC ngtcp2_static can_hub_tls ${CAN_HUB_WINDOWS_LIBRARIES})

    add_library(canhub_shared SHARED ${LIBCANHUB_WINDOWS_SOURCES})
    target_include_directories(canhub_shared PUBLIC include)
    target_link_libraries(canhub_shared PRIVATE ngtcp2_static can_hub_tls ${CAN_HUB_WINDOWS_LIBRARIES})
    set_target_properties(canhub_shared PROPERTIES OUTPUT_NAME canhub C_VISIBILITY_PRESET hidden)

    add_executable(canhub-dump examples/canhub_dump.c)
    target_link_libraries(canhub-dump PRIVATE canhub)

    return()
endif()

set(COMMON_SOURCES
    src/version.c
    src/platform/linux/shared/cli_meta.c
    src/platform/linux/shared/log.c
    src/protocol/wire.c
    src/protocol/admin_message.c
    src/protocol/message_header.c
    src/protocol/frame_message.c
    src/protocol/hello_message.c
    src/protocol/error_message.c
    src/protocol/list_message.c
    src/protocol/open_message.c
    src/protocol/register_message.c
    src/protocol/subscribe_message.c
    src/protocol/ifconfig_message.c
    src/protocol/interface_status_message.c
    src/protocol/interface_name.c
    src/shared/egress_shaper.c
)

FetchContent_Declare(sqlite3
    URL https://sqlite.org/2026/sqlite-amalgamation-3530200.zip
    URL_HASH SHA256=8a310d0a16c7a90cacd4c884e70faa51c902afed2a89f63aaa0126ab83558a32
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3)
add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
target_compile_definitions(sqlite3 PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_THREADSAFE=0)

set(AGENT_SOURCES
    src/agent/agent.c
    src/agent/agent_app.c
    src/agent/domain/channel_map.c
    src/agent/domain/echo_correlator.c
    src/agent/domain/reconnect_backoff.c
    src/agent/domain/tx_pacer.c
    src/platform/linux/clock/clock.c
    src/platform/linux/shared/connect_url.c
    src/platform/linux/shared/epoll_registry.c
    src/platform/linux/shared/pin_store.c
    src/platform/linux/shared/pinned_server_verifier.c
    src/platform/linux/shared/tls_defaults.c
    src/platform/linux/shared/tls_identity.c
    src/platform/linux/shared/tls_identity_ed25519.c
    src/platform/linux/shared/tls_peer_certificate.c
    src/platform/linux/shared/tls_ed25519.c
    src/platform/linux/shared/message_framer.c
    src/platform/linux/socketcan/socketcan_adapter.c
    src/platform/linux/socketcan/can_netlink.c
    src/platform/linux/tcp/tcp_channel.c
    src/platform/linux/tcp/tcp_client_transport.c
    src/platform/linux/tls/tls_channel.c
    src/platform/linux/tls/tls_client_security.c
    src/platform/linux/tls/tls_client_transport.c
    src/platform/linux/quic/quic_client_security.c
    src/platform/linux/quic/quic_client_transport.c
    src/platform/linux/quic/quic_connection.c
    src/platform/linux/quic/quic_datagram_backlog.c
    src/platform/linux/quic/quic_control_channel.c
    src/platform/linux/quic/quic_egress.c
    src/platform/linux/quic/quic_udp_gso.c
    src/platform/linux/quic/quic_reliable_streams.c
    src/platform/linux/quic/quic_udp_endpoint.c
)

set(HUB_SOURCES
    src/hub/broker.c
    src/hub/hub_app.c
    src/hub/domain/admin_views.c
    src/hub/domain/client_session.c
    src/hub/domain/egress_queue.c
    src/hub/domain/frame_routes.c
    src/hub/domain/hub_peer.c
    src/hub/domain/interface_registry.c
    src/hub/domain/peer_directory.c
    src/platform/linux/clock/clock.c
    src/platform/linux/shared/connect_url.c
    src/platform/linux/shared/epoll_registry.c
    src/platform/linux/shared/listen_endpoint.c
    src/platform/linux/shared/pin_store.c
    src/platform/linux/shared/tls_defaults.c
    src/platform/linux/shared/tls_identity.c
    src/platform/linux/shared/tls_identity_ed25519.c
    src/platform/linux/shared/tls_peer_certificate.c
    src/platform/linux/shared/tls_ed25519.c
    src/platform/linux/shared/message_framer.c
    src/platform/linux/tcp/tcp_channel.c
    src/platform/linux/tcp/tcp_server_transport.c
    src/platform/linux/tls/tls_channel.c
    src/platform/linux/tls/tls_server_security.c
    src/platform/linux/tls/tls_server_transport.c
    src/platform/linux/quic/quic_connection.c
    src/platform/linux/quic/quic_control_channel.c
    src/platform/linux/quic/quic_egress.c
    src/platform/linux/quic/quic_udp_gso.c
    src/platform/linux/quic/quic_reliable_streams.c
    src/platform/linux/quic/quic_server_security.c
    src/platform/linux/quic/quic_server_transport.c
    src/platform/linux/sqlite/identity_database.c
)

add_executable(can-hub src/platform/linux/hub_main.c ${COMMON_SOURCES} ${HUB_SOURCES})
target_link_libraries(can-hub PRIVATE ngtcp2_static can_hub_tls sqlite3)
add_executable(can-hub-agent src/platform/linux/agent_main.c ${COMMON_SOURCES} ${AGENT_SOURCES})
target_link_libraries(can-hub-agent PRIVATE ngtcp2_static can_hub_tls)
set(CLIENT_SOURCES
    src/client/client.c
    src/platform/linux/clock/clock.c
    src/platform/linux/shared/connect_url.c
    src/platform/linux/shared/epoll_registry.c
    src/platform/linux/shared/message_framer.c
    src/platform/linux/tcp/tcp_channel.c
    src/platform/linux/tcp/tcp_client_transport.c
)

set(CLIENT_ATTACH_SOURCES
    src/mirror/mirror_app.c
    src/platform/linux/socketcan/socketcan_adapter.c
    src/platform/linux/socketcan/can_netlink.c
)

set(CLIENT_TLS_SOURCES
    src/platform/linux/shared/pin_store.c
    src/platform/linux/shared/pinned_server_verifier.c
    src/platform/linux/shared/tls_defaults.c
    src/platform/linux/shared/tls_identity.c
    src/platform/linux/shared/tls_identity_ed25519.c
    src/platform/linux/shared/tls_peer_certificate.c
    src/platform/linux/shared/tls_ed25519.c
    src/platform/linux/tls/tls_channel.c
    src/platform/linux/tls/tls_client_security.c
    src/platform/linux/tls/tls_client_transport.c
    src/platform/linux/quic/quic_client_security.c
    src/platform/linux/quic/quic_client_transport.c
    src/platform/linux/quic/quic_connection.c
    src/platform/linux/quic/quic_datagram_backlog.c
    src/platform/linux/quic/quic_control_channel.c
    src/platform/linux/quic/quic_egress.c
    src/platform/linux/quic/quic_udp_gso.c
    src/platform/linux/quic/quic_reliable_streams.c
    src/platform/linux/quic/quic_udp_endpoint.c
)

set(SOCKETCAND_SOURCES
    src/socketcand/socketcand_bridge.c
    src/socketcand/socketcand_app.c
    src/socketcand/domain/ascii_framer.c
    src/socketcand/domain/socketcand_codec.c
    src/socketcand/domain/interface_catalogue.c
    src/socketcand/domain/connection_table.c
    src/socketcand/domain/beacon_xml.c
    src/platform/linux/socketcand/socketcand_server.c
    src/platform/linux/socketcand/beacon_udp.c
)

add_executable(can-hub-client src/platform/linux/client_main.c ${COMMON_SOURCES} ${CLIENT_SOURCES} ${CLIENT_ATTACH_SOURCES} ${CLIENT_TLS_SOURCES} ${SOCKETCAND_SOURCES})
target_link_libraries(can-hub-client PRIVATE ngtcp2_static can_hub_tls)
add_executable(can-hub-cli src/platform/linux/cli_main.c ${COMMON_SOURCES} ${CLIENT_SOURCES})

set(LIBCANHUB_SOURCES
    src/platform/linux/libcanhub/canhub.c
    ${CLIENT_SOURCES}
    ${CLIENT_TLS_SOURCES}
)

add_library(canhub STATIC ${COMMON_SOURCES} ${LIBCANHUB_SOURCES})
target_include_directories(canhub PUBLIC include)
target_link_libraries(canhub PUBLIC ngtcp2_static can_hub_tls)

if(NOT CAN_HUB_STATIC)
    add_library(canhub_shared SHARED ${COMMON_SOURCES} ${LIBCANHUB_SOURCES})
    target_include_directories(canhub_shared PUBLIC include)
    target_link_libraries(canhub_shared PRIVATE ngtcp2_static can_hub_tls)
    set_target_properties(canhub_shared PROPERTIES
        OUTPUT_NAME canhub
        C_VISIBILITY_PRESET hidden
        SOVERSION 0
    )
    install(TARGETS canhub_shared LIBRARY DESTINATION lib)
endif()

add_executable(canhub-dump examples/canhub_dump.c)
target_link_libraries(canhub-dump PRIVATE canhub)

install(TARGETS can-hub can-hub-agent can-hub-cli RUNTIME DESTINATION bin)
install(TARGETS canhub ARCHIVE DESTINATION lib)
install(FILES include/canhub.h DESTINATION include)

option(CAN_HUB_PACKAGING "Generate per-binary Debian packages with CPack" OFF)
if(CAN_HUB_PACKAGING)
    include(${CMAKE_CURRENT_SOURCE_DIR}/packaging/cpack-deb.cmake)
endif()

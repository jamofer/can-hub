set(CEST_DIR ${CMAKE_SOURCE_DIR}/vendor)

# add_unit_test(<name> SOURCES <test.cpp> [real_src.c ...])
#
# Registers a cest executable. Includes: cest + src/.
function(add_unit_test TEST_NAME)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})

    add_executable(${TEST_NAME} ${ARG_SOURCES})

    target_compile_features(${TEST_NAME} PRIVATE cxx_std_20)
    target_compile_options(${TEST_NAME} PRIVATE -Wall -Wextra -Wno-unused-parameter)

    target_include_directories(${TEST_NAME} PRIVATE
        ${CEST_DIR}
        ${ROOT_SRC_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endfunction()

# ── Registered tests ─────────────────────────────────────────────────────────

add_unit_test(test_version
    SOURCES
        version/test_version.cpp
        ${ROOT_SRC_DIR}/version.c
)

add_unit_test(test_log
    SOURCES
        platform/test_log.cpp
        ${ROOT_SRC_DIR}/platform/linux/shared/log.c
)

add_unit_test(test_message_header
    SOURCES
        protocol/test_message_header.cpp
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_list_message
    SOURCES
        protocol/test_list_message.cpp
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_open_message
    SOURCES
        protocol/test_open_message.cpp
        ${ROOT_SRC_DIR}/protocol/open_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_subscribe_message
    SOURCES
        protocol/test_subscribe_message.cpp
        ${ROOT_SRC_DIR}/protocol/subscribe_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_ifconfig_message
    SOURCES
        protocol/test_ifconfig_message.cpp
        ${ROOT_SRC_DIR}/protocol/ifconfig_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_interface_status_message
    SOURCES
        protocol/test_interface_status_message.cpp
        ${ROOT_SRC_DIR}/protocol/interface_status_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_frame_message
    SOURCES
        protocol/test_frame_message.cpp
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_hello_message
    SOURCES
        protocol/test_hello_message.cpp
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_error_message
    SOURCES
        protocol/test_error_message.cpp
        ${ROOT_SRC_DIR}/protocol/error_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_register_message
    SOURCES
        protocol/test_register_message.cpp
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_admin_message
    SOURCES
        protocol/test_admin_message.cpp
        ${ROOT_SRC_DIR}/protocol/admin_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_reconnect_backoff
    SOURCES
        agent/domain/test_reconnect_backoff.cpp
        ${ROOT_SRC_DIR}/agent/domain/reconnect_backoff.c
)

add_unit_test(test_channel_map
    SOURCES
        agent/domain/test_channel_map.cpp
        ${ROOT_SRC_DIR}/agent/domain/channel_map.c
)

add_unit_test(test_echo_correlator
    SOURCES
        agent/domain/test_echo_correlator.cpp
        ${ROOT_SRC_DIR}/agent/domain/echo_correlator.c
)

add_unit_test(test_tx_pacer
    SOURCES
        agent/domain/test_tx_pacer.cpp
        ${ROOT_SRC_DIR}/agent/domain/tx_pacer.c
)

add_unit_test(test_quic_control_channel
    SOURCES
        platform/test_quic_control_channel.cpp
        ${ROOT_SRC_DIR}/platform/linux/quic/quic_control_channel.c
        ${ROOT_SRC_DIR}/platform/linux/shared/message_framer.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_connect_url
    SOURCES
        platform/test_connect_url.cpp
        ${ROOT_SRC_DIR}/platform/linux/shared/connect_url.c
)

add_unit_test(test_listen_endpoint
    SOURCES
        platform/test_listen_endpoint.cpp
        ${ROOT_SRC_DIR}/platform/linux/shared/listen_endpoint.c
)

add_unit_test(test_quic_datagram_backlog
    SOURCES
        platform/test_quic_datagram_backlog.cpp
        ${ROOT_SRC_DIR}/platform/linux/quic/quic_datagram_backlog.c
)

add_unit_test(test_message_framer
    SOURCES
        platform/test_message_framer.cpp
        ${ROOT_SRC_DIR}/platform/linux/shared/message_framer.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_tls_channel
    SOURCES
        platform/test_tls_channel.cpp
        ${ROOT_SRC_DIR}/platform/linux/tls/tls_channel.c
        ${ROOT_SRC_DIR}/platform/linux/tls/tls_client_security.c
        ${ROOT_SRC_DIR}/platform/linux/tls/tls_server_security.c
        ${ROOT_SRC_DIR}/platform/linux/shared/pin_store.c
        ${ROOT_SRC_DIR}/platform/linux/shared/pinned_server_verifier.c
        ${ROOT_SRC_DIR}/platform/linux/shared/tls_defaults.c
        ${ROOT_SRC_DIR}/platform/linux/shared/tls_identity.c
        ${ROOT_SRC_DIR}/platform/linux/shared/tls_identity_openssl.c
        ${ROOT_SRC_DIR}/platform/linux/shared/tls_peer_certificate.c
        ${ROOT_SRC_DIR}/platform/linux/shared/message_framer.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)
target_link_libraries(test_tls_channel PRIVATE picotls OpenSSL::SSL OpenSSL::Crypto)

add_unit_test(test_identity_database
    SOURCES
        platform/test_identity_database.cpp
        ${ROOT_SRC_DIR}/platform/linux/sqlite/identity_database.c
)
target_link_libraries(test_identity_database PRIVATE sqlite3)

add_unit_test(test_agent
    SOURCES
        agent/test_agent.cpp
        ${ROOT_SRC_DIR}/agent/agent.c
        ${ROOT_SRC_DIR}/agent/domain/channel_map.c
        ${ROOT_SRC_DIR}/agent/domain/echo_correlator.c
        ${ROOT_SRC_DIR}/agent/domain/reconnect_backoff.c
        ${ROOT_SRC_DIR}/agent/domain/tx_pacer.c
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/ifconfig_message.c
        ${ROOT_SRC_DIR}/protocol/interface_status_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)
target_link_libraries(test_agent PRIVATE port_mocks)

add_unit_test(test_interface_registry
    SOURCES
        hub/domain/test_interface_registry.cpp
        ${ROOT_SRC_DIR}/hub/domain/interface_registry.c
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_client_session
    SOURCES
        hub/domain/test_client_session.cpp
        ${ROOT_SRC_DIR}/hub/domain/client_session.c
)

add_unit_test(test_admin_views
    SOURCES
        hub/domain/test_admin_views.cpp
        ${ROOT_SRC_DIR}/hub/domain/admin_views.c
        ${ROOT_SRC_DIR}/hub/domain/hub_peer.c
        ${ROOT_SRC_DIR}/hub/domain/client_session.c
        ${ROOT_SRC_DIR}/hub/domain/egress_queue.c
        ${ROOT_SRC_DIR}/hub/domain/interface_registry.c
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
        ${ROOT_SRC_DIR}/hub/domain/peer_directory.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_hub_peer
    SOURCES
        hub/domain/test_hub_peer.cpp
        ${ROOT_SRC_DIR}/hub/domain/hub_peer.c
        ${ROOT_SRC_DIR}/hub/domain/client_session.c
)

add_unit_test(test_egress_queue
    SOURCES
        hub/domain/test_egress_queue.cpp
        ${ROOT_SRC_DIR}/hub/domain/egress_queue.c
)

add_unit_test(test_egress_shaper
    SOURCES
        hub/domain/test_egress_shaper.cpp
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
)

add_unit_test(test_frame_routes
    SOURCES
        hub/domain/test_frame_routes.cpp
        ${ROOT_SRC_DIR}/hub/domain/frame_routes.c
        ${ROOT_SRC_DIR}/hub/domain/interface_registry.c
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
        ${ROOT_SRC_DIR}/hub/domain/client_session.c
        ${ROOT_SRC_DIR}/hub/domain/hub_peer.c
        ${ROOT_SRC_DIR}/hub/domain/egress_queue.c
        ${ROOT_SRC_DIR}/hub/domain/peer_directory.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_broker
    SOURCES
        hub/test_broker.cpp
        ${ROOT_SRC_DIR}/hub/broker.c
        ${ROOT_SRC_DIR}/hub/domain/admin_views.c
        ${ROOT_SRC_DIR}/hub/domain/egress_queue.c
        ${ROOT_SRC_DIR}/hub/domain/frame_routes.c
        ${ROOT_SRC_DIR}/protocol/error_message.c
        ${ROOT_SRC_DIR}/hub/domain/hub_peer.c
        ${ROOT_SRC_DIR}/hub/domain/interface_registry.c
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
        ${ROOT_SRC_DIR}/hub/domain/client_session.c
        ${ROOT_SRC_DIR}/hub/domain/peer_directory.c
        ${ROOT_SRC_DIR}/protocol/admin_message.c
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/open_message.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/subscribe_message.c
        ${ROOT_SRC_DIR}/protocol/ifconfig_message.c
        ${ROOT_SRC_DIR}/protocol/interface_status_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)
target_link_libraries(test_broker PRIVATE port_mocks)

add_unit_test(test_client
    SOURCES
        client/test_client.cpp
        ${ROOT_SRC_DIR}/client/client.c
        ${ROOT_SRC_DIR}/protocol/error_message.c
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/interface_name.c
        ${ROOT_SRC_DIR}/protocol/interface_status_message.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/open_message.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/subscribe_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
        ${ROOT_SRC_DIR}/shared/egress_shaper.c
)
target_link_libraries(test_client PRIVATE port_mocks)

add_unit_test(test_mirror_app
    SOURCES
        mirror/test_mirror_app.cpp
        ${ROOT_SRC_DIR}/mirror/mirror_app.c
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/interface_name.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/open_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)
target_link_libraries(test_mirror_app PRIVATE port_mocks)

add_unit_test(test_interface_name
    SOURCES
        protocol/test_interface_name.cpp
        ${ROOT_SRC_DIR}/protocol/interface_name.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/register_message.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)

add_unit_test(test_ascii_framer
    SOURCES
        socketcand/test_ascii_framer.cpp
        ${ROOT_SRC_DIR}/socketcand/domain/ascii_framer.c
)

add_unit_test(test_socketcand_codec
    SOURCES
        socketcand/test_socketcand_codec.cpp
        ${ROOT_SRC_DIR}/socketcand/domain/socketcand_codec.c
)

add_unit_test(test_interface_catalogue
    SOURCES
        socketcand/test_interface_catalogue.cpp
        ${ROOT_SRC_DIR}/socketcand/domain/interface_catalogue.c
)

add_unit_test(test_beacon_xml
    SOURCES
        socketcand/test_beacon_xml.cpp
        ${ROOT_SRC_DIR}/socketcand/domain/beacon_xml.c
        ${ROOT_SRC_DIR}/socketcand/domain/interface_catalogue.c
)

add_unit_test(test_socketcand_bridge
    SOURCES
        socketcand/test_socketcand_bridge.cpp
        ${ROOT_SRC_DIR}/socketcand/socketcand_bridge.c
        ${ROOT_SRC_DIR}/socketcand/domain/ascii_framer.c
        ${ROOT_SRC_DIR}/socketcand/domain/socketcand_codec.c
        ${ROOT_SRC_DIR}/socketcand/domain/interface_catalogue.c
        ${ROOT_SRC_DIR}/socketcand/domain/connection_table.c
        ${ROOT_SRC_DIR}/socketcand/domain/beacon_xml.c
        ${ROOT_SRC_DIR}/protocol/frame_message.c
        ${ROOT_SRC_DIR}/protocol/hello_message.c
        ${ROOT_SRC_DIR}/protocol/list_message.c
        ${ROOT_SRC_DIR}/protocol/open_message.c
        ${ROOT_SRC_DIR}/protocol/message_header.c
        ${ROOT_SRC_DIR}/protocol/wire.c
)
target_link_libraries(test_socketcand_bridge PRIVATE port_mocks)

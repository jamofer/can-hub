#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include <sys/socket.h>

#include "platform/linux/quic/quic_connection.h"
#include "platform/linux/quic/quic_control_channel.h"
#include "platform/linux/quic/quic_reliable_streams.h"
#include "platform/linux/quic/quic_server_security.h"
#include "platform/linux/shared/tls_identity.h"
#include "hub/ports/hub_transport_events.h"
#include "hub/ports/hub_transport_port.h"

#define QUIC_SERVER_PEERS_MAX 64

/*
 * QUIC server transport for the hub: one UDP socket multiplexing every
 * connection, peers matched by Destination Connection ID (survives client
 * migration and NAT rebinding; the remote address follows the latest
 * packet), one shared expiry timer armed to the earliest deadline. Control
 * plane on the client-opened bidirectional stream, data plane on datagrams.
 * Reliable channels ride dedicated bidirectional streams: the hub opens one
 * per channel (set_channel_mode) for that channel's frames; an incoming
 * stream that is neither the control nor a known reliable stream is adopted
 * for receive (its frames carry their own channel).
 */
typedef struct QuicServerTransport QuicServerTransport;

typedef struct {
    QuicServerTransport *transport;
    QuicConnection connection;
    QuicServerSession session;
    QuicControlChannel control;
    QuicReliableStreamSet reliable_streams;
    ngtcp2_cid original_dcid;
    char fingerprint_hex[TLS_IDENTITY_FINGERPRINT_HEX_SIZE];
    struct sockaddr_storage remote_address;
    socklen_t remote_address_length;
    uint32_t peer_id;
    bool connected;
    bool close_pending;
} QuicServerPeer;

struct QuicServerTransport {
    HubTransportPort port;
    HubTransportEvents events;
    QuicServerSecurity security;
    int32_t udp_fd;
    int32_t timer_fd;
    uint32_t next_peer_id;
    bool dispatching;
    bool gso_unsupported;
    QuicServerPeer *dispatching_peer;
    struct sockaddr_storage local_address;
    socklen_t local_address_length;
    QuicServerPeer peers[QUIC_SERVER_PEERS_MAX];
};

bool QuicServerTransport_Init(
    QuicServerTransport *self,
    const char *bind_address,
    const char *port,
    const char *certificate_file,
    const char *key_file,
    uint32_t peer_id_base,
    const HubTransportEvents *events
);
HubTransportPort *QuicServerTransport_Port(QuicServerTransport *self);
int32_t QuicServerTransport_UdpFd(const QuicServerTransport *self);
int32_t QuicServerTransport_TimerFd(const QuicServerTransport *self);
void QuicServerTransport_OnUdpReadable(QuicServerTransport *self);
void QuicServerTransport_OnTimer(QuicServerTransport *self);

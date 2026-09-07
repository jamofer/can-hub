#include "platform/linux/quic/quic_server_transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#include "platform/linux/clock/clock.h"
#include "platform/linux/quic/quic_egress.h"
#include "platform/linux/quic/quic_udp_gso.h"
#include "platform/linux/shared/listen_endpoint.h"
#include "protocol/message_header.h"

#define UDP_PACKET_BUFFER_SIZE 1452
#define UDP_SOCKET_BUFFER_BYTES (4 * 1024 * 1024)
#define QUIC_SERVER_ORIGIN_SIZE 56

static bool portSendControl(void *context, uint32_t peer_id, const uint8_t *data, size_t size);
static bool portSendFrame(void *context, uint32_t peer_id, uint8_t channel, const uint8_t *data, size_t size);
static void portSetChannelMode(void *context, uint32_t peer_id, uint8_t channel, bool reliable);
static void portClosePeer(void *context, uint32_t peer_id);
static QuicServerPeer *findPeerById(QuicServerTransport *self, uint32_t peer_id);
static QuicServerPeer *findPeerByDcid(QuicServerTransport *self, const uint8_t *packet, size_t packet_size);
static void refreshPeerAddress(
    QuicServerPeer *peer,
    const struct sockaddr_storage *address,
    socklen_t address_length
);
static QuicServerPeer *acceptPeer(
    QuicServerTransport *self,
    const struct sockaddr_storage *address,
    socklen_t address_length,
    const uint8_t *packet,
    size_t packet_size
);
static void makePeerPath(QuicServerTransport *self, QuicServerPeer *peer, ngtcp2_path *path);
static bool flushPeer(QuicServerTransport *self, QuicServerPeer *peer, const uint8_t *datagram, size_t datagram_size);
static void notifyWritable(QuicServerTransport *self, QuicServerPeer *peer);
static void sendPacketToPeer(void *context, const uint8_t *data, size_t size, size_t segment_size);
static void sendToPeer(QuicServerTransport *self, QuicServerPeer *peer, const uint8_t *data, size_t size, size_t segment_size);
static void rearmTimer(QuicServerTransport *self);
static void teardownPeer(QuicServerTransport *self, QuicServerPeer *peer, bool notify);
static void dispatchControlMessages(QuicServerTransport *self, QuicServerPeer *peer);
static void capturePeerFingerprint(QuicServerPeer *peer);
static void onHandshakeCompleted(void *context);
static void onDatagram(void *context, const uint8_t *data, size_t size);
static void onStreamData(void *context, int64_t stream_id, const uint8_t *data, size_t size);
static void onStreamAcked(void *context, int64_t stream_id, uint64_t acked_end_offset);
static void receiveControlData(QuicServerPeer *peer, const uint8_t *data, size_t size);
static bool serverFrameSink(void *context, const uint8_t *frame, size_t size);
static void retryStalledReliableStreams(QuicServerTransport *self);

/* ---------- public ---------- */

bool QuicServerTransport_Init(
    QuicServerTransport *self,
    const char *bind_address,
    const char *port,
    const char *certificate_file,
    const char *key_file,
    uint32_t peer_id_base,
    const HubTransportEvents *events
)
{
    struct sockaddr_storage address;
    socklen_t address_length;
    int32_t address_family;
    int32_t buffer_bytes;

    memset(self, 0, sizeof(*self));
    self->port.context = self;
    self->port.send_control = portSendControl;
    self->port.send_frame = portSendFrame;
    self->port.set_channel_mode = portSetChannelMode;
    self->port.close_peer = portClosePeer;
    self->events = *events;
    self->next_peer_id = peer_id_base;

    if (!QuicServerSecurity_Init(&self->security, certificate_file, key_file)) {
        return false;
    }

    self->udp_fd = ListenEndpoint_OpenSocket(SOCK_DGRAM, &address_family);
    self->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (self->udp_fd < 0 || self->timer_fd < 0) {
        return false;
    }

    buffer_bytes = UDP_SOCKET_BUFFER_BYTES;
    setsockopt(self->udp_fd, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
    setsockopt(self->udp_fd, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));

    if (!ListenEndpoint_BuildSockaddr(address_family, bind_address, port, &address, &address_length)) {
        return false;
    }
    if (bind(self->udp_fd, (struct sockaddr *)&address, address_length) < 0) {
        return false;
    }

    self->local_address_length = sizeof(self->local_address);
    getsockname(self->udp_fd, (struct sockaddr *)&self->local_address, &self->local_address_length);

    return true;
}

HubTransportPort *QuicServerTransport_Port(QuicServerTransport *self)
{
    return &self->port;
}

int32_t QuicServerTransport_UdpFd(const QuicServerTransport *self)
{
    return self->udp_fd;
}

int32_t QuicServerTransport_TimerFd(const QuicServerTransport *self)
{
    return self->timer_fd;
}

void QuicServerTransport_OnUdpReadable(QuicServerTransport *self)
{
    uint8_t packet[UDP_PACKET_BUFFER_SIZE];
    struct sockaddr_storage peer_address;
    socklen_t peer_address_length;
    QuicServerPeer *peer;
    ngtcp2_path path;
    ssize_t bytes_received;

    for (;;) {
        peer_address_length = sizeof(peer_address);
        bytes_received = recvfrom(
            self->udp_fd,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr *)&peer_address,
            &peer_address_length
        );
        if (bytes_received <= 0) {
            break;
        }

        peer = findPeerByDcid(self, packet, (size_t)bytes_received);
        if (peer == NULL) {
            peer = acceptPeer(self, &peer_address, peer_address_length, packet, (size_t)bytes_received);
            if (peer == NULL) {
                continue;
            }
        } else {
            refreshPeerAddress(peer, &peer_address, peer_address_length);
        }

        makePeerPath(self, peer, &path);
        self->dispatching = true;
        self->dispatching_peer = peer;
        if (!QuicConnection_ReadPacket(&peer->connection, &path, packet, (size_t)bytes_received)) {
            self->dispatching = false;
            self->dispatching_peer = NULL;
            teardownPeer(self, peer, true);
            continue;
        }
        self->dispatching = false;
        self->dispatching_peer = NULL;

        if (peer->close_pending) {
            flushPeer(self, peer, NULL, 0);
            teardownPeer(self, peer, false);
            continue;
        }
        flushPeer(self, peer, NULL, 0);
        notifyWritable(self, peer);
    }

    retryStalledReliableStreams(self);
    rearmTimer(self);
}

void QuicServerTransport_OnTimer(QuicServerTransport *self)
{
    uint64_t expiration_count;
    uint64_t now_ns;
    uint8_t i;
    ssize_t bytes_read;

    bytes_read = read(self->timer_fd, &expiration_count, sizeof(expiration_count));
    (void)bytes_read;

    now_ns = Clock_MonotonicNs();
    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        QuicServerPeer *peer = &self->peers[i];

        if (!QuicConnection_IsOpen(&peer->connection)) {
            continue;
        }
        if (QuicConnection_NextExpiryNs(&peer->connection) > now_ns) {
            continue;
        }
        self->dispatching = true;
        self->dispatching_peer = peer;
        if (!QuicConnection_HandleExpiry(&peer->connection)) {
            self->dispatching = false;
            self->dispatching_peer = NULL;
            teardownPeer(self, peer, true);
            continue;
        }
        self->dispatching = false;
        self->dispatching_peer = NULL;

        if (peer->close_pending) {
            flushPeer(self, peer, NULL, 0);
            teardownPeer(self, peer, false);
            continue;
        }
        flushPeer(self, peer, NULL, 0);
        notifyWritable(self, peer);
    }

    retryStalledReliableStreams(self);
    rearmTimer(self);
}

/* ---------- private: hub transport port ---------- */

static bool portSendControl(void *context, uint32_t peer_id, const uint8_t *data, size_t size)
{
    QuicServerTransport *self = context;
    QuicServerPeer *peer = findPeerById(self, peer_id);

    if (peer == NULL || !peer->connected || peer->close_pending) {
        return false;
    }
    if (!QuicControlChannel_QueueTx(&peer->control, data, size)) {
        return false;
    }
    if (self->dispatching) {
        return true;
    }

    return flushPeer(self, peer, NULL, 0);
}

static bool portSendFrame(void *context, uint32_t peer_id, uint8_t channel, const uint8_t *data, size_t size)
{
    QuicServerTransport *self = context;
    QuicServerPeer *peer = findPeerById(self, peer_id);
    QuicReliableStream *reliable;

    if (peer == NULL || !peer->connected || peer->close_pending) {
        return false;
    }

    reliable = QuicReliableStreams_FindByChannel(&peer->reliable_streams, channel);
    if (reliable == NULL) {
        return flushPeer(self, peer, data, size);
    }
    if (!QuicControlChannel_QueueTx(&reliable->stream, data, size)) {
        return false;
    }
    if (self->dispatching && peer == self->dispatching_peer) {
        return true;
    }

    return flushPeer(self, peer, NULL, 0);
}

static void portSetChannelMode(void *context, uint32_t peer_id, uint8_t channel, bool reliable)
{
    QuicServerTransport *self = context;
    QuicServerPeer *peer = findPeerById(self, peer_id);

    if (peer == NULL || !peer->connected || !reliable) {
        return;
    }

    QuicReliableStreams_Open(&peer->reliable_streams, &peer->connection, channel);
}

static void portClosePeer(void *context, uint32_t peer_id)
{
    QuicServerTransport *self = context;
    QuicServerPeer *peer = findPeerById(self, peer_id);

    if (peer == NULL) {
        return;
    }
    if (self->dispatching) {
        peer->close_pending = true;
        return;
    }

    teardownPeer(self, peer, false);
}

/* ---------- private: peers ---------- */

static QuicServerPeer *findPeerById(QuicServerTransport *self, uint32_t peer_id)
{
    uint8_t i;

    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        if (QuicConnection_IsOpen(&self->peers[i].connection) && self->peers[i].peer_id == peer_id) {
            return &self->peers[i];
        }
    }

    return NULL;
}

static QuicServerPeer *findPeerByDcid(QuicServerTransport *self, const uint8_t *packet, size_t packet_size)
{
    ngtcp2_version_cid version_cid;
    ngtcp2_cid dcid;
    QuicServerPeer *peer;
    uint8_t i;

    if (ngtcp2_pkt_decode_version_cid(&version_cid, packet, packet_size, QUIC_CONNECTION_CID_LENGTH) != 0) {
        return NULL;
    }
    if (version_cid.dcidlen > NGTCP2_MAX_CIDLEN) {
        return NULL;
    }
    ngtcp2_cid_init(&dcid, version_cid.dcid, version_cid.dcidlen);

    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        peer = &self->peers[i];
        if (!QuicConnection_IsOpen(&peer->connection)) {
            continue;
        }
        if (ngtcp2_cid_eq(&peer->original_dcid, &dcid)) {
            return peer;
        }
        if (QuicConnection_HasLocalCid(&peer->connection, &dcid)) {
            return peer;
        }
    }

    return NULL;
}

static void refreshPeerAddress(
    QuicServerPeer *peer,
    const struct sockaddr_storage *address,
    socklen_t address_length
)
{
    memcpy(&peer->remote_address, address, address_length);
    peer->remote_address_length = address_length;
}

static QuicServerPeer *acceptPeer(
    QuicServerTransport *self,
    const struct sockaddr_storage *address,
    socklen_t address_length,
    const uint8_t *packet,
    size_t packet_size
)
{
    QuicConnectionEvents connection_events = {
        .on_handshake_completed = onHandshakeCompleted,
        .on_datagram = onDatagram,
        .on_stream_data = onStreamData,
        .on_stream_acked = onStreamAcked,
    };
    ngtcp2_pkt_hd initial_header;
    QuicServerPeer *peer = NULL;
    ngtcp2_path path;
    uint8_t i;

    if (ngtcp2_accept(&initial_header, packet, packet_size) != 0) {
        return NULL;
    }

    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        if (!QuicConnection_IsOpen(&self->peers[i].connection)) {
            peer = &self->peers[i];
            break;
        }
    }
    if (peer == NULL) {
        return NULL;
    }

    memset(peer, 0, sizeof(*peer));
    peer->transport = self;
    connection_events.context = peer;
    QuicConnection_Bind(&peer->connection, &connection_events);
    QuicControlChannel_Reset(&peer->control);
    peer->original_dcid = initial_header.dcid;
    memcpy(&peer->remote_address, address, address_length);
    peer->remote_address_length = address_length;
    peer->peer_id = self->next_peer_id++;

    if (!QuicServerSecurity_NewSession(&self->security, &peer->session, QuicConnection_Ref(&peer->connection))) {
        return NULL;
    }

    makePeerPath(self, peer, &path);
    if (!QuicConnection_OpenServer(&peer->connection, &peer->session.tls_context, &path, &initial_header)) {
        QuicServerSecurity_FreeSession(&peer->session);
        return NULL;
    }

    return peer;
}

static void makePeerPath(QuicServerTransport *self, QuicServerPeer *peer, ngtcp2_path *path)
{
    path->local.addr = (ngtcp2_sockaddr *)&self->local_address;
    path->local.addrlen = self->local_address_length;
    path->remote.addr = (ngtcp2_sockaddr *)&peer->remote_address;
    path->remote.addrlen = peer->remote_address_length;
    path->user_data = NULL;
}

/* ---------- private: egress ---------- */

static bool flushPeer(QuicServerTransport *self, QuicServerPeer *peer, const uint8_t *datagram, size_t datagram_size)
{
    QuicEgressSink sink = { peer, sendPacketToPeer };
    bool accepted = true;

    if (datagram != NULL) {
        if (!QuicEgress_FlushDatagram(&peer->connection, &sink, datagram, datagram_size, &accepted)) {
            teardownPeer(self, peer, true);
            return false;
        }
    }

    if (!QuicEgress_Drain(&peer->connection, &peer->control, &sink)) {
        teardownPeer(self, peer, true);
        return false;
    }

    if (!QuicReliableStreams_Drain(&peer->reliable_streams, &peer->connection, &sink)) {
        teardownPeer(self, peer, true);
        return false;
    }

    rearmTimer(self);

    return accepted;
}

static void retryStalledReliableStreams(QuicServerTransport *self)
{
    uint8_t i;

    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        if (QuicConnection_IsOpen(&self->peers[i].connection)) {
            QuicReliableStreams_RetryDrain(&self->peers[i].reliable_streams, &self->peers[i].connection, serverFrameSink, &self->peers[i]);
        }
    }
    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        if (QuicConnection_IsOpen(&self->peers[i].connection)) {
            flushPeer(self, &self->peers[i], NULL, 0);
        }
    }
}

static void notifyWritable(QuicServerTransport *self, QuicServerPeer *peer)
{
    if (self->events.on_peer_writable == NULL || !peer->connected || peer->close_pending) {
        return;
    }

    self->events.on_peer_writable(self->events.context, peer->peer_id);
}

static void sendPacketToPeer(void *context, const uint8_t *data, size_t size, size_t segment_size)
{
    QuicServerPeer *peer = context;

    sendToPeer(peer->transport, peer, data, size, segment_size);
}

static void sendToPeer(QuicServerTransport *self, QuicServerPeer *peer, const uint8_t *data, size_t size, size_t segment_size)
{
    QuicUdpGso_Send(
        self->udp_fd,
        (const struct sockaddr *)&peer->remote_address,
        peer->remote_address_length,
        data,
        size,
        segment_size,
        &self->gso_unsupported
    );
}

static void rearmTimer(QuicServerTransport *self)
{
    struct itimerspec timer_specification;
    uint64_t earliest_ns = UINT64_MAX;
    uint64_t expiry_ns;
    uint8_t i;

    for(i=0; i<QUIC_SERVER_PEERS_MAX; i++) {
        if (!QuicConnection_IsOpen(&self->peers[i].connection)) {
            continue;
        }
        expiry_ns = QuicConnection_NextExpiryNs(&self->peers[i].connection);
        if (expiry_ns < earliest_ns) {
            earliest_ns = expiry_ns;
        }
    }

    memset(&timer_specification, 0, sizeof(timer_specification));
    if (earliest_ns == UINT64_MAX) {
        timerfd_settime(self->timer_fd, 0, &timer_specification, NULL);
        return;
    }

    timer_specification.it_value.tv_sec = (time_t)(earliest_ns / NGTCP2_SECONDS);
    timer_specification.it_value.tv_nsec = (long)(earliest_ns % NGTCP2_SECONDS);
    timerfd_settime(self->timer_fd, TFD_TIMER_ABSTIME, &timer_specification, NULL);
}

static void teardownPeer(QuicServerTransport *self, QuicServerPeer *peer, bool notify)
{
    bool was_connected = peer->connected;
    uint32_t peer_id = peer->peer_id;

    QuicServerSecurity_FreeSession(&peer->session);
    QuicConnection_Close(&peer->connection);
    QuicControlChannel_Reset(&peer->control);
    QuicReliableStreams_Reset(&peer->reliable_streams);
    peer->connected = false;
    peer->close_pending = false;

    if (notify && was_connected) {
        self->events.on_peer_disconnected(self->events.context, peer_id, Clock_MonotonicUs());
    }
}

/* ---------- private: connection events ---------- */

static void capturePeerFingerprint(QuicServerPeer *peer)
{
    snprintf(
        peer->fingerprint_hex,
        TLS_IDENTITY_FINGERPRINT_HEX_SIZE,
        "%s",
        QuicConnection_PeerCertificate(&peer->connection)->fingerprint
    );
}

static void dispatchControlMessages(QuicServerTransport *self, QuicServerPeer *peer)
{
    const uint8_t *message;
    size_t message_size;

    for (;;) {
        message_size = QuicControlChannel_NextMessage(&peer->control, &message);
        if (message_size == 0) {
            return;
        }

        self->events.on_peer_control(
            self->events.context,
            peer->peer_id,
            message,
            message_size,
            Clock_MonotonicUs()
        );
        QuicControlChannel_ConsumeMessage(&peer->control, message_size);
    }
}

static void onHandshakeCompleted(void *context)
{
    QuicServerPeer *peer = context;
    HubPeerConnectInfo info;
    char origin[QUIC_SERVER_ORIGIN_SIZE];

    capturePeerFingerprint(peer);
    peer->connected = true;
    ListenEndpoint_FormatOrigin(&peer->remote_address, origin, sizeof(origin));
    info.fingerprint_hex = peer->fingerprint_hex[0] != '\0' ? peer->fingerprint_hex : NULL;
    info.origin = origin;
    info.transport_kind = kPEER_TRANSPORT_QUIC;
    info.local = false;
    peer->transport->events.on_peer_connected(
        peer->transport->events.context,
        peer->peer_id,
        &info,
        Clock_MonotonicUs()
    );
}

static void onDatagram(void *context, const uint8_t *data, size_t size)
{
    QuicServerPeer *peer = context;

    peer->transport->events.on_peer_frame(peer->transport->events.context, peer->peer_id, data, size);
}

static void onStreamData(void *context, int64_t stream_id, const uint8_t *data, size_t size)
{
    QuicServerPeer *peer = context;
    QuicReliableStream *reliable;

    if (peer->control.stream_id == QUIC_CONTROL_NO_STREAM) {
        peer->control.stream_id = stream_id;
    }
    if (stream_id == peer->control.stream_id) {
        receiveControlData(peer, data, size);
        QuicConnection_ExtendStreamCredit(&peer->connection, stream_id, size);
        return;
    }

    reliable = QuicReliableStreams_FindById(&peer->reliable_streams, stream_id);
    if (reliable == NULL) {
        reliable = QuicReliableStreams_Adopt(&peer->reliable_streams, stream_id);
    }
    if (reliable != NULL) {
        /* Receive extends credit only for relayed bytes; un-relayable bytes stay
         * framed and withhold credit, backpressuring the sender instead of dropping. */
        QuicReliableStreams_Receive(reliable, &peer->connection, data, size, serverFrameSink, peer);
        return;
    }
    QuicConnection_ExtendStreamCredit(&peer->connection, stream_id, size);
}

static void onStreamAcked(void *context, int64_t stream_id, uint64_t acked_end_offset)
{
    QuicServerPeer *peer = context;
    QuicReliableStream *reliable;

    if (stream_id == peer->control.stream_id) {
        QuicControlChannel_MarkAcked(&peer->control, acked_end_offset);
        return;
    }

    reliable = QuicReliableStreams_FindById(&peer->reliable_streams, stream_id);
    if (reliable != NULL) {
        QuicControlChannel_MarkAcked(&reliable->stream, acked_end_offset);
    }
}

static void receiveControlData(QuicServerPeer *peer, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    size_t taken;

    while (offset < size) {
        taken = QuicControlChannel_QueueRx(&peer->control, data + offset, size - offset);
        offset += taken;
        dispatchControlMessages(peer->transport, peer);
        if (taken == 0) {
            break;
        }
    }
}

static bool serverFrameSink(void *context, const uint8_t *frame, size_t size)
{
    QuicServerPeer *peer = context;

    return peer->transport->events.on_peer_frame(peer->transport->events.context, peer->peer_id, frame, size);
}

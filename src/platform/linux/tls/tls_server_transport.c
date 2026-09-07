#define _GNU_SOURCE

#include "platform/linux/tls/tls_server_transport.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "platform/linux/clock/clock.h"
#include "platform/linux/shared/listen_endpoint.h"
#include "platform/linux/shared/tls_identity.h"
#include "protocol/message_header.h"

#define TLS_SERVER_READ_CHUNK_SIZE 4096

#define LISTEN_BACKLOG 8

static bool portSendControl(void *context, uint32_t peer_id, const uint8_t *data, size_t size);
static bool portSendFrame(void *context, uint32_t peer_id, uint8_t channel, const uint8_t *data, size_t size);
static void portSetChannelMode(void *context, uint32_t peer_id, uint8_t channel, bool reliable);
static void portClosePeer(void *context, uint32_t peer_id);
static TlsServerPeer *findPeer(TlsServerTransport *self, uint32_t peer_id);
static TlsServerPeer *findFreeSlot(TlsServerTransport *self);
typedef struct {
    TlsServerTransport *transport;
    TlsServerPeer *peer;
} TlsServerDispatch;

static void pumpHandshake(TlsServerTransport *self, TlsServerPeer *peer);
static bool pumpCiphertextOut(TlsServerTransport *self, TlsServerPeer *peer);
static bool pumpCiphertextIn(TlsServerTransport *self, TlsServerPeer *peer);
static bool feedPeer(TlsServerTransport *self, TlsServerPeer *peer, const uint8_t *data, size_t size);
static void announcePeer(TlsServerTransport *self, TlsServerPeer *peer);
static void dispatchMessage(void *context, const uint8_t *message, size_t size);
static void closePeer(TlsServerTransport *self, TlsServerPeer *peer, bool notify);

/* ---------- public ---------- */

bool TlsServerTransport_Init(
    TlsServerTransport *self,
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
    int32_t reuse = 1;
    uint8_t slot;

    memset(self, 0, sizeof(*self));
    self->port.context = self;
    self->port.send_control = portSendControl;
    self->port.send_frame = portSendFrame;
    self->port.set_channel_mode = portSetChannelMode;
    self->port.close_peer = portClosePeer;
    self->events = *events;
    self->next_peer_id = peer_id_base;
    for(slot=0; slot<TLS_SERVER_PEERS_MAX; slot++) {
        TlsChannel_Reset(&self->peers[slot].channel);
        self->peers[slot].fd = TLS_CHANNEL_NO_SOCKET;
    }

    if (!TlsServerSecurity_Init(&self->security, certificate_file, key_file)) {
        return false;
    }

    self->listen_fd = ListenEndpoint_OpenSocket(SOCK_STREAM, &address_family);
    if (self->listen_fd < 0) {
        return false;
    }
    setsockopt(self->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (!ListenEndpoint_BuildSockaddr(address_family, bind_address, port, &address, &address_length)) {
        return false;
    }
    if (bind(self->listen_fd, (struct sockaddr *)&address, address_length) < 0) {
        return false;
    }

    return listen(self->listen_fd, LISTEN_BACKLOG) == 0;
}

HubTransportPort *TlsServerTransport_Port(TlsServerTransport *self)
{
    return &self->port;
}

int32_t TlsServerTransport_ListenFd(const TlsServerTransport *self)
{
    return self->listen_fd;
}

int32_t TlsServerTransport_SlotFd(const TlsServerTransport *self, uint8_t slot)
{
    return self->peers[slot].fd;
}

bool TlsServerTransport_SlotWantsWritable(const TlsServerTransport *self, uint8_t slot)
{
    if (!TlsChannel_IsBound(&self->peers[slot].channel)) {
        return false;
    }

    return TlsChannel_WantsWrite(&self->peers[slot].channel);
}

void TlsServerTransport_OnAcceptReady(TlsServerTransport *self)
{
    TlsServerPeer *peer;
    ptls_t *tls;
    struct sockaddr_storage remote;
    socklen_t remote_size = sizeof(remote);
    int32_t peer_fd;
    int32_t nodelay = 1;

    for (;;) {
        peer_fd = accept4(self->listen_fd, (struct sockaddr *)&remote, &remote_size, SOCK_NONBLOCK);
        if (peer_fd < 0) {
            return;
        }

        peer = findFreeSlot(self);
        if (peer == NULL) {
            close(peer_fd);
            continue;
        }
        if (!TlsServerSecurity_NewSession(&self->security, &tls)) {
            close(peer_fd);
            continue;
        }

        setsockopt(peer_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        TlsChannel_Bind(&peer->channel, tls, NULL);
        peer->fd = peer_fd;
        peer->peer_id = self->next_peer_id++;
        peer->announced = false;
        ListenEndpoint_FormatOrigin(&remote, peer->origin, sizeof(peer->origin));
        pumpHandshake(self, peer);
    }
}

void TlsServerTransport_OnSlotReadable(TlsServerTransport *self, uint8_t slot)
{
    TlsServerPeer *peer = &self->peers[slot];

    if (!TlsChannel_IsBound(&peer->channel)) {
        return;
    }

    if (!pumpCiphertextIn(self, peer)) {
        closePeer(self, peer, true);
        return;
    }
    if (!TlsChannel_IsBound(&peer->channel)) {
        return;
    }
    if (!pumpCiphertextOut(self, peer)) {
        closePeer(self, peer, true);
    }
}

void TlsServerTransport_OnSlotWritable(TlsServerTransport *self, uint8_t slot)
{
    TlsServerPeer *peer = &self->peers[slot];

    if (!TlsChannel_IsBound(&peer->channel)) {
        return;
    }

    if (!pumpCiphertextOut(self, peer)) {
        closePeer(self, peer, true);
        return;
    }

    if (!TlsChannel_IsEstablished(&peer->channel)) {
        return;
    }

    if (self->events.on_peer_writable != NULL) {
        self->events.on_peer_writable(self->events.context, peer->peer_id);
    }
}

/* ---------- private: hub transport port ---------- */

static bool portSendControl(void *context, uint32_t peer_id, const uint8_t *data, size_t size)
{
    TlsServerTransport *self = context;
    TlsServerPeer *peer = findPeer(self, peer_id);

    if (peer == NULL || !peer->announced) {
        return false;
    }
    if (!TlsChannel_Queue(&peer->channel, data, size)) {
        return false;
    }
    if (!TlsChannel_Flush(&peer->channel)) {
        closePeer(self, peer, true);
        return false;
    }

    return true;
}

static bool portSendFrame(void *context, uint32_t peer_id, uint8_t channel, const uint8_t *data, size_t size)
{
    TlsServerTransport *self = context;
    TlsServerPeer *peer = findPeer(self, peer_id);

    (void)channel;

    if (peer == NULL) {
        return false;
    }
    if (TlsChannel_FreeTxSpace(&peer->channel) < size) {
        return false;
    }

    return portSendControl(context, peer_id, data, size);
}

static void portSetChannelMode(void *context, uint32_t peer_id, uint8_t channel, bool reliable)
{
    (void)context;
    (void)peer_id;
    (void)channel;
    (void)reliable;
}

static void portClosePeer(void *context, uint32_t peer_id)
{
    TlsServerTransport *self = context;
    TlsServerPeer *peer = findPeer(self, peer_id);

    if (peer != NULL) {
        closePeer(self, peer, false);
    }
}

/* ---------- private ---------- */

static TlsServerPeer *findPeer(TlsServerTransport *self, uint32_t peer_id)
{
    uint8_t slot;

    for(slot=0; slot<TLS_SERVER_PEERS_MAX; slot++) {
        if (TlsChannel_IsBound(&self->peers[slot].channel) && self->peers[slot].peer_id == peer_id) {
            return &self->peers[slot];
        }
    }

    return NULL;
}

static TlsServerPeer *findFreeSlot(TlsServerTransport *self)
{
    uint8_t slot;

    for(slot=0; slot<TLS_SERVER_PEERS_MAX; slot++) {
        if (!TlsChannel_IsBound(&self->peers[slot].channel)) {
            return &self->peers[slot];
        }
    }

    return NULL;
}

static void pumpHandshake(TlsServerTransport *self, TlsServerPeer *peer)
{
    if (!TlsChannel_Pump(&peer->channel) || !pumpCiphertextOut(self, peer)) {
        closePeer(self, peer, false);
        return;
    }

    if (TlsChannel_IsEstablished(&peer->channel) && !peer->announced) {
        announcePeer(self, peer);
    }
}

static void announcePeer(TlsServerTransport *self, TlsServerPeer *peer)
{
    char fingerprint_hex[TLS_IDENTITY_FINGERPRINT_HEX_SIZE];
    bool has_fingerprint = TlsChannel_PeerFingerprint(&peer->channel, fingerprint_hex);
    HubPeerConnectInfo info;

    peer->announced = true;
    info.fingerprint_hex = has_fingerprint ? fingerprint_hex : NULL;
    info.origin = peer->origin;
    info.transport_kind = kPEER_TRANSPORT_TLS;
    info.local = false;
    self->events.on_peer_connected(self->events.context, peer->peer_id, &info, Clock_MonotonicUs());
}

static bool pumpCiphertextOut(TlsServerTransport *self, TlsServerPeer *peer)
{
    ssize_t bytes_sent;

    (void)self;

    while (TlsChannel_PendingCiphertext(&peer->channel) > 0) {
        bytes_sent = send(
            peer->fd,
            TlsChannel_Ciphertext(&peer->channel),
            TlsChannel_PendingCiphertext(&peer->channel),
            MSG_NOSIGNAL
        );
        if (bytes_sent > 0) {
            TlsChannel_ConsumeCiphertext(&peer->channel, (size_t)bytes_sent);
            continue;
        }
        if (bytes_sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }

        return false;
    }

    return true;
}

static bool pumpCiphertextIn(TlsServerTransport *self, TlsServerPeer *peer)
{
    uint8_t chunk[TLS_SERVER_READ_CHUNK_SIZE];
    ssize_t bytes_received;

    for (;;) {
        bytes_received = recv(peer->fd, chunk, sizeof(chunk), 0);
        if (bytes_received > 0) {
            if (!feedPeer(self, peer, chunk, (size_t)bytes_received)) {
                return false;
            }
            if (!TlsChannel_IsBound(&peer->channel)) {
                return true;
            }
            continue;
        }
        if (bytes_received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }

        return false;
    }
}

static bool feedPeer(TlsServerTransport *self, TlsServerPeer *peer, const uint8_t *data, size_t size)
{
    TlsServerDispatch dispatch = { self, peer };
    MessageSink sink = { &dispatch, dispatchMessage };
    size_t offset = 0;
    size_t consumed;

    while (offset < size) {
        if (!TlsChannel_PushCiphertext(&peer->channel, data + offset, size - offset, &consumed, &sink)) {
            return false;
        }
        offset += consumed;
        if (TlsChannel_IsEstablished(&peer->channel) && !peer->announced) {
            announcePeer(self, peer);
        }
        if (!TlsChannel_IsBound(&peer->channel)) {
            return true;
        }
        if (consumed == 0) {
            return true;
        }
    }

    return true;
}

static void dispatchMessage(void *context, const uint8_t *message, size_t size)
{
    TlsServerDispatch *dispatch = context;
    TlsServerTransport *self = dispatch->transport;
    TlsServerPeer *peer = dispatch->peer;
    MessageHeader header;

    MessageHeader_Decode(&header, message, size);
    if (header.type == kMESSAGE_TYPE_FRAME) {
        self->events.on_peer_frame(self->events.context, peer->peer_id, message, size);
    } else {
        self->events.on_peer_control(
            self->events.context,
            peer->peer_id,
            message,
            size,
            Clock_MonotonicUs()
        );
    }
}

static void closePeer(TlsServerTransport *self, TlsServerPeer *peer, bool notify)
{
    uint32_t peer_id = peer->peer_id;
    bool was_announced = peer->announced;
    int32_t peer_fd = peer->fd;

    TlsChannel_Close(&peer->channel);
    close(peer_fd);
    peer->fd = TLS_CHANNEL_NO_SOCKET;
    peer->announced = false;

    if (notify && was_announced) {
        self->events.on_peer_disconnected(self->events.context, peer_id, Clock_MonotonicUs());
    }
}

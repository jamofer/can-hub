#include "platform/linux/tls/tls_client_transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "platform/linux/clock/clock.h"
#include "protocol/message_header.h"

#define TLS_CLIENT_READ_CHUNK_SIZE 4096

static bool portConnect(void *context);
static void portDisconnect(void *context);
static bool portSendControl(void *context, const uint8_t *data, size_t size);
static bool portSendFrame(void *context, uint8_t channel, const uint8_t *data, size_t size);
static void portSetChannelMode(void *context, uint8_t channel, bool reliable);
static bool connectTcp(TlsClientTransport *self, int32_t *connected_fd);
static void pumpHandshake(TlsClientTransport *self);
static void announceWhenEstablished(TlsClientTransport *self);
static bool pumpCiphertextOut(TlsClientTransport *self);
static bool pumpCiphertextIn(TlsClientTransport *self);
static bool feedChannel(TlsClientTransport *self, const uint8_t *data, size_t size);
static void dispatchMessage(void *context, const uint8_t *message, size_t size);
static void closeConnection(TlsClientTransport *self, bool notify);

/* ---------- public ---------- */

bool TlsClientTransport_Init(
    TlsClientTransport *self,
    const char *host,
    const char *port,
    const TransportEvents *events,
    const TlsClientSecurityConfig *security_config
)
{
    memset(self, 0, sizeof(*self));
    self->port.context = self;
    self->port.connect = portConnect;
    self->port.disconnect = portDisconnect;
    self->port.send_control = portSendControl;
    self->port.send_frame = portSendFrame;
    self->port.set_channel_mode = portSetChannelMode;
    self->events = *events;
    snprintf(self->host, TLS_CLIENT_HOST_MAX, "%s", host);
    snprintf(self->port_text, TLS_CLIENT_PORT_TEXT_MAX, "%s", port);
    TlsChannel_Reset(&self->channel);
    self->fd = TLS_CHANNEL_NO_SOCKET;

    return TlsClientSecurity_Init(&self->security, security_config);
}

TransportPort *TlsClientTransport_Port(TlsClientTransport *self)
{
    return &self->port;
}

int32_t TlsClientTransport_Fd(const TlsClientTransport *self)
{
    return self->fd;
}

bool TlsClientTransport_WantsWritable(const TlsClientTransport *self)
{
    if (!TlsChannel_IsBound(&self->channel)) {
        return false;
    }

    return self->connecting || TlsChannel_WantsWrite(&self->channel);
}

void TlsClientTransport_OnReadable(TlsClientTransport *self)
{
    if (!TlsChannel_IsBound(&self->channel)) {
        return;
    }

    if (!pumpCiphertextIn(self)) {
        closeConnection(self, true);
        return;
    }
    if (!TlsChannel_IsBound(&self->channel)) {
        return;
    }
    if (!pumpCiphertextOut(self)) {
        closeConnection(self, true);
        return;
    }
    announceWhenEstablished(self);
}

void TlsClientTransport_OnWritable(TlsClientTransport *self)
{
    int32_t socket_error = 0;
    socklen_t error_length = sizeof(socket_error);

    if (!TlsChannel_IsBound(&self->channel)) {
        return;
    }

    if (self->connecting) {
        getsockopt(self->fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length);
        if (socket_error != 0) {
            closeConnection(self, true);
            return;
        }

        self->connecting = false;
        pumpHandshake(self);
        return;
    }

    if (!pumpCiphertextOut(self)) {
        closeConnection(self, true);
        return;
    }
    announceWhenEstablished(self);
}

/* ---------- private: transport port ---------- */

static bool portConnect(void *context)
{
    TlsClientTransport *self = context;
    ptls_t *tls;
    int32_t connected_fd;

    if (TlsChannel_IsBound(&self->channel)) {
        return true;
    }

    if (!connectTcp(self, &connected_fd)) {
        return false;
    }
    if (!TlsClientSecurity_NewSession(&self->security, self->host, &tls)) {
        close(connected_fd);
        return false;
    }

    TlsChannel_Bind(&self->channel, tls, TlsClientSecurity_HandshakeProperties(&self->security));
    self->fd = connected_fd;
    self->connecting = true;
    self->announced = false;

    return true;
}

static void portDisconnect(void *context)
{
    TlsClientTransport *self = context;

    closeConnection(self, false);
}

static bool portSendControl(void *context, const uint8_t *data, size_t size)
{
    TlsClientTransport *self = context;

    if (!self->announced) {
        return false;
    }
    if (!TlsChannel_Queue(&self->channel, data, size)) {
        return false;
    }
    if (!TlsChannel_Flush(&self->channel) || !pumpCiphertextOut(self)) {
        closeConnection(self, true);
        return false;
    }

    return true;
}

static bool portSendFrame(void *context, uint8_t channel, const uint8_t *data, size_t size)
{
    TlsClientTransport *self = context;

    (void)channel;

    if (!self->announced) {
        return false;
    }
    if (TlsChannel_FreeTxSpace(&self->channel) < size) {
        return false;
    }

    return portSendControl(context, data, size);
}

static void portSetChannelMode(void *context, uint8_t channel, bool reliable)
{
    (void)context;
    (void)channel;
    (void)reliable;
}

/* ---------- private ---------- */

static bool connectTcp(TlsClientTransport *self, int32_t *connected_fd)
{
    struct addrinfo hints;
    struct addrinfo *resolved;
    struct addrinfo *candidate;
    int32_t tcp_fd;
    int32_t connect_result;
    int32_t nodelay = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(self->host, self->port_text, &hints, &resolved) != 0) {
        return false;
    }

    tcp_fd = -1;
    for(candidate=resolved; candidate!=NULL; candidate=candidate->ai_next) {
        tcp_fd = socket(candidate->ai_family, candidate->ai_socktype | SOCK_NONBLOCK, 0);
        if (tcp_fd < 0) {
            continue;
        }
        setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        connect_result = connect(tcp_fd, candidate->ai_addr, candidate->ai_addrlen);
        if (connect_result == 0 || errno == EINPROGRESS) {
            break;
        }
        close(tcp_fd);
        tcp_fd = -1;
    }
    freeaddrinfo(resolved);
    if (tcp_fd < 0) {
        return false;
    }

    *connected_fd = tcp_fd;

    return true;
}

static void pumpHandshake(TlsClientTransport *self)
{
    if (!TlsChannel_Pump(&self->channel) || !pumpCiphertextOut(self)) {
        closeConnection(self, true);
        return;
    }

    announceWhenEstablished(self);
}

static void announceWhenEstablished(TlsClientTransport *self)
{
    if (!TlsChannel_IsEstablished(&self->channel) || self->announced) {
        return;
    }

    self->announced = true;
    self->events.on_connected(self->events.context);
}

static bool pumpCiphertextOut(TlsClientTransport *self)
{
    ssize_t bytes_sent;

    while (TlsChannel_PendingCiphertext(&self->channel) > 0) {
        bytes_sent = send(
            self->fd,
            TlsChannel_Ciphertext(&self->channel),
            TlsChannel_PendingCiphertext(&self->channel),
            MSG_NOSIGNAL
        );
        if (bytes_sent > 0) {
            TlsChannel_ConsumeCiphertext(&self->channel, (size_t)bytes_sent);
            continue;
        }
        if (bytes_sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }

        return false;
    }

    return true;
}

static bool pumpCiphertextIn(TlsClientTransport *self)
{
    uint8_t chunk[TLS_CLIENT_READ_CHUNK_SIZE];
    ssize_t bytes_received;

    for (;;) {
        bytes_received = recv(self->fd, chunk, sizeof(chunk), 0);
        if (bytes_received > 0) {
            if (!feedChannel(self, chunk, (size_t)bytes_received)) {
                return false;
            }
            if (!TlsChannel_IsBound(&self->channel)) {
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

static bool feedChannel(TlsClientTransport *self, const uint8_t *data, size_t size)
{
    MessageSink sink = { self, dispatchMessage };
    size_t offset = 0;
    size_t consumed;

    while (offset < size) {
        if (!TlsChannel_PushCiphertext(&self->channel, data + offset, size - offset, &consumed, &sink)) {
            return false;
        }
        offset += consumed;
        announceWhenEstablished(self);
        if (!TlsChannel_IsBound(&self->channel)) {
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
    TlsClientTransport *self = context;
    MessageHeader header;

    MessageHeader_Decode(&header, message, size);
    if (header.type == kMESSAGE_TYPE_FRAME) {
        self->events.on_frame(self->events.context, message, size);
    } else {
        self->events.on_control(self->events.context, message, size, Clock_MonotonicUs());
    }
}

static void closeConnection(TlsClientTransport *self, bool notify)
{
    int32_t connection_fd;

    if (!TlsChannel_IsBound(&self->channel)) {
        return;
    }

    connection_fd = self->fd;
    TlsChannel_Close(&self->channel);
    close(connection_fd);
    self->fd = TLS_CHANNEL_NO_SOCKET;
    self->connecting = false;
    self->announced = false;

    if (notify) {
        self->events.on_disconnected(self->events.context, Clock_MonotonicUs());
    }
}

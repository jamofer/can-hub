#include "platform/linux/quic/quic_client_transport.h"

#include <stdio.h>
#include <string.h>

#include "platform/linux/clock/clock.h"
#include "platform/linux/quic/quic_egress.h"

#define UDP_PACKET_BUFFER_SIZE 1452

static bool portConnect(void *context);
static void portDisconnect(void *context);
static bool portSendControl(void *context, const uint8_t *data, size_t size);
static bool portSendFrame(void *context, uint8_t channel, const uint8_t *data, size_t size);
static void portSetChannelMode(void *context, uint8_t channel, bool reliable);
static void teardown(QuicClientTransport *self, bool notify);
static bool flushEgress(QuicClientTransport *self);
static void sendPacket(void *context, const uint8_t *data, size_t size, size_t segment_size);
static void rearmTimer(QuicClientTransport *self);
static void dispatchControlMessages(QuicClientTransport *self);
static void receiveControlData(QuicClientTransport *self, const uint8_t *data, size_t size);
static bool clientFrameSink(void *context, const uint8_t *frame, size_t size);
static void onHandshakeCompleted(void *context);
static void onDatagram(void *context, const uint8_t *data, size_t size);
static void onStreamData(void *context, int64_t stream_id, const uint8_t *data, size_t size);
static void onStreamAcked(void *context, int64_t stream_id, uint64_t acked_end_offset);

/* ---------- public ---------- */

bool QuicClientTransport_Init(
    QuicClientTransport *self,
    const char *host,
    const char *port,
    const TransportEvents *events,
    const QuicClientSecurityConfig *security_config
)
{
    QuicConnectionEvents connection_events = {
        .context = self,
        .on_handshake_completed = onHandshakeCompleted,
        .on_datagram = onDatagram,
        .on_stream_data = onStreamData,
        .on_stream_acked = onStreamAcked,
    };

    memset(self, 0, sizeof(*self));
    self->port.context = self;
    self->port.connect = portConnect;
    self->port.disconnect = portDisconnect;
    self->port.send_control = portSendControl;
    self->port.send_frame = portSendFrame;
    self->port.set_channel_mode = portSetChannelMode;
    self->events = *events;
    if (security_config != NULL) {
        self->security_config = *security_config;
    }
    QuicConnection_Bind(&self->connection, &connection_events);
    QuicControlChannel_Reset(&self->control);
    QuicDatagramBacklog_Reset(&self->egress_backlog);
    snprintf(self->server.host, QUIC_HOST_MAX, "%s", host);
    snprintf(self->server.port_text, QUIC_PORT_TEXT_MAX, "%s", port);

    return QuicUdpEndpoint_Open(&self->udp);
}

TransportPort *QuicClientTransport_Port(QuicClientTransport *self)
{
    return &self->port;
}

int32_t QuicClientTransport_UdpFd(const QuicClientTransport *self)
{
    return self->udp.udp_fd;
}

int32_t QuicClientTransport_TimerFd(const QuicClientTransport *self)
{
    return self->udp.timer_fd;
}

void QuicClientTransport_OnUdpReadable(QuicClientTransport *self)
{
    uint8_t buffer[UDP_PACKET_BUFFER_SIZE];
    ngtcp2_path path;
    ssize_t bytes_received;

    if (!QuicConnection_IsOpen(&self->connection)) {
        return;
    }

    for (;;) {
        bytes_received = QuicUdpEndpoint_Receive(&self->udp, buffer, sizeof(buffer));
        if (bytes_received <= 0) {
            break;
        }

        QuicUdpEndpoint_MakePath(&self->udp, &path);
        self->dispatching = true;
        if (!QuicConnection_ReadPacket(&self->connection, &path, buffer, (size_t)bytes_received)) {
            self->dispatching = false;
            teardown(self, true);
            return;
        }
        self->dispatching = false;

        if (self->disconnect_pending) {
            flushEgress(self);
            teardown(self, false);
            return;
        }
    }

    flushEgress(self);
}

void QuicClientTransport_OnTimer(QuicClientTransport *self)
{
    QuicUdpEndpoint_ClearTimerEvent(&self->udp);
    if (!QuicConnection_IsOpen(&self->connection)) {
        return;
    }

    self->dispatching = true;
    if (!QuicConnection_HandleExpiry(&self->connection)) {
        self->dispatching = false;
        teardown(self, true);
        return;
    }
    self->dispatching = false;

    if (self->disconnect_pending) {
        flushEgress(self);
        teardown(self, false);
        return;
    }

    flushEgress(self);
}

/* ---------- private: transport port ---------- */

static bool portConnect(void *context)
{
    QuicClientTransport *self = context;
    ngtcp2_path path;

    if (QuicConnection_IsOpen(&self->connection)) {
        return true;
    }
    if (!QuicUdpEndpoint_ConnectTo(&self->udp, self->server.host, self->server.port_text)) {
        return false;
    }
    if (!QuicClientSecurity_Init(&self->security, self->server.host, QuicConnection_Ref(&self->connection), &self->security_config)) {
        return false;
    }

    QuicUdpEndpoint_MakePath(&self->udp, &path);
    if (!QuicConnection_Open(&self->connection, &self->security.tls_context, &path)) {
        QuicClientSecurity_Free(&self->security);
        return false;
    }
    if (!QuicClientSecurity_AttachConnection(&self->security, QuicConnection_Handle(&self->connection))) {
        QuicConnection_Close(&self->connection);
        QuicClientSecurity_Free(&self->security);
        return false;
    }

    return flushEgress(self);
}

static void portDisconnect(void *context)
{
    QuicClientTransport *self = context;
    uint8_t packet[UDP_PACKET_BUFFER_SIZE];
    ngtcp2_ssize written;

    if (self->dispatching) {
        self->disconnect_pending = true;
        return;
    }

    if (self->connected && QuicConnection_IsOpen(&self->connection)) {
        written = QuicConnection_WriteConnectionClose(&self->connection, packet, sizeof(packet));
        if (written > 0) {
            QuicUdpEndpoint_Send(&self->udp, packet, (size_t)written);
        }
    }

    teardown(self, false);
}

static bool portSendControl(void *context, const uint8_t *data, size_t size)
{
    QuicClientTransport *self = context;

    if (!self->connected || self->disconnect_pending) {
        return false;
    }
    if (!QuicControlChannel_QueueTx(&self->control, data, size)) {
        return false;
    }
    if (self->dispatching) {
        return true;
    }

    return flushEgress(self);
}

static bool portSendFrame(void *context, uint8_t channel, const uint8_t *data, size_t size)
{
    QuicClientTransport *self = context;
    QuicReliableStream *reliable;

    if (!self->connected) {
        return false;
    }

    reliable = QuicReliableStreams_FindByChannel(&self->reliable_streams, channel);
    if (reliable != NULL) {
        if (!QuicControlChannel_QueueTx(&reliable->stream, data, size)) {
            return false;
        }
    } else {
        QuicDatagramBacklog_Push(&self->egress_backlog, data, size);
    }

    if (!self->dispatching) {
        flushEgress(self);
    }

    return true;
}

static void portSetChannelMode(void *context, uint8_t channel, bool reliable)
{
    QuicClientTransport *self = context;

    if (!self->connected || !reliable) {
        return;
    }

    QuicReliableStreams_Open(&self->reliable_streams, &self->connection, channel);
}

/* ---------- private: lifecycle ---------- */

static void teardown(QuicClientTransport *self, bool notify)
{
    if (!QuicConnection_IsOpen(&self->connection)) {
        return;
    }

    QuicClientSecurity_Free(&self->security);
    QuicConnection_Close(&self->connection);
    QuicControlChannel_Reset(&self->control);
    QuicReliableStreams_Reset(&self->reliable_streams);
    QuicDatagramBacklog_Reset(&self->egress_backlog);
    QuicUdpEndpoint_DisarmTimer(&self->udp);
    QuicUdpEndpoint_ReopenSocket(&self->udp);
    self->connected = false;
    self->disconnect_pending = false;

    if (notify) {
        self->events.on_disconnected(self->events.context, Clock_MonotonicUs());
    }
}

/* ---------- private: egress pump ---------- */

static bool flushEgress(QuicClientTransport *self)
{
    QuicEgressSink sink = { self, sendPacket };
    const uint8_t *front;
    size_t front_size;
    bool datagram_accepted;

    if (!QuicConnection_IsOpen(&self->connection)) {
        return false;
    }

    while (!QuicDatagramBacklog_IsEmpty(&self->egress_backlog)) {
        front = QuicDatagramBacklog_Front(&self->egress_backlog, &front_size);
        datagram_accepted = true;
        if (!QuicEgress_FlushDatagram(&self->connection, &sink, front, front_size, &datagram_accepted)) {
            teardown(self, true);
            return false;
        }
        if (!datagram_accepted) {
            break;
        }
        QuicDatagramBacklog_PopFront(&self->egress_backlog);
    }

    if (!QuicEgress_Drain(&self->connection, &self->control, &sink)) {
        teardown(self, true);
        return false;
    }

    if (!QuicReliableStreams_Drain(&self->reliable_streams, &self->connection, &sink)) {
        teardown(self, true);
        return false;
    }

    rearmTimer(self);

    return true;
}

static void sendPacket(void *context, const uint8_t *data, size_t size, size_t segment_size)
{
    QuicClientTransport *self = context;

    QuicUdpEndpoint_SendSegmented(&self->udp, data, size, segment_size);
}

static void rearmTimer(QuicClientTransport *self)
{
    uint64_t expiry_ns = QuicConnection_NextExpiryNs(&self->connection);

    if (expiry_ns == UINT64_MAX) {
        QuicUdpEndpoint_DisarmTimer(&self->udp);
        return;
    }

    QuicUdpEndpoint_ArmTimerAt(&self->udp, expiry_ns);
}

/* ---------- private: connection events ---------- */

static void dispatchControlMessages(QuicClientTransport *self)
{
    const uint8_t *message;
    size_t message_size;

    for (;;) {
        message_size = QuicControlChannel_NextMessage(&self->control, &message);
        if (message_size == 0) {
            return;
        }

        self->events.on_control(self->events.context, message, message_size, Clock_MonotonicUs());
        QuicControlChannel_ConsumeMessage(&self->control, message_size);
    }
}

static void onHandshakeCompleted(void *context)
{
    QuicClientTransport *self = context;

    if (!QuicConnection_OpenControlStream(&self->connection, &self->control.stream_id)) {
        return;
    }

    self->connected = true;
    self->events.on_connected(self->events.context);
}

static void onDatagram(void *context, const uint8_t *data, size_t size)
{
    QuicClientTransport *self = context;

    self->events.on_frame(self->events.context, data, size);
}

static void onStreamData(void *context, int64_t stream_id, const uint8_t *data, size_t size)
{
    QuicClientTransport *self = context;
    QuicReliableStream *reliable;

    if (stream_id == self->control.stream_id) {
        receiveControlData(self, data, size);
        QuicConnection_ExtendStreamCredit(&self->connection, stream_id, size);
        return;
    }

    reliable = QuicReliableStreams_FindById(&self->reliable_streams, stream_id);
    if (reliable == NULL) {
        reliable = QuicReliableStreams_Adopt(&self->reliable_streams, stream_id);
    }
    if (reliable != NULL) {
        QuicReliableStreams_Receive(reliable, &self->connection, data, size, clientFrameSink, self);
        return;
    }
    QuicConnection_ExtendStreamCredit(&self->connection, stream_id, size);
}

static void receiveControlData(QuicClientTransport *self, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    size_t taken;

    while (offset < size) {
        taken = QuicControlChannel_QueueRx(&self->control, data + offset, size - offset);
        offset += taken;
        dispatchControlMessages(self);
        if (taken == 0) {
            break;
        }
    }
}

static void onStreamAcked(void *context, int64_t stream_id, uint64_t acked_end_offset)
{
    QuicClientTransport *self = context;
    QuicReliableStream *reliable;

    if (stream_id == self->control.stream_id) {
        QuicControlChannel_MarkAcked(&self->control, acked_end_offset);
        return;
    }

    reliable = QuicReliableStreams_FindById(&self->reliable_streams, stream_id);
    if (reliable != NULL) {
        QuicControlChannel_MarkAcked(&reliable->stream, acked_end_offset);
    }
}

static bool clientFrameSink(void *context, const uint8_t *frame, size_t size)
{
    QuicClientTransport *self = context;

    self->events.on_frame(self->events.context, frame, size);

    return true;
}

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include "platform/linux/shared/tls_peer_certificate.h"

/*
 * Thin wrapper around one ngtcp2 connection (client or server side): owns
 * the ngtcp2_conn, registers the callback table and forwards the
 * interesting events. No I/O, no buffering — packets in, packets out.
 */

#define QUIC_CONNECTION_CID_LENGTH 16

typedef struct {
    void *context;
    void (*on_handshake_completed)(void *context);
    void (*on_datagram)(void *context, const uint8_t *data, size_t size);
    void (*on_stream_data)(void *context, int64_t stream_id, const uint8_t *data, size_t size);
    void (*on_stream_acked)(void *context, int64_t stream_id, uint64_t acked_end_offset);
} QuicConnectionEvents;

typedef struct {
    ngtcp2_conn *connection;
    ngtcp2_crypto_conn_ref connection_ref;
    TlsPeerCertificate peer;
    QuicConnectionEvents events;
    uint64_t next_datagram_id;
} QuicConnection;

void QuicConnection_Bind(QuicConnection *self, const QuicConnectionEvents *events);
ngtcp2_crypto_conn_ref *QuicConnection_Ref(QuicConnection *self);
ngtcp2_conn *QuicConnection_Handle(QuicConnection *self);
TlsPeerCertificate *QuicConnection_PeerCertificate(QuicConnection *self);
TlsPeerCertificate *QuicConnection_PeerCertificateOfSession(ptls_t *tls);
bool QuicConnection_Open(QuicConnection *self, ngtcp2_crypto_picotls_ctx *tls_context, const ngtcp2_path *path);
bool QuicConnection_OpenServer(
    QuicConnection *self,
    ngtcp2_crypto_picotls_ctx *tls_context,
    const ngtcp2_path *path,
    const ngtcp2_pkt_hd *initial_header
);
void QuicConnection_Close(QuicConnection *self);
bool QuicConnection_IsOpen(const QuicConnection *self);
bool QuicConnection_HasLocalCid(const QuicConnection *self, const ngtcp2_cid *cid);
bool QuicConnection_ReadPacket(QuicConnection *self, const ngtcp2_path *path, const uint8_t *data, size_t size);
bool QuicConnection_HandleExpiry(QuicConnection *self);
uint64_t QuicConnection_NextExpiryNs(const QuicConnection *self);
bool QuicConnection_OpenControlStream(QuicConnection *self, int64_t *stream_id);
void QuicConnection_ExtendStreamCredit(QuicConnection *self, int64_t stream_id, size_t size);
ngtcp2_ssize QuicConnection_WriteDatagram(
    QuicConnection *self,
    uint8_t *packet_buffer,
    size_t packet_buffer_size,
    const uint8_t *payload,
    size_t payload_size,
    bool *accepted
);
ngtcp2_ssize QuicConnection_WriteStream(
    QuicConnection *self,
    uint8_t *packet_buffer,
    size_t packet_buffer_size,
    int64_t stream_id,
    const uint8_t *data,
    size_t data_size,
    size_t *consumed
);
ngtcp2_ssize QuicConnection_WritePacket(QuicConnection *self, uint8_t *packet_buffer, size_t packet_buffer_size);
ngtcp2_ssize QuicConnection_WriteConnectionClose(QuicConnection *self, uint8_t *packet_buffer, size_t packet_buffer_size);

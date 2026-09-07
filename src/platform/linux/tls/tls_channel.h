#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <picotls.h>

#include "platform/linux/shared/message_framer.h"
#include "platform/linux/shared/tls_peer_certificate.h"

#define TLS_CHANNEL_TX_BACKLOG_SIZE 8192
#define TLS_CHANNEL_CIPHERTEXT_SIZE 16384
#define TLS_CHANNEL_CIPHERTEXT_HIGH_WATER 8192
#define TLS_CHANNEL_NO_SOCKET (-1)

/*
 * One TLS-protected stream of protocol messages. The channel owns no socket
 * and makes no syscall: ciphertext is pushed in and taken out, plaintext is
 * queued in and drained to the framer, and the transport that owns the fd
 * moves the bytes. picotls works the same way, which is what lets this stay
 * one file across platforms and be testable without a network.
 */
typedef enum ttls_channel_state_e {
    kTLS_CHANNEL_STATE_UNBOUND = 0,
    kTLS_CHANNEL_STATE_HANDSHAKING,
    kTLS_CHANNEL_STATE_ESTABLISHED,
    kTLS_CHANNEL_STATE_MAX,
} TTLS_CHANNEL_STATE;

typedef struct {
    ptls_t *tls;
    TlsPeerCertificate peer;
    ptls_handshake_properties_t handshake_properties;
    uint8_t state;
    MessageFramer framer;
    uint8_t tx_backlog[TLS_CHANNEL_TX_BACKLOG_SIZE];
    size_t tx_used;
    ptls_buffer_t ciphertext;
    uint8_t ciphertext_storage[TLS_CHANNEL_CIPHERTEXT_SIZE];
} TlsChannel;

void TlsChannel_Reset(TlsChannel *self);
bool TlsChannel_Bind(TlsChannel *self, ptls_t *tls, const ptls_handshake_properties_t *properties);
void TlsChannel_Close(TlsChannel *self);
bool TlsChannel_IsBound(const TlsChannel *self);
bool TlsChannel_IsEstablished(const TlsChannel *self);
bool TlsChannel_Pump(TlsChannel *self);
bool TlsChannel_PushCiphertext(
    TlsChannel *self,
    const uint8_t *data,
    size_t size,
    size_t *consumed,
    const MessageSink *sink
);
size_t TlsChannel_PendingCiphertext(const TlsChannel *self);
const uint8_t *TlsChannel_Ciphertext(const TlsChannel *self);
void TlsChannel_ConsumeCiphertext(TlsChannel *self, size_t size);
size_t TlsChannel_FreeTxSpace(const TlsChannel *self);
bool TlsChannel_Queue(TlsChannel *self, const uint8_t *data, size_t size);
bool TlsChannel_Flush(TlsChannel *self);
bool TlsChannel_WantsWrite(const TlsChannel *self);
bool TlsChannel_PeerFingerprint(const TlsChannel *self, char *fingerprint_hex);

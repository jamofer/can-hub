#include "platform/linux/tls/tls_channel.h"

#include <string.h>

#define PLAINTEXT_CHUNK_SIZE 4096

static bool advanceHandshake(TlsChannel *self, const uint8_t *data, size_t *size);
static bool decryptAndFrame(
    TlsChannel *self,
    const uint8_t *data,
    size_t size,
    size_t *consumed,
    const MessageSink *sink
);
static bool drainPlaintext(TlsChannel *self, const uint8_t *plaintext, size_t size, const MessageSink *sink);

/* ---------- public ---------- */

void TlsChannel_Reset(TlsChannel *self)
{
    memset(self, 0, sizeof(*self));
    MessageFramer_Reset(&self->framer);
    TlsPeerCertificate_Reset(&self->peer);
    ptls_buffer_init(&self->ciphertext, self->ciphertext_storage, sizeof(self->ciphertext_storage));
}

bool TlsChannel_Bind(TlsChannel *self, ptls_t *tls, const ptls_handshake_properties_t *properties)
{
    TlsChannel_Reset(self);
    self->tls = tls;
    self->state = kTLS_CHANNEL_STATE_HANDSHAKING;
    if (properties != NULL) {
        self->handshake_properties = *properties;
    }
    *ptls_get_data_ptr(tls) = &self->peer;

    return true;
}

void TlsChannel_Close(TlsChannel *self)
{
    if (self->tls != NULL) {
        ptls_free(self->tls);
    }
    ptls_buffer_dispose(&self->ciphertext);

    TlsChannel_Reset(self);
}

bool TlsChannel_IsBound(const TlsChannel *self)
{
    return self->tls != NULL;
}

bool TlsChannel_IsEstablished(const TlsChannel *self)
{
    return self->state == kTLS_CHANNEL_STATE_ESTABLISHED;
}

bool TlsChannel_Pump(TlsChannel *self)
{
    if (self->state != kTLS_CHANNEL_STATE_HANDSHAKING || ptls_is_server(self->tls)) {
        return true;
    }

    return advanceHandshake(self, NULL, NULL);
}

bool TlsChannel_PushCiphertext(
    TlsChannel *self,
    const uint8_t *data,
    size_t size,
    size_t *consumed,
    const MessageSink *sink
)
{
    *consumed = size;

    if (self->state == kTLS_CHANNEL_STATE_HANDSHAKING) {
        return advanceHandshake(self, data, consumed);
    }

    return decryptAndFrame(self, data, size, consumed, sink);
}

size_t TlsChannel_PendingCiphertext(const TlsChannel *self)
{
    return self->ciphertext.off;
}

const uint8_t *TlsChannel_Ciphertext(const TlsChannel *self)
{
    return self->ciphertext.base;
}

void TlsChannel_ConsumeCiphertext(TlsChannel *self, size_t size)
{
    if (size >= self->ciphertext.off) {
        self->ciphertext.off = 0;
        return;
    }

    memmove(self->ciphertext.base, self->ciphertext.base + size, self->ciphertext.off - size);
    self->ciphertext.off -= size;
}

size_t TlsChannel_FreeTxSpace(const TlsChannel *self)
{
    if (self->ciphertext.off >= TLS_CHANNEL_CIPHERTEXT_HIGH_WATER) {
        return 0;
    }

    return TLS_CHANNEL_TX_BACKLOG_SIZE - self->tx_used;
}

bool TlsChannel_Queue(TlsChannel *self, const uint8_t *data, size_t size)
{
    if (self->tx_used + size > TLS_CHANNEL_TX_BACKLOG_SIZE) {
        return false;
    }

    memcpy(self->tx_backlog + self->tx_used, data, size);
    self->tx_used += size;

    return true;
}

/*
 * Encrypting is what moves bytes from the plaintext backlog into the pending
 * ciphertext, so it is also where backpressure has to stop: past the high
 * water mark the plaintext stays queued and FreeTxSpace reports nothing free,
 * which is the signal the hub pages its egress against.
 */
bool TlsChannel_Flush(TlsChannel *self)
{
    if (self->state != kTLS_CHANNEL_STATE_ESTABLISHED || self->tx_used == 0) {
        return true;
    }
    if (self->ciphertext.off >= TLS_CHANNEL_CIPHERTEXT_HIGH_WATER) {
        return true;
    }

    if (ptls_send(self->tls, &self->ciphertext, self->tx_backlog, self->tx_used) != 0) {
        return false;
    }
    self->tx_used = 0;

    return true;
}

bool TlsChannel_WantsWrite(const TlsChannel *self)
{
    return self->ciphertext.off > 0 || self->tx_used > 0;
}

bool TlsChannel_PeerFingerprint(const TlsChannel *self, char *fingerprint_hex)
{
    if (!self->peer.loaded) {
        return false;
    }
    memcpy(fingerprint_hex, self->peer.fingerprint, TLS_IDENTITY_FINGERPRINT_HEX_SIZE);

    return true;
}

/* ---------- private ---------- */

static bool advanceHandshake(TlsChannel *self, const uint8_t *data, size_t *size)
{
    int result;

    result = ptls_handshake(self->tls, &self->ciphertext, data, size, &self->handshake_properties);
    if (result == 0) {
        self->state = kTLS_CHANNEL_STATE_ESTABLISHED;
        return true;
    }

    return result == PTLS_ERROR_IN_PROGRESS;
}

static bool decryptAndFrame(
    TlsChannel *self,
    const uint8_t *data,
    size_t size,
    size_t *consumed,
    const MessageSink *sink
)
{
    uint8_t storage[PLAINTEXT_CHUNK_SIZE];
    ptls_buffer_t plaintext;
    size_t offset = 0;
    size_t taken;
    bool drained = true;

    ptls_buffer_init(&plaintext, storage, sizeof(storage));

    while (offset < size) {
        taken = size - offset;
        if (ptls_receive(self->tls, &plaintext, data + offset, &taken) != 0) {
            ptls_buffer_dispose(&plaintext);
            *consumed = offset;
            return false;
        }
        offset += taken;
        if (taken == 0) {
            break;
        }
    }
    *consumed = offset;

    if (plaintext.off > 0) {
        drained = drainPlaintext(self, plaintext.base, plaintext.off, sink);
    }
    ptls_buffer_dispose(&plaintext);

    return drained;
}

static bool drainPlaintext(TlsChannel *self, const uint8_t *plaintext, size_t size, const MessageSink *sink)
{
    size_t offset = 0;
    size_t taken;

    while (offset < size) {
        taken = MessageFramer_Push(&self->framer, plaintext + offset, size - offset);
        offset += taken;
        MessageFramer_Drain(&self->framer, sink);
        if (!TlsChannel_IsBound(self)) {
            return true;
        }
        if (taken == 0) {
            return false;
        }
    }

    return true;
}

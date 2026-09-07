#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <picotls.h>

#include "platform/linux/shared/tls_identity.h"

/*
 * Peer certificate state for the picotls verify_certificate callbacks,
 * shared by the client pin check and the server accept-any path. picotls
 * hands the chain over as raw DER, which is exactly what the fingerprint is
 * taken over, so no X.509 object is ever built for it. One of these lives
 * per session and doubles as the verify_sign context.
 *
 * Sessions are reached differently per transport: TLS-over-TCP owns the
 * picotls data pointer, while QUIC must leave it to ngtcp2, which stores
 * its connection reference there. A resolver supplied at attach time is
 * what keeps one pair of callbacks serving both.
 */

typedef struct {
    uint8_t public_key[TLS_IDENTITY_PUBLIC_KEY_SIZE];
    char fingerprint[TLS_IDENTITY_FINGERPRINT_HEX_SIZE];
    bool loaded;
} TlsPeerCertificate;

typedef TlsPeerCertificate *(*TlsPeerResolver)(ptls_t *tls);

void TlsPeerCertificate_Reset(TlsPeerCertificate *self);
bool TlsPeerCertificate_Accept(TlsPeerCertificate *self, ptls_iovec_t *certificates, size_t count);
TlsPeerCertificate *TlsPeerCertificate_FromDataPointer(ptls_t *tls);
int32_t TlsPeerCertificate_VerifySignature(
    void *verify_context,
    uint16_t algorithm,
    ptls_iovec_t data,
    ptls_iovec_t signature
);

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <picotls.h>

#include "platform/linux/shared/tls_identity.h"

/*
 * ED25519 for picotls, over Monocypher. This is the whole crypto surface the
 * project owns: signing our own CertificateVerify, verifying the peer's, and
 * reading the two DER shapes involved — the PKCS#8 private key and the
 * SubjectPublicKeyInfo inside a certificate. No signing key or signature ever
 * reaches a general-purpose TLS library.
 */

#define TLS_ED25519_SECRET_KEY_SIZE 64
#define TLS_ED25519_SEED_SIZE 32
#define TLS_ED25519_SIGNATURE_SIZE 64

typedef struct {
    ptls_sign_certificate_t super;
    uint8_t secret_key[TLS_ED25519_SECRET_KEY_SIZE];
    bool loaded;
} TlsEd25519Signer;

bool TlsEd25519_AttachSigner(TlsEd25519Signer *self, ptls_context_t *context, const char *key_path);
bool TlsEd25519_PublicKeyOfCertificate(const uint8_t *certificate_der, size_t size, uint8_t *public_key);
bool TlsEd25519_Verify(
    const uint8_t *public_key,
    const uint8_t *message,
    size_t size,
    const uint8_t *signature
);

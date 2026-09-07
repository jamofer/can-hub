#include "platform/linux/shared/tls_peer_certificate.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#define ED25519_SIGNATURE_SIZE 64

static bool rawPublicKeyOfCertificate(ptls_iovec_t certificate, uint8_t *public_key);
static bool verifyEd25519(
    const uint8_t *public_key,
    ptls_iovec_t data,
    ptls_iovec_t signature
);

/* ---------- public ---------- */

void TlsPeerCertificate_Reset(TlsPeerCertificate *self)
{
    memset(self, 0, sizeof(*self));
}

bool TlsPeerCertificate_Accept(TlsPeerCertificate *self, ptls_iovec_t *certificates, size_t count)
{
    TlsPeerCertificate_Reset(self);

    if (certificates == NULL || count == 0 || certificates[0].base == NULL) {
        return false;
    }
    if (!TlsIdentity_FingerprintOfDer(certificates[0].base, certificates[0].len, self->fingerprint)) {
        return false;
    }
    if (!rawPublicKeyOfCertificate(certificates[0], self->public_key)) {
        return false;
    }
    self->loaded = true;

    return true;
}

TlsPeerCertificate *TlsPeerCertificate_FromDataPointer(ptls_t *tls)
{
    return *ptls_get_data_ptr(tls);
}

int32_t TlsPeerCertificate_VerifySignature(
    void *verify_context,
    uint16_t algorithm,
    ptls_iovec_t data,
    ptls_iovec_t signature
)
{
    TlsPeerCertificate *self = verify_context;

    if (data.base == NULL) {
        return 0;
    }
    if (!self->loaded) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if (algorithm != PTLS_SIGNATURE_ED25519) {
        return PTLS_ALERT_ILLEGAL_PARAMETER;
    }
    if (signature.len != ED25519_SIGNATURE_SIZE) {
        return PTLS_ALERT_DECRYPT_ERROR;
    }
    if (!verifyEd25519(self->public_key, data, signature)) {
        return PTLS_ALERT_DECRYPT_ERROR;
    }

    return 0;
}

/* ---------- private ---------- */

static bool rawPublicKeyOfCertificate(ptls_iovec_t certificate, uint8_t *public_key)
{
    const uint8_t *pointer = certificate.base;
    X509 *parsed;
    EVP_PKEY *key;
    size_t key_size = TLS_IDENTITY_PUBLIC_KEY_SIZE;
    bool extracted = false;

    parsed = d2i_X509(NULL, &pointer, (long)certificate.len);
    if (parsed == NULL) {
        return false;
    }

    key = X509_get0_pubkey(parsed);
    if (key != NULL && EVP_PKEY_get_raw_public_key(key, public_key, &key_size) == 1) {
        extracted = key_size == TLS_IDENTITY_PUBLIC_KEY_SIZE;
    }
    X509_free(parsed);

    return extracted;
}

static bool verifyEd25519(
    const uint8_t *public_key,
    ptls_iovec_t data,
    ptls_iovec_t signature
)
{
    EVP_PKEY *key;
    EVP_MD_CTX *context;
    bool verified = false;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, TLS_IDENTITY_PUBLIC_KEY_SIZE);
    if (key == NULL) {
        return false;
    }

    context = EVP_MD_CTX_new();
    if (context != NULL) {
        if (EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1) {
            verified = EVP_DigestVerify(context, signature.base, signature.len, data.base, data.len) == 1;
        }
        EVP_MD_CTX_free(context);
    }
    EVP_PKEY_free(key);

    return verified;
}

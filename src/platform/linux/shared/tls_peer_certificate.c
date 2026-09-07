#include "platform/linux/shared/tls_peer_certificate.h"

#include <string.h>

#include "platform/linux/shared/tls_ed25519.h"

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
    if (!TlsEd25519_PublicKeyOfCertificate(certificates[0].base, certificates[0].len, self->public_key)) {
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
    if (signature.len != TLS_ED25519_SIGNATURE_SIZE) {
        return PTLS_ALERT_DECRYPT_ERROR;
    }
    if (!TlsEd25519_Verify(self->public_key, data.base, data.len, signature.base)) {
        return PTLS_ALERT_DECRYPT_ERROR;
    }

    return 0;
}

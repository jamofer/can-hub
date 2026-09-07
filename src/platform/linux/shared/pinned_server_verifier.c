#include "platform/linux/shared/pinned_server_verifier.h"

#include <stdio.h>
#include <string.h>

#include "platform/linux/shared/tls_peer_certificate.h"

static const uint16_t verifiable_signature_algorithms[] = { PTLS_SIGNATURE_ED25519, UINT16_MAX };

static void attachVerifier(PinnedServerVerifier *self, ptls_context_t *context, TlsPeerResolver resolve_peer);
static int verifyPinnedServer(
    ptls_verify_certificate_t *verifier,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_context, uint16_t algorithm, ptls_iovec_t data, ptls_iovec_t signature),
    void **verify_data,
    ptls_iovec_t *certificates,
    size_t count
);
static bool fingerprintIsPinned(PinnedServerVerifier *self, const char *fingerprint);

/* ---------- public ---------- */

void PinnedServerVerifier_Attach(
    PinnedServerVerifier *self,
    ptls_context_t *context,
    TlsPeerResolver resolve_peer,
    const char *pin_store_path,
    const char *pin_key
)
{
    memset(self, 0, sizeof(*self));
    snprintf(self->pin_store_path, sizeof(self->pin_store_path), "%s", pin_store_path);
    snprintf(self->pin_key, sizeof(self->pin_key), "%s", pin_key);
    attachVerifier(self, context, resolve_peer);
}

void PinnedServerVerifier_AttachFixed(
    PinnedServerVerifier *self,
    ptls_context_t *context,
    TlsPeerResolver resolve_peer,
    const char *expected_fingerprint
)
{
    memset(self, 0, sizeof(*self));
    snprintf(self->expected_fingerprint, sizeof(self->expected_fingerprint), "%s", expected_fingerprint);
    attachVerifier(self, context, resolve_peer);
}

/* ---------- private ---------- */

static void attachVerifier(PinnedServerVerifier *self, ptls_context_t *context, TlsPeerResolver resolve_peer)
{
    self->resolve_peer = resolve_peer;
    self->super.cb = verifyPinnedServer;
    self->super.algos = verifiable_signature_algorithms;
    context->verify_certificate = &self->super;
}

static int verifyPinnedServer(
    ptls_verify_certificate_t *verifier,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_context, uint16_t algorithm, ptls_iovec_t data, ptls_iovec_t signature),
    void **verify_data,
    ptls_iovec_t *certificates,
    size_t count
)
{
    PinnedServerVerifier *self = (PinnedServerVerifier *)verifier;
    TlsPeerCertificate *peer = self->resolve_peer(tls);

    (void)server_name;

    if (peer == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    if (!TlsPeerCertificate_Accept(peer, certificates, count)) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if (!fingerprintIsPinned(self, peer->fingerprint)) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    *verify_sign = TlsPeerCertificate_VerifySignature;
    *verify_data = peer;

    return 0;
}

static bool fingerprintIsPinned(PinnedServerVerifier *self, const char *fingerprint)
{
    char pinned[PIN_STORE_FINGERPRINT_HEX_SIZE];

    if (self->expected_fingerprint[0] != '\0') {
        if (strcmp(self->expected_fingerprint, fingerprint) != 0) {
            fprintf(stderr, "hub fingerprint %s does not match the expected one, rejecting connection\n", fingerprint);
            return false;
        }
        return true;
    }

    if (!PinStore_Lookup(self->pin_store_path, self->pin_key, pinned)) {
        fprintf(stderr, "pinning hub %s fingerprint %s\n", self->pin_key, fingerprint);
        return PinStore_Append(self->pin_store_path, self->pin_key, fingerprint);
    }
    if (strcmp(pinned, fingerprint) != 0) {
        fprintf(stderr, "hub %s fingerprint changed, rejecting connection\n", self->pin_key);
        return false;
    }

    return true;
}

#include "platform/linux/shared/tls_defaults.h"

#include <picotls/minicrypto.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "platform/linux/shared/tls_aead.h"
#include "platform/linux/shared/tls_peer_certificate.h"

#define ALPN_PROTOCOL "canhub/0"

static const ptls_iovec_t alpn_protocols[] = {
    { (uint8_t *)ALPN_PROTOCOL, sizeof(ALPN_PROTOCOL) - 1 },
};
static const uint16_t verifiable_signature_algorithms[] = { PTLS_SIGNATURE_ED25519, UINT16_MAX };

static void initCommonProfile(TlsProfile *self);
static int acceptAnyClientCertificate(
    ptls_verify_certificate_t *verifier,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_context, uint16_t algorithm, ptls_iovec_t data, ptls_iovec_t signature),
    void **verify_data,
    ptls_iovec_t *certificates,
    size_t count
);
static int selectAlpnProtocol(ptls_on_client_hello_t *selector, ptls_t *tls, ptls_on_client_hello_parameters_t *parameters);

/* ---------- public ---------- */

bool TlsDefaults_InitClientProfile(TlsProfile *self)
{
    initCommonProfile(self);

    return true;
}

bool TlsDefaults_InitServerProfile(TlsProfile *self, TlsPeerResolver resolve_peer)
{
    initCommonProfile(self);

    self->resolve_peer = resolve_peer;

    self->client_certificate_acceptor.cb = acceptAnyClientCertificate;
    self->client_certificate_acceptor.algos = verifiable_signature_algorithms;
    self->alpn_selector.cb = selectAlpnProtocol;
    self->context.verify_certificate = &self->client_certificate_acceptor;
    self->context.on_client_hello = &self->alpn_selector;
    self->context.require_client_authentication = 1;

    return true;
}

bool TlsDefaults_LoadIdentity(TlsProfile *self, const char *certificate_path, const char *key_path)
{
    if (ptls_load_certificates(&self->context, certificate_path) != 0) {
        return false;
    }
    if (!TlsEd25519_AttachSigner(&self->signer, &self->context, key_path)) {
        return false;
    }
    self->has_signer = true;

    return true;
}

void TlsDefaults_FreeProfile(TlsProfile *self)
{
    size_t i;

    self->has_signer = false;
    for(i=0; i<self->context.certificates.count; i++) {
        free(self->context.certificates.list[i].base);
    }
    free(self->context.certificates.list);
    self->context.certificates.list = NULL;
    self->context.certificates.count = 0;
}

void TlsDefaults_ConfigureClientHandshake(ptls_handshake_properties_t *properties)
{
    memset(properties, 0, sizeof(*properties));
    properties->client.negotiated_protocols.list = (ptls_iovec_t *)alpn_protocols;
    properties->client.negotiated_protocols.count = 1;
}

/* ---------- private ---------- */

static void initCommonProfile(TlsProfile *self)
{
    memset(self, 0, sizeof(*self));
    self->context.random_bytes = ptls_minicrypto_random_bytes;
    self->context.get_time = &ptls_get_time;
    self->context.key_exchanges = ptls_minicrypto_key_exchanges;
    self->context.cipher_suites = TlsAead_CipherSuites();
}

static int acceptAnyClientCertificate(
    ptls_verify_certificate_t *verifier,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_context, uint16_t algorithm, ptls_iovec_t data, ptls_iovec_t signature),
    void **verify_data,
    ptls_iovec_t *certificates,
    size_t count
)
{
    TlsProfile *profile = (TlsProfile *)((uint8_t *)verifier - offsetof(TlsProfile, client_certificate_acceptor));
    TlsPeerCertificate *peer = profile->resolve_peer(tls);

    (void)server_name;

    if (peer == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    if (!TlsPeerCertificate_Accept(peer, certificates, count)) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    *verify_sign = TlsPeerCertificate_VerifySignature;
    *verify_data = peer;

    return 0;
}

static int selectAlpnProtocol(ptls_on_client_hello_t *selector, ptls_t *tls, ptls_on_client_hello_parameters_t *parameters)
{
    size_t i;

    (void)selector;

    for(i=0; i<parameters->negotiated_protocols.count; i++) {
        if (parameters->negotiated_protocols.list[i].len == alpn_protocols[0].len
            && memcmp(parameters->negotiated_protocols.list[i].base, alpn_protocols[0].base, alpn_protocols[0].len) == 0) {
            return ptls_set_negotiated_protocol(tls, ALPN_PROTOCOL, alpn_protocols[0].len);
        }
    }

    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

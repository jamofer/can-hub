#include "platform/linux/tls/tls_client_security.h"

#include <string.h>

static bool loadClientIdentity(TlsClientSecurity *self, const TlsClientSecurityConfig *config);

/* ---------- public ---------- */

bool TlsClientSecurity_Init(TlsClientSecurity *self, const TlsClientSecurityConfig *config)
{
    memset(self, 0, sizeof(*self));

    if (!TlsDefaults_InitClientProfile(&self->profile, kTLS_TRANSPORT_STREAM)) {
        return false;
    }
    if (!loadClientIdentity(self, config)) {
        TlsClientSecurity_Free(self);
        return false;
    }

    if (config != NULL && config->pinned_fingerprint != NULL) {
        PinnedServerVerifier_AttachFixed(
            &self->verifier,
            &self->profile.context,
            TlsPeerCertificate_FromDataPointer,
            config->pinned_fingerprint
        );
    } else if (config != NULL && config->pin_store_path != NULL && config->pin_key != NULL) {
        PinnedServerVerifier_Attach(
            &self->verifier,
            &self->profile.context,
            TlsPeerCertificate_FromDataPointer,
            config->pin_store_path,
            config->pin_key
        );
    }
    TlsDefaults_ConfigureClientHandshake(&self->handshake_properties);

    return true;
}

void TlsClientSecurity_Free(TlsClientSecurity *self)
{
    TlsDefaults_FreeProfile(&self->profile);
}

bool TlsClientSecurity_NewSession(TlsClientSecurity *self, const char *server_host, ptls_t **tls)
{
    *tls = ptls_new(&self->profile.context, 0);
    if (*tls == NULL) {
        return false;
    }
    if (server_host != NULL && ptls_set_server_name(*tls, server_host, 0) != 0) {
        ptls_free(*tls);
        *tls = NULL;
        return false;
    }

    return true;
}

const ptls_handshake_properties_t *TlsClientSecurity_HandshakeProperties(const TlsClientSecurity *self)
{
    return &self->handshake_properties;
}

/* ---------- private ---------- */

static bool loadClientIdentity(TlsClientSecurity *self, const TlsClientSecurityConfig *config)
{
    if (config == NULL || config->certificate_path == NULL || config->key_path == NULL) {
        return true;
    }

    return TlsDefaults_LoadIdentity(&self->profile, config->certificate_path, config->key_path);
}

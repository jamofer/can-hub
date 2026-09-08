#include "platform/linux/quic/quic_client_security.h"

#include <string.h>

#include "platform/linux/quic/quic_connection.h"

static bool loadClientIdentity(QuicClientSecurity *self, const QuicClientSecurityConfig *config);
static void attachVerifier(QuicClientSecurity *self, const QuicClientSecurityConfig *config);

/* ---------- public ---------- */

bool QuicClientSecurity_Init(
    QuicClientSecurity *self,
    const char *server_host,
    ngtcp2_crypto_conn_ref *connection_ref,
    const QuicClientSecurityConfig *config
)
{
    memset(self, 0, sizeof(*self));

    if (!TlsDefaults_InitClientProfile(&self->profile, kTLS_TRANSPORT_QUIC)) {
        return false;
    }
    if (ngtcp2_crypto_picotls_configure_client_context(&self->profile.context) != 0) {
        QuicClientSecurity_Free(self);
        return false;
    }
    if (!loadClientIdentity(self, config)) {
        QuicClientSecurity_Free(self);
        return false;
    }
    attachVerifier(self, config);

    ngtcp2_crypto_picotls_ctx_init(&self->tls_context);
    self->tls_context.ptls = ptls_new(&self->profile.context, 0);
    if (self->tls_context.ptls == NULL) {
        QuicClientSecurity_Free(self);
        return false;
    }

    *ptls_get_data_ptr(self->tls_context.ptls) = connection_ref;
    TlsDefaults_ConfigureClientHandshake(&self->tls_context.handshake_properties);
    if (server_host != NULL && ptls_set_server_name(self->tls_context.ptls, server_host, 0) != 0) {
        QuicClientSecurity_Free(self);
        return false;
    }

    return true;
}

bool QuicClientSecurity_AttachConnection(QuicClientSecurity *self, ngtcp2_conn *connection)
{
    self->extensions[0].type = UINT16_MAX;
    self->extensions[1].type = UINT16_MAX;
    self->tls_context.handshake_properties.additional_extensions = self->extensions;

    return ngtcp2_crypto_picotls_configure_client_session(&self->tls_context, connection) == 0;
}

void QuicClientSecurity_Free(QuicClientSecurity *self)
{
    if (self->tls_context.ptls != NULL) {
        ngtcp2_crypto_picotls_deconfigure_session(&self->tls_context);
        ptls_free(self->tls_context.ptls);
        self->tls_context.ptls = NULL;
    }
    TlsDefaults_FreeProfile(&self->profile);
}

/* ---------- private ---------- */

static bool loadClientIdentity(QuicClientSecurity *self, const QuicClientSecurityConfig *config)
{
    if (config == NULL || config->certificate_path == NULL || config->key_path == NULL) {
        return true;
    }

    return TlsDefaults_LoadIdentity(&self->profile, config->certificate_path, config->key_path);
}

static void attachVerifier(QuicClientSecurity *self, const QuicClientSecurityConfig *config)
{
    if (config == NULL) {
        return;
    }

    if (config->pinned_fingerprint != NULL) {
        PinnedServerVerifier_AttachFixed(
            &self->verifier,
            &self->profile.context,
            QuicConnection_PeerCertificateOfSession,
            config->pinned_fingerprint
        );
        return;
    }
    if (config->pin_store_path != NULL && config->pin_key != NULL) {
        PinnedServerVerifier_Attach(
            &self->verifier,
            &self->profile.context,
            QuicConnection_PeerCertificateOfSession,
            config->pin_store_path,
            config->pin_key
        );
    }
}

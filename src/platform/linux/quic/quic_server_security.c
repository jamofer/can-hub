#include "platform/linux/quic/quic_server_security.h"

#include <string.h>

#include "platform/linux/quic/quic_connection.h"

/* ---------- public ---------- */

bool QuicServerSecurity_Init(QuicServerSecurity *self, const char *certificate_file, const char *key_file)
{
    memset(self, 0, sizeof(*self));

    if (!TlsDefaults_InitServerProfile(&self->profile, QuicConnection_PeerCertificateOfSession)) {
        return false;
    }
    if (ngtcp2_crypto_picotls_configure_server_context(&self->profile.context) != 0) {
        QuicServerSecurity_Free(self);
        return false;
    }
    if (!TlsDefaults_LoadIdentity(&self->profile, certificate_file, key_file)) {
        QuicServerSecurity_Free(self);
        return false;
    }

    return true;
}

void QuicServerSecurity_Free(QuicServerSecurity *self)
{
    TlsDefaults_FreeProfile(&self->profile);
}

bool QuicServerSecurity_NewSession(
    QuicServerSecurity *self,
    QuicServerSession *session,
    ngtcp2_crypto_conn_ref *connection_ref
)
{
    memset(session, 0, sizeof(*session));
    ngtcp2_crypto_picotls_ctx_init(&session->tls_context);

    session->tls_context.ptls = ptls_new(&self->profile.context, 1);
    if (session->tls_context.ptls == NULL) {
        return false;
    }

    *ptls_get_data_ptr(session->tls_context.ptls) = connection_ref;
    session->extensions[0].type = UINT16_MAX;
    session->extensions[1].type = UINT16_MAX;
    session->tls_context.handshake_properties.additional_extensions = session->extensions;

    if (ngtcp2_crypto_picotls_configure_server_session(&session->tls_context) != 0) {
        QuicServerSecurity_FreeSession(session);
        return false;
    }

    return true;
}

void QuicServerSecurity_FreeSession(QuicServerSession *session)
{
    if (session->tls_context.ptls == NULL) {
        return;
    }

    ngtcp2_crypto_picotls_deconfigure_session(&session->tls_context);
    ptls_free(session->tls_context.ptls);
    session->tls_context.ptls = NULL;
}

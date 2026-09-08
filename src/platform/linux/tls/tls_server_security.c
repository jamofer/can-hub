#include "platform/linux/tls/tls_server_security.h"

#include <string.h>

/* ---------- public ---------- */

bool TlsServerSecurity_Init(TlsServerSecurity *self, const char *certificate_file, const char *key_file)
{
    memset(self, 0, sizeof(*self));

    if (!TlsDefaults_InitServerProfile(&self->profile, kTLS_TRANSPORT_STREAM, TlsPeerCertificate_FromDataPointer)) {
        return false;
    }
    if (!TlsDefaults_LoadIdentity(&self->profile, certificate_file, key_file)) {
        TlsServerSecurity_Free(self);
        return false;
    }

    return true;
}

void TlsServerSecurity_Free(TlsServerSecurity *self)
{
    TlsDefaults_FreeProfile(&self->profile);
}

bool TlsServerSecurity_NewSession(TlsServerSecurity *self, ptls_t **tls)
{
    *tls = ptls_new(&self->profile.context, 1);

    return *tls != NULL;
}

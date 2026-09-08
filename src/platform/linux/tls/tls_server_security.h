#pragma once

#include <stdbool.h>

#include <picotls.h>

#include "platform/linux/shared/tls_defaults.h"

/*
 * Server-side TLS material: the picotls context carrying the can-hub
 * profile, the hub identity and the accept-any client certificate policy.
 * Client identity is pinned at the application layer from the fingerprint
 * the channel records during the handshake.
 */

typedef struct {
    TlsProfile profile;
} TlsServerSecurity;

bool TlsServerSecurity_Init(TlsServerSecurity *self, const char *certificate_file, const char *key_file);
void TlsServerSecurity_Free(TlsServerSecurity *self);
bool TlsServerSecurity_NewSession(TlsServerSecurity *self, ptls_t **tls);

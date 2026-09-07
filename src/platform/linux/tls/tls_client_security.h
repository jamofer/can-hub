#pragma once

#include <stdbool.h>

#include <picotls.h>

#include "platform/linux/shared/pinned_server_verifier.h"
#include "platform/linux/shared/tls_defaults.h"

/*
 * Client-side TLS material for one transport: the picotls context carrying
 * the can-hub profile and, when configured, the client identity presented
 * for mTLS plus the TOFU verifier applied to the hub certificate. Sessions
 * are minted from it per connection attempt.
 */

typedef struct {
    const char *certificate_path;
    const char *key_path;
    const char *pin_store_path;
    const char *pin_key;
    const char *pinned_fingerprint;
} TlsClientSecurityConfig;

typedef struct {
    TlsProfile profile;
    PinnedServerVerifier verifier;
    ptls_handshake_properties_t handshake_properties;
} TlsClientSecurity;

bool TlsClientSecurity_Init(TlsClientSecurity *self, const TlsClientSecurityConfig *config);
void TlsClientSecurity_Free(TlsClientSecurity *self);
bool TlsClientSecurity_NewSession(TlsClientSecurity *self, const char *server_host, ptls_t **tls);
const ptls_handshake_properties_t *TlsClientSecurity_HandshakeProperties(const TlsClientSecurity *self);

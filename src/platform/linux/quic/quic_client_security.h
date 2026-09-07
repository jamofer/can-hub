#pragma once

#include <stdbool.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls.h>

#include "platform/linux/shared/pinned_server_verifier.h"
#include "platform/linux/shared/tls_defaults.h"

/*
 * TLS side of a QUIC client connection: a picotls session wired to ngtcp2
 * through the crypto-picotls backend. Presents the agent identity
 * certificate (mTLS) and verifies the server against the TOFU pin store
 * through PinnedServerVerifier. The session is configured in two steps
 * because ngtcp2 needs the ngtcp2_conn, which only exists once the
 * connection has been opened with this context as its native handle.
 */

#define QUIC_CLIENT_SECURITY_EXTENSIONS 2

typedef struct {
    const char *certificate_path;
    const char *key_path;
    const char *pin_store_path;
    const char *pin_key;
    const char *pinned_fingerprint;
} QuicClientSecurityConfig;

typedef struct {
    TlsProfile profile;
    PinnedServerVerifier verifier;
    ngtcp2_crypto_picotls_ctx tls_context;
    ptls_raw_extension_t extensions[QUIC_CLIENT_SECURITY_EXTENSIONS];
} QuicClientSecurity;

bool QuicClientSecurity_Init(
    QuicClientSecurity *self,
    const char *server_host,
    ngtcp2_crypto_conn_ref *connection_ref,
    const QuicClientSecurityConfig *config
);
bool QuicClientSecurity_AttachConnection(QuicClientSecurity *self, ngtcp2_conn *connection);
void QuicClientSecurity_Free(QuicClientSecurity *self);

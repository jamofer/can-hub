#pragma once

#include <stdbool.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <picotls.h>

#include "platform/linux/shared/tls_defaults.h"

/*
 * TLS side of the QUIC server: one picotls context carrying the hub
 * identity, a client certificate required from every peer and accepted
 * without a CA, and a per-connection session handed to ngtcp2 as its
 * native handle. The client fingerprint is pinned at the application layer
 * from what the session records during the handshake.
 */

#define QUIC_SERVER_SESSION_EXTENSIONS 2

typedef struct {
    ngtcp2_crypto_picotls_ctx tls_context;
    ptls_raw_extension_t extensions[QUIC_SERVER_SESSION_EXTENSIONS];
} QuicServerSession;

typedef struct {
    TlsProfile profile;
} QuicServerSecurity;

bool QuicServerSecurity_Init(QuicServerSecurity *self, const char *certificate_file, const char *key_file);
void QuicServerSecurity_Free(QuicServerSecurity *self);
bool QuicServerSecurity_NewSession(
    QuicServerSecurity *self,
    QuicServerSession *session,
    ngtcp2_crypto_conn_ref *connection_ref
);
void QuicServerSecurity_FreeSession(QuicServerSession *session);

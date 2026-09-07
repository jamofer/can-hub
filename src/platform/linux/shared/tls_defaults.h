#pragma once

#include <stdbool.h>

#include <picotls.h>
#include "platform/linux/shared/tls_ed25519.h"
#include "platform/linux/shared/tls_peer_certificate.h"

/*
 * The TLS profile every can-hub transport speaks: TLS 1.3 only, ALPN
 * canhub/0, an ED25519 identity. Certificate verification stays with the
 * caller: clients attach the TOFU verifier, servers accept any client
 * certificate and pin its fingerprint at the application layer. One profile
 * owns the picotls context and outlives every session created from it.
 */

#define TLS_PROFILE_CERTIFICATE_MAX 4

typedef struct {
    ptls_context_t context;
    TlsPeerResolver resolve_peer;
    TlsEd25519Signer signer;
    ptls_verify_certificate_t client_certificate_acceptor;
    ptls_on_client_hello_t alpn_selector;
    bool has_signer;
} TlsProfile;

bool TlsDefaults_InitClientProfile(TlsProfile *self);
bool TlsDefaults_InitServerProfile(TlsProfile *self, TlsPeerResolver resolve_peer);
bool TlsDefaults_LoadIdentity(TlsProfile *self, const char *certificate_path, const char *key_path);
void TlsDefaults_FreeProfile(TlsProfile *self);
void TlsDefaults_ConfigureClientHandshake(ptls_handshake_properties_t *properties);

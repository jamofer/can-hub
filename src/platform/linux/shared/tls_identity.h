#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Self-signed TLS identity for zero-config TOFU: an ED25519 keypair and
 * certificate generated on first start and reused afterwards. The state
 * directory defaults to /var/lib/can-hub with a per-user fallback when it
 * is not writable. Fingerprints are taken over the DER certificate, so
 * nothing here needs a TLS session or an X.509 object.
 */

#define TLS_IDENTITY_PATH_MAX 512
#define TLS_IDENTITY_FINGERPRINT_HEX_SIZE 65
#define TLS_IDENTITY_PUBLIC_KEY_SIZE 32

bool TlsIdentity_ResolveStateDirectory(const char *override_directory, char *directory);
bool TlsIdentity_LoadOrCreate(
    const char *directory,
    const char *name,
    char *certificate_path,
    char *key_path
);
bool TlsIdentity_FingerprintOfDer(const uint8_t *certificate_der, size_t der_size, char *fingerprint_hex);
bool TlsIdentity_FingerprintOfFile(const char *certificate_path, char *fingerprint_hex);

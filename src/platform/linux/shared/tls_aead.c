#include "platform/linux/shared/tls_aead.h"

#include <stdbool.h>

#include <monocypher.h>
#include <picotls/minicrypto.h>

#include "chacha20poly1305.h"

typedef struct {
    struct chacha20poly1305_context_t super;
    crypto_poly1305_ctx poly1305;
} MonocypherChacha20Poly1305Context;

static void poly1305Init(struct chacha20poly1305_context_t *context, const void *key);
static void poly1305Update(struct chacha20poly1305_context_t *context, const void *input, size_t size);
static void poly1305Finish(struct chacha20poly1305_context_t *context, void *tag);
static int setupCrypto(ptls_aead_context_t *context, int is_enc, const void *key, const void *iv);

/* ---------- public ---------- */

ptls_aead_algorithm_t can_hub_chacha20poly1305 = {
    "CHACHA20-POLY1305",
    PTLS_CHACHA20POLY1305_CONFIDENTIALITY_LIMIT,
    PTLS_CHACHA20POLY1305_INTEGRITY_LIMIT,
    &ptls_minicrypto_chacha20,
    NULL,
    PTLS_CHACHA20_KEY_SIZE,
    PTLS_CHACHA20POLY1305_IV_SIZE,
    PTLS_CHACHA20POLY1305_TAG_SIZE,
    { PTLS_TLS12_CHACHAPOLY_FIXED_IV_SIZE, PTLS_TLS12_CHACHAPOLY_RECORD_IV_SIZE },
    0,
    0,
    sizeof(MonocypherChacha20Poly1305Context),
    setupCrypto,
};

ptls_cipher_suite_t can_hub_chacha20poly1305sha256 = {
    .id = PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    .name = PTLS_CIPHER_SUITE_NAME_CHACHA20_POLY1305_SHA256,
    .aead = &can_hub_chacha20poly1305,
    .hash = &ptls_minicrypto_sha256,
};

/* ---------- private ---------- */

static void poly1305Init(struct chacha20poly1305_context_t *context, const void *key)
{
    MonocypherChacha20Poly1305Context *self = (MonocypherChacha20Poly1305Context *)context;

    crypto_poly1305_init(&self->poly1305, key);
}

static void poly1305Update(struct chacha20poly1305_context_t *context, const void *input, size_t size)
{
    MonocypherChacha20Poly1305Context *self = (MonocypherChacha20Poly1305Context *)context;

    crypto_poly1305_update(&self->poly1305, input, size);
}

static void poly1305Finish(struct chacha20poly1305_context_t *context, void *tag)
{
    MonocypherChacha20Poly1305Context *self = (MonocypherChacha20Poly1305Context *)context;

    crypto_poly1305_final(&self->poly1305, tag);
}

static int setupCrypto(ptls_aead_context_t *context, int is_enc, const void *key, const void *iv)
{
    return chacha20poly1305_setup_crypto(
        context,
        is_enc,
        key,
        iv,
        &ptls_minicrypto_chacha20,
        poly1305Init,
        poly1305Update,
        poly1305Finish
    );
}

/* ---------- public: aes for quic initial packets ---------- */

#if defined(CAN_HUB_TLS_FUSION)

#include <stdint.h>

#include <picotls/fusion.h>

#define FUSION_ECB_ALIGNMENT 32

typedef struct {
    ptls_cipher_context_t super;
    uint8_t storage[sizeof(ptls_fusion_aesecb_context_t) + FUSION_ECB_ALIGNMENT];
    ptls_fusion_aesecb_context_t *ecb;
} FusionEcbContext;

static bool fusionUsable(void);
static ptls_cipher_suite_t *acceleratedAesSuite(void);
static ptls_fusion_aesecb_context_t *fusionEcbOf(FusionEcbContext *self);
static void fusionEcbDispose(ptls_cipher_context_t *context);
static void fusionEcbTransform(ptls_cipher_context_t *context, void *output, const void *input, size_t size);
static int fusionEcbSetup(ptls_cipher_context_t *context, int is_enc, const void *key);

static ptls_cipher_algorithm_t fusion_aes128ecb = {
    "AES128-ECB",
    PTLS_AES128_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    0,
    sizeof(FusionEcbContext),
    fusionEcbSetup,
};

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void)
{
    return fusionUsable() ? &ptls_fusion_aes128gcm : &ptls_minicrypto_aes128gcm;
}

/*
 * Not offered as a negotiated suite, deliberately. picotls ships two AES-NI
 * engines and says so: ptls_fusion_aes128gcm is "optimized for QUIC" while
 * ptls_non_temporal_aes128gcm is "optimized for TLS". One profile serves both
 * of our transports, and putting the QUIC engine on TLS-over-TCP records makes
 * the peer reject them with a bad record MAC — observed, not assumed. Serving
 * both would mean a per-transport suite list; until then AES stays confined to
 * the Initial packets, where RFC 9001 mandates it and where the engine is used
 * exactly as intended.
 */
static ptls_cipher_suite_t *acceleratedAesSuite(void)
{
    return NULL;
}

ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void)
{
    return fusionUsable() ? &fusion_aes128ecb : &ptls_minicrypto_aes128ecb;
}

static bool fusionUsable(void)
{
    static int8_t usable = -1;

    if (usable < 0) {
        usable = ptls_fusion_is_supported_by_cpu() ? 1 : 0;
    }

    return usable == 1;
}

static ptls_fusion_aesecb_context_t *fusionEcbOf(FusionEcbContext *self)
{
    uintptr_t base = (uintptr_t)self->storage;
    uintptr_t aligned = (base + FUSION_ECB_ALIGNMENT - 1) & ~(uintptr_t)(FUSION_ECB_ALIGNMENT - 1);

    return (ptls_fusion_aesecb_context_t *)aligned;
}

static void fusionEcbDispose(ptls_cipher_context_t *context)
{
    FusionEcbContext *self = (FusionEcbContext *)context;

    ptls_fusion_aesecb_dispose(self->ecb);
}

static void fusionEcbTransform(ptls_cipher_context_t *context, void *output, const void *input, size_t size)
{
    FusionEcbContext *self = (FusionEcbContext *)context;
    size_t offset;

    for(offset=0; offset + PTLS_AES_BLOCK_SIZE <= size; offset += PTLS_AES_BLOCK_SIZE) {
        ptls_fusion_aesecb_encrypt(self->ecb, (uint8_t *)output + offset, (const uint8_t *)input + offset);
    }
}

static int fusionEcbSetup(ptls_cipher_context_t *context, int is_enc, const void *key)
{
    FusionEcbContext *self = (FusionEcbContext *)context;

    if (!is_enc) {
        return PTLS_ERROR_LIBRARY;
    }

    self->ecb = fusionEcbOf(self);
    ptls_fusion_aesecb_init(self->ecb, 1, key, PTLS_AES128_KEY_SIZE, 0);
    self->super.do_dispose = fusionEcbDispose;
    self->super.do_init = NULL;
    self->super.do_transform = fusionEcbTransform;

    return 0;
}

#else

static ptls_cipher_suite_t *acceleratedAesSuite(void);

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void)
{
    return &ptls_minicrypto_aes128gcm;
}

ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void)
{
    return &ptls_minicrypto_aes128ecb;
}

static ptls_cipher_suite_t *acceleratedAesSuite(void)
{
    return NULL;
}

#endif

/* ---------- public: offered suites ---------- */

ptls_cipher_suite_t **TlsAead_CipherSuites(void)
{
    static ptls_cipher_suite_t *suites[3];
    ptls_cipher_suite_t *accelerated;

    if (suites[0] != NULL) {
        return suites;
    }

    accelerated = acceleratedAesSuite();
    if (accelerated != NULL) {
        suites[0] = accelerated;
        suites[1] = &can_hub_chacha20poly1305sha256;
        return suites;
    }

    suites[0] = &can_hub_chacha20poly1305sha256;

    return suites;
}

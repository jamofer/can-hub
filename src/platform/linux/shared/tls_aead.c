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
static size_t appendSuite(ptls_cipher_suite_t **offered, size_t count, ptls_cipher_suite_t *suite);

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

static size_t appendSuite(ptls_cipher_suite_t **offered, size_t count, ptls_cipher_suite_t *suite)
{
    if (suite == NULL) {
        return 0;
    }

    offered[count] = suite;

    return 1;
}

/* ---------- public: aes ---------- */

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
static ptls_cipher_suite_t *acceleratedAesSuite(TLS_TRANSPORT transport);
static ptls_cipher_suite_t *acceleratedAes256Suite(TLS_TRANSPORT transport);
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

static ptls_cipher_algorithm_t fusion_aes256ecb = {
    "AES256-ECB",
    PTLS_AES256_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    0,
    sizeof(FusionEcbContext),
    fusionEcbSetup,
};

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void)
{
    return fusionUsable() ? &ptls_fusion_aes128gcm : &ptls_minicrypto_aes128gcm;
}

ptls_aead_algorithm_t *TlsAead_Aes256Gcm(void)
{
    return fusionUsable() ? &ptls_fusion_aes256gcm : &ptls_minicrypto_aes256gcm;
}

/*
 * The QUIC suite has to keep the very pointer TlsAead_Aes128Gcm returns: the
 * ngtcp2 backend selects the header-protection cipher and the AEAD usage
 * limits by comparing the negotiated aead against it, and a miss would mean
 * encrypting past the confidentiality bound with no header protection.
 */
static ptls_cipher_suite_t quic_aes128gcmsha256 = {
    .id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
    .aead = &ptls_fusion_aes128gcm,
    .hash = &ptls_minicrypto_sha256,
};

static ptls_cipher_suite_t stream_aes128gcmsha256 = {
    .id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
    .aead = &ptls_non_temporal_aes128gcm,
    .hash = &ptls_minicrypto_sha256,
};

static ptls_cipher_suite_t quic_aes256gcmsha384 = {
    .id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
    .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384,
    .aead = &ptls_fusion_aes256gcm,
    .hash = &ptls_minicrypto_sha384,
};

static ptls_cipher_suite_t stream_aes256gcmsha384 = {
    .id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
    .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384,
    .aead = &ptls_non_temporal_aes256gcm,
    .hash = &ptls_minicrypto_sha384,
};

static ptls_cipher_suite_t *acceleratedAesSuite(TLS_TRANSPORT transport)
{
    if (!fusionUsable()) {
        return NULL;
    }

    return transport == kTLS_TRANSPORT_QUIC ? &quic_aes128gcmsha256 : &stream_aes128gcmsha256;
}

static ptls_cipher_suite_t *acceleratedAes256Suite(TLS_TRANSPORT transport)
{
    if (!fusionUsable()) {
        return NULL;
    }

    return transport == kTLS_TRANSPORT_QUIC ? &quic_aes256gcmsha384 : &stream_aes256gcmsha384;
}

ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void)
{
    return fusionUsable() ? &fusion_aes128ecb : &ptls_minicrypto_aes128ecb;
}

ptls_cipher_algorithm_t *TlsAead_Aes256Ecb(void)
{
    return fusionUsable() ? &fusion_aes256ecb : &ptls_minicrypto_aes256ecb;
}

static bool fusionUsable(void)
{
    static int8_t usable = -1;

    if (usable < 0) {
        usable = ptls_fusion_is_supported_by_cpu() ? 1 : 0;
#if defined(CAN_HUB_TLS_FUSION_NO_AESNI256)
        ptls_fusion_can_aesni256 = 0;
#endif
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
    ptls_fusion_aesecb_init(self->ecb, 1, key, self->super.algo->key_size, 0);
    self->super.do_dispose = fusionEcbDispose;
    self->super.do_init = NULL;
    self->super.do_transform = fusionEcbTransform;

    return 0;
}

#else

static ptls_cipher_suite_t *acceleratedAesSuite(TLS_TRANSPORT transport);
static ptls_cipher_suite_t *acceleratedAes256Suite(TLS_TRANSPORT transport);

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void)
{
    return &ptls_minicrypto_aes128gcm;
}

ptls_aead_algorithm_t *TlsAead_Aes256Gcm(void)
{
    return &ptls_minicrypto_aes256gcm;
}

ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void)
{
    return &ptls_minicrypto_aes128ecb;
}

ptls_cipher_algorithm_t *TlsAead_Aes256Ecb(void)
{
    return &ptls_minicrypto_aes256ecb;
}

static ptls_cipher_suite_t *acceleratedAesSuite(TLS_TRANSPORT transport)
{
    (void)transport;

    return NULL;
}

static ptls_cipher_suite_t *acceleratedAes256Suite(TLS_TRANSPORT transport)
{
    (void)transport;

    return NULL;
}

#endif

/* ---------- public: offered suites ---------- */

ptls_cipher_suite_t **TlsAead_CipherSuites(TLS_TRANSPORT transport)
{
    static ptls_cipher_suite_t *suites[kTLS_TRANSPORT_MAX][4];
    ptls_cipher_suite_t **offered = suites[transport];
    size_t count;

    if (offered[0] != NULL) {
        return offered;
    }

    count = 0;
    count += appendSuite(offered, count, acceleratedAesSuite(transport));
    count += appendSuite(offered, count, acceleratedAes256Suite(transport));
    offered[count] = &can_hub_chacha20poly1305sha256;

    return offered;
}

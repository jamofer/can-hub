#include "platform/linux/shared/tls_aead.h"

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

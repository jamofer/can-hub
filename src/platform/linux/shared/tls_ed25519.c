#include "platform/linux/shared/tls_ed25519.h"

#include <stdlib.h>
#include <string.h>

#include <monocypher-ed25519.h>
#include <picotls/pembase64.h>

#define DER_TAG_INTEGER 0x02
#define DER_TAG_BIT_STRING 0x03
#define DER_TAG_OCTET_STRING 0x04
#define DER_TAG_SEQUENCE 0x30
#define DER_TAG_CONTEXT_ZERO 0xA0
#define DER_LONG_FORM 0x80
#define DER_LENGTH_BYTES_MAX 4
#define BIT_STRING_UNUSED_BITS 0x00
#define PRIVATE_KEY_OBJECTS_MAX 1

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} DerReader;

static int signCertificate(
    ptls_sign_certificate_t *signer,
    ptls_t *tls,
    ptls_async_job_t **async,
    uint16_t *selected_algorithm,
    ptls_buffer_t *output,
    ptls_iovec_t input,
    const uint16_t *algorithms,
    size_t algorithm_count
);
static bool offersEd25519(const uint16_t *algorithms, size_t algorithm_count);
static bool seedOfPrivateKeyDer(const uint8_t *key_der, size_t size, uint8_t *seed);
static void derReaderInit(DerReader *reader, const uint8_t *data, size_t size);
static bool derReadElement(DerReader *reader, uint8_t tag, DerReader *content);
static bool derSkipElement(DerReader *reader);

/* ---------- public ---------- */

bool TlsEd25519_AttachSigner(TlsEd25519Signer *self, ptls_context_t *context, const char *key_path)
{
    ptls_iovec_t objects[PRIVATE_KEY_OBJECTS_MAX];
    size_t count = 0;
    uint8_t seed[TLS_ED25519_SEED_SIZE];
    uint8_t public_key[TLS_IDENTITY_PUBLIC_KEY_SIZE];
    bool loaded;

    memset(self, 0, sizeof(*self));

    if (ptls_load_pem_objects(key_path, "PRIVATE KEY", objects, PRIVATE_KEY_OBJECTS_MAX, &count) != 0) {
        return false;
    }
    if (count != PRIVATE_KEY_OBJECTS_MAX) {
        return false;
    }

    loaded = seedOfPrivateKeyDer(objects[0].base, objects[0].len, seed);
    free(objects[0].base);
    if (!loaded) {
        return false;
    }

    crypto_ed25519_key_pair(self->secret_key, public_key, seed);
    self->loaded = true;
    self->super.cb = signCertificate;
    context->sign_certificate = &self->super;

    return true;
}

bool TlsEd25519_PublicKeyOfCertificate(const uint8_t *certificate_der, size_t size, uint8_t *public_key)
{
    DerReader certificate;
    DerReader tbs;
    DerReader key_info;
    DerReader bits;

    derReaderInit(&certificate, certificate_der, size);
    if (!derReadElement(&certificate, DER_TAG_SEQUENCE, &certificate)) {
        return false;
    }
    if (!derReadElement(&certificate, DER_TAG_SEQUENCE, &tbs)) {
        return false;
    }

    if (tbs.offset < tbs.size && tbs.data[tbs.offset] == DER_TAG_CONTEXT_ZERO && !derSkipElement(&tbs)) {
        return false;
    }
    if (!derSkipElement(&tbs) || !derSkipElement(&tbs) || !derSkipElement(&tbs)
        || !derSkipElement(&tbs) || !derSkipElement(&tbs)) {
        return false;
    }

    if (!derReadElement(&tbs, DER_TAG_SEQUENCE, &key_info)) {
        return false;
    }
    if (!derSkipElement(&key_info)) {
        return false;
    }
    if (!derReadElement(&key_info, DER_TAG_BIT_STRING, &bits)) {
        return false;
    }
    if (bits.size - bits.offset != TLS_IDENTITY_PUBLIC_KEY_SIZE + 1) {
        return false;
    }
    if (bits.data[bits.offset] != BIT_STRING_UNUSED_BITS) {
        return false;
    }

    memcpy(public_key, bits.data + bits.offset + 1, TLS_IDENTITY_PUBLIC_KEY_SIZE);

    return true;
}

bool TlsEd25519_Verify(
    const uint8_t *public_key,
    const uint8_t *message,
    size_t size,
    const uint8_t *signature
)
{
    return crypto_ed25519_check(signature, public_key, message, size) == 0;
}

/* ---------- private ---------- */

static int signCertificate(
    ptls_sign_certificate_t *signer,
    ptls_t *tls,
    ptls_async_job_t **async,
    uint16_t *selected_algorithm,
    ptls_buffer_t *output,
    ptls_iovec_t input,
    const uint16_t *algorithms,
    size_t algorithm_count
)
{
    TlsEd25519Signer *self = (TlsEd25519Signer *)signer;
    uint8_t signature[TLS_ED25519_SIGNATURE_SIZE];
    int reserved;

    (void)tls;
    (void)async;

    if (!self->loaded) {
        return PTLS_ERROR_LIBRARY;
    }
    if (!offersEd25519(algorithms, algorithm_count)) {
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    crypto_ed25519_sign(signature, self->secret_key, input.base, input.len);

    reserved = ptls_buffer_reserve(output, sizeof(signature));
    if (reserved != 0) {
        return reserved;
    }
    memcpy(output->base + output->off, signature, sizeof(signature));
    output->off += sizeof(signature);
    *selected_algorithm = PTLS_SIGNATURE_ED25519;

    return 0;
}

static bool offersEd25519(const uint16_t *algorithms, size_t algorithm_count)
{
    size_t i;

    for(i=0; i<algorithm_count; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ED25519) {
            return true;
        }
    }

    return false;
}

static bool seedOfPrivateKeyDer(const uint8_t *key_der, size_t size, uint8_t *seed)
{
    DerReader key;
    DerReader wrapper;
    DerReader inner;

    derReaderInit(&key, key_der, size);
    if (!derReadElement(&key, DER_TAG_SEQUENCE, &key)) {
        return false;
    }
    if (!derSkipElement(&key) || !derSkipElement(&key)) {
        return false;
    }
    if (!derReadElement(&key, DER_TAG_OCTET_STRING, &wrapper)) {
        return false;
    }
    if (!derReadElement(&wrapper, DER_TAG_OCTET_STRING, &inner)) {
        return false;
    }
    if (inner.size - inner.offset != TLS_ED25519_SEED_SIZE) {
        return false;
    }

    memcpy(seed, inner.data + inner.offset, TLS_ED25519_SEED_SIZE);

    return true;
}

static void derReaderInit(DerReader *reader, const uint8_t *data, size_t size)
{
    reader->data = data;
    reader->size = size;
    reader->offset = 0;
}

static bool derReadElement(DerReader *reader, uint8_t tag, DerReader *content)
{
    size_t offset = reader->offset;
    size_t length = 0;
    uint8_t length_bytes;
    uint8_t i;

    if (offset + 2 > reader->size || reader->data[offset] != tag) {
        return false;
    }
    offset++;

    if ((reader->data[offset] & DER_LONG_FORM) == 0) {
        length = reader->data[offset];
        offset++;
    } else {
        length_bytes = reader->data[offset] & (uint8_t)~DER_LONG_FORM;
        offset++;
        if (length_bytes == 0 || length_bytes > DER_LENGTH_BYTES_MAX || offset + length_bytes > reader->size) {
            return false;
        }
        for(i=0; i<length_bytes; i++) {
            length = (length << 8) | reader->data[offset + i];
        }
        offset += length_bytes;
    }

    if (length > reader->size - offset) {
        return false;
    }

    reader->offset = offset + length;
    content->data = reader->data;
    content->size = offset + length;
    content->offset = offset;

    return true;
}

static bool derSkipElement(DerReader *reader)
{
    DerReader content;

    if (reader->offset >= reader->size) {
        return false;
    }

    return derReadElement(reader, reader->data[reader->offset], &content);
}

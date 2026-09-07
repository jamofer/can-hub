#include "platform/linux/shared/tls_identity_backend.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <monocypher-ed25519.h>
#include <picotls/minicrypto.h>
#include <picotls/pembase64.h>

#include "platform/linux/shared/tls_ed25519.h"
#include "platform/linux/shared/tls_identity.h"

#define DER_TAG_INTEGER 0x02
#define DER_TAG_BIT_STRING 0x03
#define DER_TAG_OCTET_STRING 0x04
#define DER_TAG_OBJECT_IDENTIFIER 0x06
#define DER_TAG_UTF8_STRING 0x0C
#define DER_TAG_UTC_TIME 0x17
#define DER_TAG_SEQUENCE 0x30
#define DER_TAG_SET 0x31
#define DER_TAG_CONTEXT_ZERO 0xA0
#define DER_LONG_FORM 0x80
#define BIT_STRING_UNUSED_BITS 0x00

#define CERTIFICATE_X509_VERSION_3 2
#define CERTIFICATE_SERIAL 1
#define CERTIFICATE_LIFETIME_SECONDS (10L * 365 * 24 * 3600)
#define CERTIFICATE_BACKDATE_SECONDS 3600
#define UTC_TIME_SIZE 13
#define DER_BUFFER_SIZE 1024
#define PEM_LINE_LENGTH 64
#define BASE64_TERMINATOR_SIZE 1

static const uint8_t oid_ed25519[] = { 0x2B, 0x65, 0x70 };
static const uint8_t oid_common_name[] = { 0x55, 0x04, 0x03 };

typedef struct {
    uint8_t *data;
    size_t size;
    size_t offset;
} DerWriter;

static void derWriterInit(DerWriter *writer, uint8_t *data, size_t size);
static bool derWriteHeader(DerWriter *writer, uint8_t tag, size_t length);
static bool derWriteBytes(DerWriter *writer, const uint8_t *data, size_t size);
static bool derWriteElement(DerWriter *writer, uint8_t tag, const uint8_t *data, size_t size);
static bool derWriteObjectIdentifier(DerWriter *writer, const uint8_t *oid, size_t size);
static bool encodeAlgorithmIdentifier(DerWriter *writer);
static bool encodeName(DerWriter *writer, const char *common_name);
static bool encodeValidity(DerWriter *writer);
static bool encodePublicKeyInfo(DerWriter *writer, const uint8_t *public_key);
static bool encodeTbsCertificate(
    uint8_t *buffer,
    size_t buffer_size,
    size_t *length,
    const char *common_name,
    const uint8_t *public_key
);
static bool encodeCertificate(
    uint8_t *buffer,
    size_t buffer_size,
    size_t *length,
    const uint8_t *tbs,
    size_t tbs_length,
    const uint8_t *signature
);
static bool encodePrivateKey(uint8_t *buffer, size_t buffer_size, size_t *length, const uint8_t *secret_key);
static void formatUtcTime(char *text, int64_t offset_seconds);
static bool writePem(
    const char *label,
    const uint8_t *der,
    size_t der_length,
    uint8_t *out,
    size_t out_size,
    size_t *out_length
);

/* ---------- public ---------- */

bool TlsIdentityBackend_Generate(
    const char *common_name,
    uint8_t *certificate_pem,
    size_t certificate_pem_size,
    size_t *certificate_pem_length,
    uint8_t *key_pem,
    size_t key_pem_size,
    size_t *key_pem_length
)
{
    uint8_t seed[TLS_ED25519_SEED_SIZE];
    uint8_t secret_key[TLS_ED25519_SECRET_KEY_SIZE];
    uint8_t public_key[TLS_IDENTITY_PUBLIC_KEY_SIZE];
    uint8_t signature[TLS_ED25519_SIGNATURE_SIZE];
    uint8_t tbs[DER_BUFFER_SIZE];
    uint8_t certificate[DER_BUFFER_SIZE];
    uint8_t key[DER_BUFFER_SIZE];
    size_t tbs_length = 0;
    size_t certificate_length = 0;
    size_t key_length = 0;

    ptls_minicrypto_random_bytes(seed, sizeof(seed));
    crypto_ed25519_key_pair(secret_key, public_key, seed);

    if (!encodeTbsCertificate(tbs, sizeof(tbs), &tbs_length, common_name, public_key)) {
        return false;
    }
    crypto_ed25519_sign(signature, secret_key, tbs, tbs_length);

    if (!encodeCertificate(certificate, sizeof(certificate), &certificate_length, tbs, tbs_length, signature)) {
        return false;
    }
    if (!encodePrivateKey(key, sizeof(key), &key_length, secret_key)) {
        return false;
    }

    if (!writePem("CERTIFICATE", certificate, certificate_length, certificate_pem, certificate_pem_size, certificate_pem_length)) {
        return false;
    }

    return writePem("PRIVATE KEY", key, key_length, key_pem, key_pem_size, key_pem_length);
}

/* ---------- private ---------- */

static void derWriterInit(DerWriter *writer, uint8_t *data, size_t size)
{
    writer->data = data;
    writer->size = size;
    writer->offset = 0;
}

static bool derWriteHeader(DerWriter *writer, uint8_t tag, size_t length)
{
    if (writer->offset + 2 > writer->size) {
        return false;
    }
    writer->data[writer->offset] = tag;
    writer->offset++;

    if (length < DER_LONG_FORM) {
        writer->data[writer->offset] = (uint8_t)length;
        writer->offset++;
        return true;
    }
    if (length > 0xFFFF || writer->offset + 3 > writer->size) {
        return false;
    }
    if (length <= 0xFF) {
        writer->data[writer->offset] = DER_LONG_FORM | 1;
        writer->data[writer->offset + 1] = (uint8_t)length;
        writer->offset += 2;
        return true;
    }

    writer->data[writer->offset] = DER_LONG_FORM | 2;
    writer->data[writer->offset + 1] = (uint8_t)(length >> 8);
    writer->data[writer->offset + 2] = (uint8_t)length;
    writer->offset += 3;

    return true;
}

static bool derWriteBytes(DerWriter *writer, const uint8_t *data, size_t size)
{
    if (writer->offset + size > writer->size) {
        return false;
    }
    memcpy(writer->data + writer->offset, data, size);
    writer->offset += size;

    return true;
}

static bool derWriteElement(DerWriter *writer, uint8_t tag, const uint8_t *data, size_t size)
{
    return derWriteHeader(writer, tag, size) && derWriteBytes(writer, data, size);
}

static bool derWriteObjectIdentifier(DerWriter *writer, const uint8_t *oid, size_t size)
{
    return derWriteElement(writer, DER_TAG_OBJECT_IDENTIFIER, oid, size);
}

static bool encodeAlgorithmIdentifier(DerWriter *writer)
{
    uint8_t content[DER_BUFFER_SIZE];
    DerWriter inner;

    derWriterInit(&inner, content, sizeof(content));
    if (!derWriteObjectIdentifier(&inner, oid_ed25519, sizeof(oid_ed25519))) {
        return false;
    }

    return derWriteElement(writer, DER_TAG_SEQUENCE, content, inner.offset);
}

static bool encodeName(DerWriter *writer, const char *common_name)
{
    uint8_t attribute[DER_BUFFER_SIZE];
    uint8_t set_content[DER_BUFFER_SIZE];
    uint8_t sequence_content[DER_BUFFER_SIZE];
    DerWriter inner;
    DerWriter wrapper;

    derWriterInit(&inner, attribute, sizeof(attribute));
    if (!derWriteObjectIdentifier(&inner, oid_common_name, sizeof(oid_common_name))) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_UTF8_STRING, (const uint8_t *)common_name, strlen(common_name))) {
        return false;
    }

    derWriterInit(&wrapper, set_content, sizeof(set_content));
    if (!derWriteElement(&wrapper, DER_TAG_SEQUENCE, attribute, inner.offset)) {
        return false;
    }

    derWriterInit(&inner, sequence_content, sizeof(sequence_content));
    if (!derWriteElement(&inner, DER_TAG_SET, set_content, wrapper.offset)) {
        return false;
    }

    return derWriteElement(writer, DER_TAG_SEQUENCE, sequence_content, inner.offset);
}

static bool encodeValidity(DerWriter *writer)
{
    uint8_t content[DER_BUFFER_SIZE];
    char not_before[UTC_TIME_SIZE + 1];
    char not_after[UTC_TIME_SIZE + 1];
    DerWriter inner;

    formatUtcTime(not_before, -CERTIFICATE_BACKDATE_SECONDS);
    formatUtcTime(not_after, CERTIFICATE_LIFETIME_SECONDS);

    derWriterInit(&inner, content, sizeof(content));
    if (!derWriteElement(&inner, DER_TAG_UTC_TIME, (const uint8_t *)not_before, UTC_TIME_SIZE)) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_UTC_TIME, (const uint8_t *)not_after, UTC_TIME_SIZE)) {
        return false;
    }

    return derWriteElement(writer, DER_TAG_SEQUENCE, content, inner.offset);
}

static bool encodePublicKeyInfo(DerWriter *writer, const uint8_t *public_key)
{
    uint8_t content[DER_BUFFER_SIZE];
    uint8_t bits[TLS_IDENTITY_PUBLIC_KEY_SIZE + 1];
    DerWriter inner;

    bits[0] = BIT_STRING_UNUSED_BITS;
    memcpy(bits + 1, public_key, TLS_IDENTITY_PUBLIC_KEY_SIZE);

    derWriterInit(&inner, content, sizeof(content));
    if (!encodeAlgorithmIdentifier(&inner)) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_BIT_STRING, bits, sizeof(bits))) {
        return false;
    }

    return derWriteElement(writer, DER_TAG_SEQUENCE, content, inner.offset);
}

static bool encodeTbsCertificate(
    uint8_t *buffer,
    size_t buffer_size,
    size_t *length,
    const char *common_name,
    const uint8_t *public_key
)
{
    uint8_t content[DER_BUFFER_SIZE];
    uint8_t version[DER_BUFFER_SIZE];
    uint8_t serial = CERTIFICATE_SERIAL;
    uint8_t version_value = CERTIFICATE_X509_VERSION_3;
    DerWriter inner;
    DerWriter version_writer;
    DerWriter outer;

    derWriterInit(&version_writer, version, sizeof(version));
    if (!derWriteElement(&version_writer, DER_TAG_INTEGER, &version_value, sizeof(version_value))) {
        return false;
    }

    derWriterInit(&inner, content, sizeof(content));
    if (!derWriteElement(&inner, DER_TAG_CONTEXT_ZERO, version, version_writer.offset)) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_INTEGER, &serial, sizeof(serial))) {
        return false;
    }
    if (!encodeAlgorithmIdentifier(&inner)) {
        return false;
    }
    if (!encodeName(&inner, common_name)) {
        return false;
    }
    if (!encodeValidity(&inner)) {
        return false;
    }
    if (!encodeName(&inner, common_name)) {
        return false;
    }
    if (!encodePublicKeyInfo(&inner, public_key)) {
        return false;
    }

    derWriterInit(&outer, buffer, buffer_size);
    if (!derWriteElement(&outer, DER_TAG_SEQUENCE, content, inner.offset)) {
        return false;
    }
    *length = outer.offset;

    return true;
}

static bool encodeCertificate(
    uint8_t *buffer,
    size_t buffer_size,
    size_t *length,
    const uint8_t *tbs,
    size_t tbs_length,
    const uint8_t *signature
)
{
    uint8_t content[DER_BUFFER_SIZE];
    uint8_t bits[TLS_ED25519_SIGNATURE_SIZE + 1];
    DerWriter inner;
    DerWriter outer;

    bits[0] = BIT_STRING_UNUSED_BITS;
    memcpy(bits + 1, signature, TLS_ED25519_SIGNATURE_SIZE);

    derWriterInit(&inner, content, sizeof(content));
    if (!derWriteBytes(&inner, tbs, tbs_length)) {
        return false;
    }
    if (!encodeAlgorithmIdentifier(&inner)) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_BIT_STRING, bits, sizeof(bits))) {
        return false;
    }

    derWriterInit(&outer, buffer, buffer_size);
    if (!derWriteElement(&outer, DER_TAG_SEQUENCE, content, inner.offset)) {
        return false;
    }
    *length = outer.offset;

    return true;
}

/*
 * crypto_ed25519_key_pair wipes the seed it is handed, so the PKCS#8 seed is
 * taken from the secret key, whose first half is that same seed.
 */
static bool encodePrivateKey(uint8_t *buffer, size_t buffer_size, size_t *length, const uint8_t *secret_key)
{
    uint8_t content[DER_BUFFER_SIZE];
    uint8_t wrapped[DER_BUFFER_SIZE];
    uint8_t version = 0;
    DerWriter inner;
    DerWriter wrapper;
    DerWriter outer;

    derWriterInit(&wrapper, wrapped, sizeof(wrapped));
    if (!derWriteElement(&wrapper, DER_TAG_OCTET_STRING, secret_key, TLS_ED25519_SEED_SIZE)) {
        return false;
    }

    derWriterInit(&inner, content, sizeof(content));
    if (!derWriteElement(&inner, DER_TAG_INTEGER, &version, sizeof(version))) {
        return false;
    }
    if (!encodeAlgorithmIdentifier(&inner)) {
        return false;
    }
    if (!derWriteElement(&inner, DER_TAG_OCTET_STRING, wrapped, wrapper.offset)) {
        return false;
    }

    derWriterInit(&outer, buffer, buffer_size);
    if (!derWriteElement(&outer, DER_TAG_SEQUENCE, content, inner.offset)) {
        return false;
    }
    *length = outer.offset;

    return true;
}

static void formatUtcTime(char *text, int64_t offset_seconds)
{
    time_t moment = time(NULL) + (time_t)offset_seconds;
    struct tm parts;

    gmtime_r(&moment, &parts);
    snprintf(
        text,
        UTC_TIME_SIZE + 1,
        "%02u%02u%02u%02u%02u%02uZ",
        (uint32_t)(parts.tm_year + 1900) % 100u,
        (uint32_t)(parts.tm_mon + 1) % 100u,
        (uint32_t)parts.tm_mday % 100u,
        (uint32_t)parts.tm_hour % 100u,
        (uint32_t)parts.tm_min % 100u,
        (uint32_t)parts.tm_sec % 100u
    );
}

static bool writePem(
    const char *label,
    const uint8_t *der,
    size_t der_length,
    uint8_t *out,
    size_t out_size,
    size_t *out_length
)
{
    char base64[DER_BUFFER_SIZE * 2];
    size_t written = 0;
    size_t offset = 0;
    size_t chunk;
    int encoded;

    if (ptls_base64_howlong(der_length) + BASE64_TERMINATOR_SIZE > sizeof(base64)) {
        return false;
    }
    encoded = ptls_base64_encode(der, der_length, base64);
    if (encoded <= 1) {
        return false;
    }
    encoded -= BASE64_TERMINATOR_SIZE;

    written = (size_t)snprintf((char *)out, out_size, "-----BEGIN %s-----\n", label);
    if (written >= out_size) {
        return false;
    }

    while (offset < (size_t)encoded) {
        chunk = (size_t)encoded - offset;
        if (chunk > PEM_LINE_LENGTH) {
            chunk = PEM_LINE_LENGTH;
        }
        if (written + chunk + 1 >= out_size) {
            return false;
        }
        memcpy(out + written, base64 + offset, chunk);
        written += chunk;
        out[written] = '\n';
        written++;
        offset += chunk;
    }

    encoded = snprintf((char *)out + written, out_size - written, "-----END %s-----\n", label);
    if (encoded < 0 || written + (size_t)encoded >= out_size) {
        return false;
    }
    *out_length = written + (size_t)encoded;

    return true;
}

#include "platform/linux/shared/tls_identity.h"

#include "platform/linux/shared/tls_identity_backend.h"

#include <direct.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <picotls.h>
#include <picotls/minicrypto.h>
#include <picotls/pembase64.h>

#define STATE_SUBDIRECTORY "\\can-hub"
#define FINGERPRINT_SIZE 32
#define IDENTITY_CHAIN_MAX 4
#define IDENTITY_PEM_MAX 8192

static bool makeDirectoryPath(const char *directory);
static bool filesExist(const char *first_path, const char *second_path);
static bool generateIdentity(const char *certificate_path, const char *key_path, const char *common_name);
static bool writeFile(const char *path, const uint8_t *data, size_t size);

/* ---------- public ---------- */

bool TlsIdentity_ResolveStateDirectory(const char *override_directory, char *directory)
{
    const char *application_data;

    if (override_directory != NULL) {
        snprintf(directory, TLS_IDENTITY_PATH_MAX, "%s", override_directory);
        return makeDirectoryPath(directory);
    }

    application_data = getenv("LOCALAPPDATA");
    if (application_data == NULL) {
        application_data = getenv("APPDATA");
    }
    if (application_data == NULL) {
        return false;
    }
    snprintf(directory, TLS_IDENTITY_PATH_MAX, "%s%s", application_data, STATE_SUBDIRECTORY);

    return makeDirectoryPath(directory);
}

bool TlsIdentity_LoadOrCreate(
    const char *directory,
    const char *name,
    char *certificate_path,
    char *key_path
)
{
    snprintf(certificate_path, TLS_IDENTITY_PATH_MAX, "%s/%s.crt", directory, name);
    snprintf(key_path, TLS_IDENTITY_PATH_MAX, "%s/%s.key", directory, name);

    if (filesExist(certificate_path, key_path)) {
        return true;
    }

    return generateIdentity(certificate_path, key_path, name);
}

bool TlsIdentity_FingerprintOfDer(const uint8_t *certificate_der, size_t der_size, char *fingerprint_hex)
{
    uint8_t fingerprint[FINGERPRINT_SIZE];
    size_t i;

    if (ptls_calc_hash(&ptls_minicrypto_sha256, fingerprint, certificate_der, der_size) != 0) {
        return false;
    }

    for(i=0; i<FINGERPRINT_SIZE; i++) {
        snprintf(&fingerprint_hex[i * 2], 3, "%02x", fingerprint[i]);
    }

    return true;
}

bool TlsIdentity_FingerprintOfFile(const char *certificate_path, char *fingerprint_hex)
{
    ptls_iovec_t certificates[IDENTITY_CHAIN_MAX];
    size_t count = 0;
    bool computed = false;
    size_t i;

    if (ptls_load_pem_objects(certificate_path, "CERTIFICATE", certificates, IDENTITY_CHAIN_MAX, &count) != 0) {
        return false;
    }
    if (count > 0) {
        computed = TlsIdentity_FingerprintOfDer(certificates[0].base, certificates[0].len, fingerprint_hex);
    }

    for(i=0; i<count; i++) {
        free(certificates[i].base);
    }

    return computed;
}

/* ---------- private ---------- */

static bool makeDirectoryPath(const char *directory)
{
    char partial[TLS_IDENTITY_PATH_MAX];
    char *separator;

    snprintf(partial, sizeof(partial), "%s", directory);
    separator = partial;
    while ((separator = strpbrk(separator + 1, "/\\")) != NULL) {
        *separator = '\0';
        _mkdir(partial);
        *separator = '\\';
    }
    _mkdir(partial);

    return _access(directory, 0) == 0;
}

static bool filesExist(const char *first_path, const char *second_path)
{
    return _access(first_path, 4) == 0 && _access(second_path, 4) == 0;
}

static bool generateIdentity(const char *certificate_path, const char *key_path, const char *common_name)
{
    uint8_t certificate_pem[IDENTITY_PEM_MAX];
    uint8_t key_pem[IDENTITY_PEM_MAX];
    size_t certificate_length = 0;
    size_t key_length = 0;

    if (!TlsIdentityBackend_Generate(
            common_name,
            certificate_pem, sizeof(certificate_pem), &certificate_length,
            key_pem, sizeof(key_pem), &key_length)) {
        return false;
    }

    return writeFile(key_path, key_pem, key_length)
        && writeFile(certificate_path, certificate_pem, certificate_length);
}

static bool writeFile(const char *path, const uint8_t *data, size_t size)
{
    FILE *file = fopen(path, "wb");
    size_t written;

    if (file == NULL) {
        return false;
    }
    written = fwrite(data, 1, size, file);
    fclose(file);

    return written == size;
}

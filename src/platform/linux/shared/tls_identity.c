#include "platform/linux/shared/tls_identity.h"

#include "platform/linux/shared/tls_identity_backend.h"


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>

#include <picotls.h>
#include <picotls/pembase64.h>

#include <openssl/evp.h>

#define SYSTEM_STATE_DIRECTORY "/var/lib/can-hub"
#define USER_STATE_SUBDIRECTORY "/.local/state/can-hub"
#define STATE_DIRECTORY_MODE 0755
#define PRIVATE_KEY_FILE_MODE 0600
#define IDENTITY_PEM_MAX 8192
#define CERTIFICATE_FILE_MODE 0644
#define CERTIFICATE_LIFETIME_SECONDS (20L * 365 * 24 * 3600)
#define CERTIFICATE_BACKDATE_SECONDS 86400
#define CERTIFICATE_SERIAL 1
#define CERTIFICATE_X509_VERSION_3 2
#define FINGERPRINT_SIZE 32
#define IDENTITY_CHAIN_MAX 4

static bool directoryUsable(const char *directory);
static bool makeDirectoryPath(const char *directory);
static bool filesExist(const char *first_path, const char *second_path);
static bool generateIdentity(const char *certificate_path, const char *key_path, const char *common_name);
static bool writeFileWithMode(const char *path, const uint8_t *data, size_t size, mode_t mode);

/* ---------- public ---------- */

bool TlsIdentity_ResolveStateDirectory(const char *override_directory, char *directory)
{
    const char *home;

    if (override_directory != NULL) {
        snprintf(directory, TLS_IDENTITY_PATH_MAX, "%s", override_directory);
        return makeDirectoryPath(directory);
    }

    snprintf(directory, TLS_IDENTITY_PATH_MAX, "%s", SYSTEM_STATE_DIRECTORY);
    if (makeDirectoryPath(directory) && directoryUsable(directory)) {
        return true;
    }

    home = getenv("HOME");
    if (home == NULL) {
        return false;
    }
    snprintf(directory, TLS_IDENTITY_PATH_MAX, "%s%s", home, USER_STATE_SUBDIRECTORY);

    return makeDirectoryPath(directory) && directoryUsable(directory);
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
    unsigned int fingerprint_size = 0;
    size_t i;

    if (!EVP_Digest(certificate_der, der_size, fingerprint, &fingerprint_size, EVP_sha256(), NULL)) {
        return false;
    }
    if (fingerprint_size != FINGERPRINT_SIZE) {
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

static bool directoryUsable(const char *directory)
{
    return access(directory, W_OK | X_OK) == 0;
}

static bool makeDirectoryPath(const char *directory)
{
    char partial[TLS_IDENTITY_PATH_MAX];
    char *separator;

    snprintf(partial, sizeof(partial), "%s", directory);
    separator = partial;
    while ((separator = strchr(separator + 1, '/')) != NULL) {
        *separator = '\0';
        mkdir(partial, STATE_DIRECTORY_MODE);
        *separator = '/';
    }
    mkdir(partial, STATE_DIRECTORY_MODE);

    return access(directory, F_OK) == 0;
}

static bool filesExist(const char *first_path, const char *second_path)
{
    return access(first_path, R_OK) == 0 && access(second_path, R_OK) == 0;
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

    return writeFileWithMode(key_path, key_pem, key_length, PRIVATE_KEY_FILE_MODE)
        && writeFileWithMode(certificate_path, certificate_pem, certificate_length, CERTIFICATE_FILE_MODE);
}





static bool writeFileWithMode(const char *path, const uint8_t *data, size_t size, mode_t mode)
{
    FILE *file;
    size_t written;
    int32_t fd;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        return false;
    }
    if (fchmod(fd, mode) != 0) {
        close(fd);
        return false;
    }

    file = fdopen(fd, "w");
    if (file == NULL) {
        close(fd);
        return false;
    }

    written = fwrite(data, 1, size, file);
    fclose(file);

    return written == size;
}

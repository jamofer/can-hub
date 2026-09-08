/*
 * AEAD throughput and cross-engine agreement for the picotls stack.
 *
 * Standalone: it links the archives an existing can-hub build tree already
 * produced, so it measures exactly the engines that build would negotiate.
 *
 * Two jobs in one tool, because on a new target both questions are open at the
 * same time: how fast each engine is, and whether it agrees byte for byte with
 * minicrypto, which is the reference every other engine has to match. The
 * agreement check is not decoration — building picotls's AES-NI engines under
 * llvm-mingw produced ciphertext no peer would accept, and nothing but this
 * comparison would have said so before a handshake failed.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <picotls.h>
#include <picotls/minicrypto.h>

#if defined(CAN_HUB_TLS_FUSION)
#include <picotls/fusion.h>
#endif

#include "platform/linux/shared/tls_aead.h"

#define BUDGET_NS 300000000.0
#define SMALL_SIZE 40
#define LARGE_SIZE 1200
#define MAX_SIZE 1200
#define TAG_SIZE 16

static double benchmark(ptls_aead_algorithm_t *algorithm, size_t size);
static int matchesMinicrypto(ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference, size_t size);
static int matchesMinicryptoVectored(ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference);
static void report(const char *name, ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference);

int main(void)
{
#if defined(CAN_HUB_TLS_FUSION)
    printf("fusion supported by cpu: %d, aesni256: ", ptls_fusion_is_supported_by_cpu());
    printf("%d\n", ptls_fusion_can_aesni256);
#else
    printf("built without fusion\n");
#endif
    printf("\n%-32s %9s %9s %10s %9s\n", "engine", "40 B us", "1200 B us", "one-shot", "vectored");
#if defined(CAN_HUB_TLS_FUSION)
    report("fusion aes128gcm (quic)", &ptls_fusion_aes128gcm, &ptls_minicrypto_aes128gcm);
    report("fusion aes256gcm (quic)", &ptls_fusion_aes256gcm, &ptls_minicrypto_aes256gcm);
    report("non-temporal aes128gcm (tls)", &ptls_non_temporal_aes128gcm, &ptls_minicrypto_aes128gcm);
    report("non-temporal aes256gcm (tls)", &ptls_non_temporal_aes256gcm, &ptls_minicrypto_aes256gcm);
#endif
    report("can-hub chacha20poly1305", &can_hub_chacha20poly1305, &ptls_minicrypto_chacha20poly1305);
    report("minicrypto chacha20poly1305", &ptls_minicrypto_chacha20poly1305, &ptls_minicrypto_chacha20poly1305);
    report("minicrypto aes128gcm", &ptls_minicrypto_aes128gcm, &ptls_minicrypto_aes128gcm);
    report("minicrypto aes256gcm", &ptls_minicrypto_aes256gcm, &ptls_minicrypto_aes256gcm);

    return 0;
}

/* ---------- private ---------- */

static double benchmark(ptls_aead_algorithm_t *algorithm, size_t size)
{
    static uint8_t key[32] = { 9 };
    static uint8_t iv[12] = { 7 };
    uint8_t plaintext[MAX_SIZE];
    uint8_t output[MAX_SIZE + TAG_SIZE];
    ptls_aead_context_t *aead = ptls_aead_new_direct(algorithm, 1, key, iv);
    struct timespec start;
    struct timespec end;
    uint32_t rounds = 0;
    double elapsed = 0.0;

    memset(plaintext, 0xA5, sizeof(plaintext));
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (elapsed < BUDGET_NS) {
        ptls_aead_encrypt(aead, output, plaintext, size, rounds, "aad", 3);
        rounds++;
        if ((rounds & 0x3F) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &end);
            elapsed = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    ptls_aead_free(aead);

    return elapsed / rounds / 1000.0;
}

static int matchesMinicrypto(ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference, size_t size)
{
    static uint8_t key[32] = { 9 };
    static uint8_t iv[12] = { 7 };
    uint8_t plaintext[MAX_SIZE];
    uint8_t expected[MAX_SIZE + TAG_SIZE];
    uint8_t produced[MAX_SIZE + TAG_SIZE];
    ptls_aead_context_t *a = ptls_aead_new_direct(reference, 1, key, iv);
    ptls_aead_context_t *b = ptls_aead_new_direct(algorithm, 1, key, iv);
    size_t expected_size;
    size_t produced_size;

    memset(plaintext, 0xA5, sizeof(plaintext));
    memset(expected, 0, sizeof(expected));
    memset(produced, 0, sizeof(produced));
    expected_size = ptls_aead_encrypt(a, expected, plaintext, size, 3, "aad", 3);
    produced_size = ptls_aead_encrypt(b, produced, plaintext, size, 3, "aad", 3);
    ptls_aead_free(a);
    ptls_aead_free(b);

    return expected_size == produced_size && memcmp(expected, produced, expected_size) == 0;
}

/*
 * The TLS record layer encrypts through do_encrypt_v so that the content-type
 * byte need not be copied next to the payload. An engine can be correct in the
 * one-shot path and wrong here, which is what the QUIC-only engine does.
 */
static int matchesMinicryptoVectored(ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference)
{
    static uint8_t key[32] = { 9 };
    static uint8_t iv[12] = { 7 };
    uint8_t body[64];
    uint8_t expected[128];
    uint8_t produced[128];
    uint8_t type = 23;
    ptls_iovec_t input[2];
    ptls_aead_context_t *a = ptls_aead_new_direct(reference, 1, key, iv);
    ptls_aead_context_t *b = ptls_aead_new_direct(algorithm, 1, key, iv);

    memset(body, 0x5A, sizeof(body));
    memset(expected, 0, sizeof(expected));
    memset(produced, 0, sizeof(produced));
    input[0] = ptls_iovec_init(body, sizeof(body));
    input[1] = ptls_iovec_init(&type, 1);
    ptls_aead_encrypt_v(a, expected, input, 2, 5, "aad", 3);
    ptls_aead_encrypt_v(b, produced, input, 2, 5, "aad", 3);
    ptls_aead_free(a);
    ptls_aead_free(b);

    return memcmp(expected, produced, sizeof(body) + 1 + TAG_SIZE) == 0;
}

static void report(const char *name, ptls_aead_algorithm_t *algorithm, ptls_aead_algorithm_t *reference)
{
    const char *one_shot = "reference";
    const char *vectored = "reference";
    double small;
    double large;

    small = benchmark(algorithm, SMALL_SIZE);
    large = benchmark(algorithm, LARGE_SIZE);
    if (algorithm != reference) {
        one_shot = "yes";
        vectored = "yes";
        if (!matchesMinicrypto(algorithm, reference, SMALL_SIZE) || !matchesMinicrypto(algorithm, reference, LARGE_SIZE)) {
            one_shot = "NO";
        }
        if (!matchesMinicryptoVectored(algorithm, reference)) {
            vectored = "NO";
        }
    }

    printf("%-32s %9.3f %9.3f %10s %9s\n", name, small, large, one_shot, vectored);
}

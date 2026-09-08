#pragma once

#include <picotls.h>

/*
 * CHACHA20-POLY1305 with Monocypher's POLY1305 underneath.
 *
 * picotls's minicrypto binding is otherwise fine — its CHACHA20 is in fact
 * slightly faster than Monocypher's — but cifra's POLY1305 dominates the AEAD:
 * measured at 1200 bytes, the whole minicrypto AEAD costs 20.0 us while its
 * CHACHA20 alone costs 1.9 and Monocypher's POLY1305 costs 0.8. Swapping just
 * the authenticator is where the win is, and it leaves the cipher, the nonce
 * construction, the padding and the length encoding to picotls's own
 * CHACHA20-POLY1305 template rather than to code of ours.
 */

extern ptls_aead_algorithm_t can_hub_chacha20poly1305;
extern ptls_cipher_suite_t can_hub_chacha20poly1305sha256;

/*
 * The AES this build uses on QUIC: for the Initial packets, which RFC 9001
 * fixes to AES-128-GCM whatever the connection later negotiates, and for a
 * negotiated AES suite. cifra's constant-time AES costs 2415 us to seal a
 * 1200-byte packet and 31 us for one ECB block of header protection, so an
 * unauthenticated peer can make the hub burn a core with a few Mbit/s of
 * Initial packets. Where picotls's AES-NI engine is available these resolve to
 * it instead; elsewhere they resolve to minicrypto and the exposure stands,
 * which is address validation's job, not the cipher's.
 *
 * Selected once, on first use, and returned as stable pointers because the
 * ngtcp2 backend resolves header protection and the AEAD usage limits by
 * comparing the negotiated algorithm against exactly these.
 */

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void);
ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void);

/*
 * AES-256, which QUIC never uses for Initial packets but may negotiate. It is
 * offered for the policies that require a 256-bit key, not because it is
 * stronger than what TLS 1.3 already gives.
 */

ptls_aead_algorithm_t *TlsAead_Aes256Gcm(void);
ptls_cipher_algorithm_t *TlsAead_Aes256Ecb(void);

/*
 * Which record layer the suites are for. picotls ships two AES-NI engines and
 * they are not interchangeable: ptls_fusion_aes128gcm implements do_encrypt
 * only, which is all QUIC ever calls, and leaves do_encrypt_v as an assertion
 * upstream marked FIXME. The TLS record layer encrypts through do_encrypt_v so
 * that the content-type byte need not be copied next to the payload, so on a
 * release build that assertion is compiled out and the peer rejects the record
 * with a bad record MAC. ptls_non_temporal_aes128gcm is the engine with the
 * vectored path.
 */

typedef enum tls_transport_e {
    kTLS_TRANSPORT_STREAM,
    kTLS_TRANSPORT_QUIC,
    kTLS_TRANSPORT_MAX
} TLS_TRANSPORT;

/*
 * The suites this build offers for a transport, most preferred first,
 * NULL-terminated.
 *
 * AES is offered only where there is a fast AES. In TLS 1.3 the server picks,
 * so a peer that offers AES-128-GCM is telling the other end it may be chosen —
 * and a client without AES-NI that offered it could be pinned to cifra's AES at
 * 2415 us per 1200-byte packet by any server that prefers it. Offering only
 * what we can afford keeps a mixed fleet correct without any capability
 * signalling on the wire.
 */

ptls_cipher_suite_t **TlsAead_CipherSuites(TLS_TRANSPORT transport);

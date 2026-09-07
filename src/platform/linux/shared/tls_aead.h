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
 * AES for QUIC's Initial packets, which RFC 9001 fixes to AES-128-GCM whatever
 * the connection later negotiates. cifra's constant-time AES costs 2415 us to
 * seal a 1200-byte packet and 31 us for one ECB block of header protection, so
 * an unauthenticated peer can make the hub burn a core with a few Mbit/s of
 * Initial packets. Where picotls's AES-NI engine is available these resolve to
 * it instead; elsewhere they resolve to minicrypto and the exposure stands,
 * which is address validation's job, not the cipher's.
 *
 * Selected once, on first use, and returned as stable pointers so identity
 * comparisons keep working.
 */

ptls_aead_algorithm_t *TlsAead_Aes128Gcm(void);
ptls_cipher_algorithm_t *TlsAead_Aes128Ecb(void);

/*
 * The suites this build offers, most preferred first, NULL-terminated.
 *
 * AES is offered only where there is a fast AES. In TLS 1.3 the server picks,
 * so a peer that offers AES-128-GCM is telling the other end it may be chosen —
 * and a client without AES-NI that offered it could be pinned to cifra's AES at
 * 2415 us per 1200-byte packet by any server that prefers it. Offering only
 * what we can afford keeps a mixed fleet correct without any capability
 * signalling on the wire.
 */

ptls_cipher_suite_t **TlsAead_CipherSuites(void);

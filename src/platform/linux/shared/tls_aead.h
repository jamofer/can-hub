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

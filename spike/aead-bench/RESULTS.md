# AEAD bench results — picotls stack

Measures every AEAD engine this build can negotiate, and checks each one against minicrypto
byte for byte. Both questions matter on a new target: how fast the engine is, and whether it
produces what a peer will accept.

## Reading the agreement columns

`one-shot` compares `ptls_aead_encrypt`, which is what QUIC uses. `vectored` compares
`ptls_aead_encrypt_v`, which is what the TLS record layer uses so the content-type byte need
not be copied next to the payload.

`fusion aes128gcm` reporting `NO` under `vectored` is **expected**: upstream leaves
`do_encrypt_v` as an assertion marked FIXME in that engine, which is why it is offered on QUIC
only. A `NO` under `one-shot`, or a `NO` under `vectored` from a non-temporal engine, is a
real defect — that is how the llvm-mingw miscompilation of the 256-bit VAES path was found.

## x86-64 Linux — 2026-09-08

Ubuntu, gcc 13, 8 cores, `-O2`. **Not a quiet host**: a browser at ~20 % CPU and unrelated
containers including one in a crash-restart loop (see #193). Numbers are given as observed
ranges over repeated runs; where the range is wide it is host noise, not engine variance.

An OpenSSL 3.0.13 reference was measured in the same session with the same loop shape, since
"ahead of v0.3.0" has to mean something measured rather than quoted.

| AEAD, one operation | 40 B (CAN frame) | 1200 B (MTU) |
|---|---|---|
| OpenSSL 3.0.13 AES-128-GCM — the reference | 0.182 | 0.284 |
| fusion AES-128-GCM — what QUIC negotiates | **0.025-0.029** | **0.168-0.199** |
| non-temporal AES-128-GCM — what TLS negotiates | **0.038-0.197** | **0.194-0.281** |
| fusion AES-256-GCM — QUIC | 0.028-0.031 | 0.196-0.218 |
| non-temporal AES-256-GCM — TLS | 0.040-0.434 | 0.243-0.676 |
| can-hub CHACHA20-POLY1305 (Monocypher POLY1305) | 0.325 | 2.739 |
| minicrypto CHACHA20-POLY1305 (cifra POLY1305) | 1.03-1.05 | 12.4-13.3 |
| minicrypto AES-128-GCM (cifra, no AES-NI) | 147-161 | 2248-2472 |
| minicrypto AES-256-GCM (cifra, no AES-NI) | 201-214 | 3091-3382 |

Every engine agreed with minicrypto except the two documented `vectored` gaps above.

Reading it: with AES-NI both transports are ahead of the OpenSSL reference — QUIC by about 7x
at CAN frame size, TLS by about 4x at its best and at parity at its worst. The AES-128 rows
are the ones that matter; AES-256 is offered for policies that require a 256-bit key.

cifra's AES is 5 800x slower than the AES-NI path at MTU size. That is the whole reason AES is
offered only where there is a fast AES, and why every target without one stays on CHACHA20.

## Windows x86-64 (llvm-mingw), under wine — 2026-09-08

Not timed; run for agreement only, which is what it found.

| Engine | one-shot | vectored |
|---|---|---|
| fusion AES-128-GCM | match | n/a (upstream FIXME) |
| non-temporal AES-128-GCM, `ptls_fusion_can_aesni256 = 1` | **MISMATCH** | **MISMATCH** |
| non-temporal AES-128-GCM, `ptls_fusion_can_aesni256 = 0` | match | match |

The same source built with gcc on Linux matches in every combination. `cmake/picotls.cmake`
therefore forces the 128-bit path on Windows.

## arm64 / armv7 — correct, speed unknown

Run under qemu (`docker --platform linux/arm64` and `linux/arm/v7`, Debian bookworm, native
gcc in the container), 2026-09-08. **Agreement only** — emulated timings are not reported here
because they measure qemu, not the target.

| Engine | one-shot | vectored |
|---|---|---|
| `can-hub chacha20poly1305`, aarch64 | match | match |
| `can-hub chacha20poly1305`, armv7l | match | match |

So the Monocypher POLY1305 binding is correct on both, which had never been checked. fusion is
x86-64 only and picotls ships no ARM AES engine, so ChaCha20-Poly1305 is the whole story there.

**Throughput still needs hardware.** On the target:

    make BUILD=<can-hub build tree> FUSION=0 && ./aead_bench

and compare against OpenSSL's ChaCha20-Poly1305 and AES-128-GCM on the same CPU. Check
`/proc/cpuinfo` for `aes` and `pmull` first: the ARMv8 crypto extensions are optional, and the
answer depends on them. Where they are present OpenSSL uses hardware AES and we do not, which
is the worst case for this stack; where they are absent OpenSSL also falls back to software and
we may well be ahead. Measure on hardware representative of the fleet, not on whatever is
nearest.

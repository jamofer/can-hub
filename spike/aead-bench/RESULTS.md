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

## arm64 — Raspberry Pi 5, 2026-09-08

Cortex-A76, Debian bookworm, gcc, load average 0.37. **This CPU has the ARMv8 crypto
extensions** (`aes pmull sha1 sha2` in `/proc/cpuinfo`), so OpenSSL uses hardware AES here and
this stack does not — the worst case for us, and the right place to look first.

Four consecutive runs of our bench landed within 0.5 %: 0.740-0.744 µs and 6.80-6.85 µs. A
quiet host measures cleanly, which the development machine does not (#193).

| AEAD, one operation | 40 B (CAN frame) | 1200 B (MTU) |
|---|---|---|
| **can-hub CHACHA20-POLY1305** — what an ARM build negotiates | **0.742** | **6.82** |
| minicrypto CHACHA20-POLY1305 (cifra POLY1305) | 2.268 | 30.005 |
| minicrypto AES-128-GCM (cifra) | 257.6 | 3 953 |
| minicrypto AES-256-GCM (cifra) | 357.9 | 5 505 |
| OpenSSL 3.5.4 CHACHA20-POLY1305 | 0.220 | 2.053 |
| OpenSSL 3.5.4 AES-128-GCM (hardware) | 0.349 | 0.843 |
| OpenSSL 3.5.4 AES-256-GCM (hardware) | 0.358 | 0.978 |

OpenSSL figures are `openssl speed -evp <alg> -bytes <n>` converted from bytes/s, because the
target has no OpenSSL headers and nothing was installed on it. That harness does slightly less
per operation than `ptls_aead_encrypt`, so it is a lower bound on OpenSSL's cost — the gap
below is an upper bound on ours.

**Reading it:** against OpenSSL's best on this CPU we are **3.4x slower at CAN frame size** and
**8.1x at MTU**. The Monocypher POLY1305 binding is still what makes it bearable: it is 3.1x
faster than stock minicrypto at 40 B and 4.4x at 1200 B. cifra's AES is unusable, at 5 300x
OpenSSL's hardware AES for a 1200-byte record — which is why AES is never offered here.

**And the absolute numbers matter more than the ratio.** 0.742 µs/frame is 1.35 M frames/s per
core; a saturated 1 Mbit/s CAN bus is about 8 700 frames/s, so one Pi 5 core covers roughly 150
fully loaded buses' worth of AEAD. Being 3.4x behind OpenSSL is not a constraint on any CAN
workload. It would start to matter for a hub aggregating hundreds of buses, or for sustained
bulk transfer at MTU.

**The number that does have a consequence** is cifra's AES at 3 953 µs per 1200-byte record.
RFC 9001 fixes AES-128-GCM for QUIC Initial packets, so a hub on this hardware spends that on
every connection attempt, from any unauthenticated peer: one core is saturated by about 250
Initial packets per second. On an ARM hub, QUIC address validation is not an optimisation.

## armv7 — correct, speed not measured

Run under qemu (`docker --platform linux/arm/v7`, Debian bookworm, native gcc in the
container). **Agreement only** — emulated timings measure qemu, not the target.

| Engine | one-shot | vectored |
|---|---|---|
| `can-hub chacha20poly1305`, armv7l | match | match |
| `can-hub chacha20poly1305`, aarch64 (also checked this way) | match | match |

To measure a real armv7 target, copy the sources and build with plain gcc — no cmake needed:
the file list is in `spike/aead-bench/` history, or use the tree's build with
`make BUILD=<can-hub build tree> FUSION=0`.

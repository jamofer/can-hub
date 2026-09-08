# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CAN-over-network hub in C11. Devices behind NAT export SocketCAN interfaces to a central hub over QUIC (mTLS); clients consume them through the hub or P2P. Binaries: `can-hub` (hub), `can-hub-agent` (device daemon), `can-hub-cli` (admin), `can-hub-client` (reference consumer). Design source of truth: `doc/design.md` and `doc/protocol.md`; user-facing docs live in `doc/` (index: `doc/README.md`). Pending work is tracked as GitHub issues; `TODO.md` is the historical decision log only.

## Commands

Make wraps cmake (see `Makefile`):

```sh
make release            # -O2 build into build/x86_64/release (ARCH=arm64|armhf for cross)
make debug              # -O0 -g
make test               # build + run all unit tests (CEST, host x86_64)
make clean
```

`make test` builds `test/` into `build/test/` and runs them with `test/vendor/cest-runner_linux_x86_64` under `setarch -R` — the runner is an ASan build and ASan shadow memory collides with high-entropy mmap ASLR on kernels >= 6.5. Do not remove that workaround.

Run a single test: build with `make test` (or `cmake --build build/test`), then execute the test binary directly:

```sh
./build/test/unit/test_broker
```

New tests are registered in `test/unit/CMakeLists.txt` with `add_unit_test(<name> SOURCES <test.cpp> <real_src.c ...>)` — each test links the real sources it exercises (no production library target). Mocks for ports live in `test/mocks/`.

ngtcp2 v1.23.0 (static) and the SQLite amalgamation (sha256-pinned zip from sqlite.org) are pulled via FetchContent; picotls and Monocypher are cloned at pinned commits and built once per build tree at configure time (cmake/picotls.cmake, cmake/monocypher.cmake). First configure needs network. ngtcp2's picotls crypto backend is retargeted from picotls's OpenSSL binding to its minicrypto one by cmake/ngtcp2_picotls_minicrypto.cmake, which regenerates it at configure time and fails loudly if upstream changes shape. There is no OpenSSL anywhere. Two picotls sources are patched at configure time for llvm-mingw (cifra's `_BitScanReverse` branch and fusion's MSVC `__cpuid` probe), both behind guards that fail loudly; on Windows the build also forces `ptls_fusion_can_aesni256 = 0`, because fusion's 256-bit VAES path miscompiles there (see MIGRATION_PICOTLS.md §19). The test project (test/CMakeLists.txt) fetches SQLite separately.

## Architecture

Layered, ports & adapters, with a hard portability rule: **everything outside `src/platform/` is freestanding** — no POSIX, no heap, no syscalls, no file descriptors — so agent core compiles on a microcontroller as-is. Nothing outside `platform/` may include anything from it.

Layout is context-first: one directory per bounded context (`src/agent/`, `src/hub/`), shared `src/protocol/`.

- `src/protocol/` — wire format encode/decode. Binary, little-endian, fixed layouts at known offsets with explicit reserved padding (decode is a bounds check + overlay, no parsing loops). One module per message type (`hello_message`, `register_message`, ...). Spec in `doc/protocol.md`.
- `src/agent/` — device-side core: `agent.c` + `agent_app.c` wiring, `domain/` (`channel_map`, `reconnect_backoff`, `echo_correlator`), `ports/` (`TransportPort`/`TransportEvents`, `CanPort`/`CanEvents`). Events pushed in, time injected (`Agent_Tick(now_us)`).
- `src/hub/` — hub-side core: `broker.c` + `hub_app.c` wiring, `domain/` (`interface_registry`, `frame_routes`, `client_session`, `peer_directory`, `hub_peer`, `admin_views`), `ports/` (`HubTransportPort`/`HubTransportEvents`, `IdentityStorePort`).
- Ports are contracts owned by the core, both directions: outbound Port structs of function pointers the core calls, inbound Events structs the core implements.
- `src/platform/linux/` — adapters (epoll, ngtcp2 QUIC, picotls TLS-over-TCP, SocketCAN, plain TCP) and the concrete `*_main.c` entry points. `src/platform/windows/` — winsock adapters for the libcanhub Windows port (tcp/tls + WSAPoll pump, `make windows`); OS-agnostic modules (framer, TLS channel/securities, client core) are reused from the linux tree. Deliberately concrete. `shared/` holds main-loop helpers (`connect_url`, `epoll_registry`, `message_framer`, `tls_identity`, `pin_store`, `pinned_server_verifier`); `quic/quic_egress.c` is the egress pump shared by client and server QUIC transports; `tls/tls_channel.c` is the nonblocking record pump shared by the TLS client and server: it owns no socket and makes no syscall, so the transports move the bytes and it is unit-testable without a network. Crypto lives in `shared/tls_defaults.c` (the picotls profile), `shared/tls_aead.c` (CHACHA20-POLY1305 over Monocypher's POLY1305, plus the AES engines), `shared/tls_ed25519.c` (signing and verification over Monocypher) and `shared/tls_identity_ed25519.c` (self-signed certificate minting through our own DER encoder). The offered cipher suites are **per transport**: `TlsDefaults_Init*Profile` and `TlsAead_CipherSuites` take a `TLS_TRANSPORT`, because picotls's two AES-NI engines are not interchangeable — `ptls_fusion_aes128gcm` implements only the one-shot path QUIC uses and leaves `do_encrypt_v` as an upstream assertion, while the TLS record layer encrypts through `do_encrypt_v`. Getting that wrong is a bad record MAC on a release build, not a compile error. AES is offered only where `ptls_fusion_is_supported_by_cpu()` says there is a fast AES (x86-64), so no peer can be pinned to cifra's constant-time AES; everywhere else the only suite is CHACHA20-POLY1305.

Two planes on the wire: control (reliable QUIC stream / the TCP connection) and data (QUIC datagrams, latest-wins; over TCP shares the stream). Identity is the TLS fingerprint — never sent per message. Data plane demultiplexes by connection-scoped u8 **channel** (assigned by REGISTER_ACK / OPEN), not by global interface id. Adding a transport must not touch the domain.

Hub defaults: always-on unix socket (`/run/can-hub/hub.sock`, one socket for wire protocol and admin, demuxed by HELLO role) plus quic://0.0.0.0:7227 (UDP), tls://0.0.0.0:7227 (TCP) and plain tcp://127.0.0.1:7228 (TLS identity auto-generated under the state dir when `--cert`/`--key` are absent, shared by quic and tls; TOFU pinning both sides, mTLS client certs required on the encrypted transports, see doc/design.md Identity). `--listen <scheme>://[<bind-ip>:]<port>` overrides the network defaults (plain tcp defaults to loopback; expose it with an explicit bind). agent and client both speak quic/tls/tcp; client adds unix and connects to the unix socket when `--connect` is omitted. The QUIC server transport demuxes peers by DCID (original DCID + live SCIDs), so client migration/NAT rebinding survive; the remote address follows the latest packet. Hub peer_id ranges per transport are hardcoded in `hub_main.c` (tcp 0x1, unix 0x40000001, quic 0x80000001, tls 0xC0000001).

Agent allowlist: default is TOFU; `--require-known-agents` rejects fingerprints not pinned (quic/tls only). Enrollment is authorized_keys-style: `can-hub-agent --show-identity` prints the fingerprint, `can-hub-cli pins add <name> <fingerprint>` authorizes it. The agent's ED25519 identity (`agent.crt`/`agent.key`) lives in the state dir and is stable across restarts. When the broker initiates a close (reject/kick), it must release the peer itself via `disconnectPeer` — the transport's broker-initiated close does not fire `on_peer_disconnected`.

Client ACLs (AuthorizationPort, SQLite client_acls): grants keyed by client fingerprint (subject) + namespaced interface `agent/iface` (object), `*` wildcard on any of the three, level none/ro/rw (`can_read`/`can_write`). Resolution most-specific-wins, subject dominating (fingerprint beats `*`, then exact > `agent/*` > `*/*`); no match → read-open, no-write. Broker enforces at OPEN (`OPEN_STATUS_READ_DENIED`/`WRITE_DENIED`) and drops unauthorized client FRAMEs (the real boundary). Plaintext/unix clients carry no fingerprint, trusted full read+write. Admin family 0x24-0x29; `can-hub-cli acl add|delete|list`, `can-hub-client --show-identity`.

## Code style

`CODE_STYLE.md` is mandatory — read it before writing C. Highlights that differ from common habits:

- Public functions `Module_PascalFunction` (in the `.h`); private functions `camelCase` `static`, prototypes at top of `.c`, definitions at the end — public API first.
- No `int`/`long`/`unsigned`: fixed-width `<stdint.h>` types only. `size_t`/`int` only at OS boundaries; fds stored as `int32_t`.
- Enums: tag `tname_e`, members `kNAME_VALUE`, typedef `TNAME`, trailing `kNAME_MAX` sentinel.
- Bounded scalars are plain integers, never one-field structs or `*_Make` wrappers; validate with guard clauses at the boundary.
- Guard clauses first, flat happy path, declarations at top of function (C89 style).
- K&R braces for control flow, Allman for functions. Compact `for(i=0; i<n; i++)` headers.
- Avoid comments — extract a named private function instead; only the non-obvious *why* is acceptable.
- No abbreviations (`message` not `msg`, `buffer` not `buf`); known acronyms (CAN, TLS, QUIC, id) fine.
- No magic numbers; no column alignment (except `#define` values).

Tests are C++20 with CEST (`#include <cest>`, `describe`/`it`/`expect().toBe()`), wrapping the C headers in `extern "C"`.

# can-hub

CAN bus over the network, done right. Devices behind NAT export their
SocketCAN interfaces to a central hub over QUIC with mutual TLS; clients
anywhere consume them with the tools they already use. A modern alternative
to socketcand and cannelloni.

```
[can-hub-agent] --quic/tls/tcp--> [can-hub] <--quic/tls/tcp/unix-- [can-hub-client]
   truck42                          the hub                          anywhere
   can0, can1                                                        list / dump / send
                                    [can-hub-cli] [can-hub-web]
                                    admin on the hub host
```

## Why

- **Works through NAT and firewalls.** Agents and clients both dial out;
  the hub rendezvous in the middle. No port forwarding on the device side.
- **Zero-config security.** Self-signed ED25519 identities generated on
  first start, trust-on-first-use pinning on both sides, client
  certificates required on the encrypted transports. The TLS fingerprint is
  the device identity — impostors are rejected, not just logged.
- **The right transport for CAN.** Control rides reliable QUIC streams;
  frames ride QUIC datagrams — latest-wins, no head-of-line blocking. A
  lost cyclic frame is repaired by the next cycle, not retransmitted late.
- **Physical-bus semantics.** Injected frames become visible to the other
  subscribers through their real bus echo: if the TX never reached the
  wire, nobody is lied to, and ordering is the bus ordering.
- **Fleet-shaped, not link-shaped.** One hub, many agents, a queryable
  catalogue (`truck42/can0`), per-peer and per-interface traffic counters,
  and an admin plane with a CLI and a web panel.
- **Small enough for the edge.** No OpenSSL: the TLS 1.3 and QUIC stack is
  picotls with permissively licensed primitives, statically linked. The
  fully static musl agent is **~590 KB** on arm64 and armv7 with no runtime
  dependencies at all, and its `.deb` is ~310 KB. Where the CPU has AES-NI
  the handshake and data plane use it.
- **Freestanding core.** Everything outside `src/platform/` is C11 without
  POSIX, heap or syscalls — the agent core compiles for microcontrollers
  as-is.

## Quickstart

```sh
# hub host (defaults: quic://7227 UDP, tls://7227 TCP, local unix socket)
can-hub

# device — identity auto-generated, hub pinned on first contact
can-hub-agent --connect quic://hub.example.com:7227 --name truck42 can0 can1

# anywhere
can-hub-client --connect tls://hub.example.com:7227 list
can-hub-client --connect tls://hub.example.com:7227 dump truck42/can0
can-hub-client --connect tls://hub.example.com:7227 send truck42/can0 123#DEADBEEF
```

No CAN hardware? The [quick start](doc/quick-start.md) runs the same thing
against a `vcan` on one machine.

## The pieces

| Binary | Role | Docs |
|---|---|---|
| `can-hub` | the hub: registry, frame relay, admin plane | [doc/hub.md](doc/hub.md) |
| `can-hub-agent` | device daemon: exports local SocketCAN interfaces | [doc/agent.md](doc/agent.md) |
| `can-hub-client` | consumer: `list`, `dump`, `send`, `socketcand`, `attach` | [doc/client.md](doc/client.md) |
| `can-hub-cli` | hub administration over the local unix socket | [doc/cli.md](doc/cli.md) |
| `can-hub-web` | web admin panel: REST API + live telemetry | [doc/web.md](doc/web.md) |

And beyond the binaries:

- **socketcand bridge** — use remote buses from python-can, Kayak or
  SavvyCAN with no can-hub awareness ([doc/client.md](doc/client.md)).
- **`attach`** — mirror a remote bus into a local `vcan`, so `candump`,
  Wireshark and friends work unmodified ([doc/client.md](doc/client.md)).
- **python** — `pip install python-can-hub`, a native python-can backend
  with all transports including QUIC ([python/README.md](python/README.md)).
- **libcanhub** — embeddable C client library, Linux and Windows
  ([doc/libcanhub.md](doc/libcanhub.md)).
- **Security** — TOFU by default; agent allowlisting and per-client
  read/write ACLs when you want them ([doc/security.md](doc/security.md)).

## Install

Releases ship static per-arch Debian packages and tarballs (x86_64, arm64,
armv7) plus python wheels on PyPI — see
[doc/installation.md](doc/installation.md). From source:

```sh
make release            # cmake+ninja+gcc; first configure needs network
make test
```

## Status

Pre-1.0. The wire protocol is version 0 and may change until v1 is frozen
(see [doc/protocol.md](doc/protocol.md)). Designed for telemetry,
diagnostics and bus replication — explicitly **not** for control loops over
the WAN.

## Documentation

Start at the [documentation index](doc/README.md). Architecture and
decisions: [doc/design.md](doc/design.md). Wire protocol (CC-BY-4.0,
independent implementations welcome): [doc/protocol.md](doc/protocol.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed: [AGPL-3.0](LICENSE) for everyone, with a
[commercial license](LICENSE.commercial) available for proprietary use.

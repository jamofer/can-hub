# Installation

## Debian packages (from releases)

Every [release](https://github.com/can-hub-io/can-hub/releases) ships
per-architecture `.deb` packages (x86_64, arm64, armv7), statically linked —
no runtime dependencies:

| Package | Contents |
|---|---|
| `can-hub` | hub daemon **and `can-hub-cli`**, `can-hub.service` (enabled and started on install), `/etc/can-hub/hub.conf`, dedicated `can-hub` system user |
| `can-hub-agent` | SocketCAN exporter, `can-hub-agent.service` (installed but not started until configured), `/etc/can-hub/agent.conf`, state in `/var/lib/can-hub-agent` |
| `can-hub-client` | reference consumer, plus an optional `can-hub-socketcand.service` bridge (not started by default), `/etc/can-hub/socketcand.conf` |

The web admin panel (`can-hub-web`) is built from source for now — see
[web admin](web.md).

### Hub

```sh
sudo dpkg -i can-hub_*.deb        # service starts immediately
```

**The packaged hub does not use the bare-binary defaults**: `hub.conf` ships
`--listen quic://0.0.0.0:7227 --listen unix:///run/can-hub/hub.sock` — QUIC
plus the local unix socket only. To also accept TLS-over-TCP or plaintext
TCP, add listeners in `/etc/can-hub/hub.conf` and
`systemctl restart can-hub`:

```sh
HUB_LISTEN_ARGS=--listen quic://0.0.0.0:7227 --listen tls://0.0.0.0:7227 --listen unix:///run/can-hub/hub.sock
```

### Agent

```sh
sudo dpkg -i can-hub-agent_*.deb
sudo editor /etc/can-hub/agent.conf      # HUB_URL, INTERFACES; AGENT_NAME defaults to the hostname
sudo systemctl enable --now can-hub-agent
```

The unit runs as the `can-hub` user with `CAP_NET_RAW` only. Remote
interface reconfiguration (`can-hub-cli interface set ...`) additionally
needs `CAP_NET_ADMIN` — see [agent](agent.md#capabilities).

### socketcand bridge (optional)

The client package includes a service that exposes the hub's interfaces as
a local socketcand server (for python-can, Kayak, SavvyCAN):

```sh
sudo editor /etc/can-hub/socketcand.conf   # defaults: 127.0.0.1:29536, beacon on
sudo systemctl enable --now can-hub-socketcand
```

## Static binaries (from releases)

`can-hub-<tag>-linux-<arch>-static.tar.gz` contains all four binaries, fully
static (musl) — drop them on any Linux, including distros the debs do not
target:

```sh
tar xzf can-hub-v*-linux-x86_64-static.tar.gz
./can-hub-agent --connect quic://hub.example.com:7227 --name edge can0
```

## Python

```sh
pip install python-can-hub
```

Manylinux wheels for x86_64, aarch64 and armv7l, plus a win_amd64 wheel; the
wheel bundles `libcanhub` with the TLS/QUIC stack statically linked. See
[python/README.md](../python/README.md).

## From source

Requirements: cmake >= 3.16, ninja, gcc, git. The first configure needs
network access — picotls and Monocypher are cloned and built once per build
tree, and ngtcp2 plus the SQLite amalgamation are fetched and built
statically. There is no OpenSSL: perl is no longer needed and nothing links
libssl or libcrypto.

```sh
make release                  # build/x86_64/release
make install [PREFIX=/usr/local]
make test                     # unit tests (CEST)
```

`make install` installs the four binaries, `libcanhub` (static + shared) and
`include/canhub.h` — no systemd units; use the debs for service deployment.

Other targets:

```sh
make release ARCH=arm64|armhf   # cross builds (toolchain files in cmake/)
make deb                        # glibc .debs into build/<arch>/package
make static ARCH=x86_64|arm64|armv7   # fully static binaries via docker, into dist/
make windows                    # libcanhub + canhub-dump for Windows (llvm-mingw / mingw-w64)
```

## Shell completion

The Debian packages ship bash and zsh completions for every binary, so tab
completion works out of the box after `apt install` (bash-completion loads them
on demand; zsh reads `/usr/share/zsh/vendor-completions`). Beyond subcommands
and flags they complete the painful dynamic values — namespaced interface names
(`agent/iface`), agent names and peer ids — by querying the hub, and fall back
to static completion when it is unreachable.

Building from source instead of installing a deb? Drop the scripts in by hand:

```sh
sudo cp packaging/completions/bash/* /usr/share/bash-completion/completions/
sudo cp packaging/completions/zsh/_*  /usr/share/zsh/vendor-completions/
```

## State directories

| Component | Default | Contents |
|---|---|---|
| hub | `/var/lib/can-hub` (fallback `~/.local/state/can-hub`) | TLS identity, `hub.db` (agent pins, client ACLs) |
| agent | `/var/lib/can-hub-agent` (deb) or the same default | `agent.crt`/`agent.key`, `known_hubs` pins |
| client | `/var/lib/can-hub` (fallback `~/.local/state/can-hub`) | TLS identity, pinned hub fingerprints |
| web | `/var/lib/can-hub/web.db` | users, groups, sessions, audit log |

`--state-dir` overrides the location on hub, agent and client.

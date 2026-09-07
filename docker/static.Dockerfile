# Fully static can-hub binaries (hub, agent, client, cli) against musl.
# Every dependency is built from source into the build tree. Zero runtime
# dependencies: the binaries run
# on any Linux of the right architecture regardless of the distro, its libc
# or its package set (embedded boards, vendor OSes, old installations).
#
# Architecture is selected with one build arg; the toolchain pins live here:
#
#   docker build -f docker/static.Dockerfile --build-arg ARCH=armv7 --output dist/armv7 .
#   make static ARCH=armv7|arm64|x86_64
#
# Every download is sha256-pinned.

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates cmake curl file gcc g++ git m4 make ninja-build perl pkg-config xz-utils \
    && rm -rf /var/lib/apt/lists/*

ARG ARCH=armv7
ARG BOOTLIN=https://toolchains.bootlin.com/downloads/releases/toolchains
ARG BOOTLIN_RELEASE=stable-2025.08-1

RUN case "$ARCH" in \
        armv7) \
            echo "TOOLCHAIN_URL=$BOOTLIN/armv7-eabihf/tarballs/armv7-eabihf--musl--$BOOTLIN_RELEASE.tar.xz" >> /etc/static-build.env; \
            echo "TOOLCHAIN_SHA256=2f3a34458c3a8b961bd09f89669130fcdc4c1dbc6e31ada720527e4ad3741c11" >> /etc/static-build.env; \
            echo "CROSS_TRIPLET=arm-buildroot-linux-musleabihf" >> /etc/static-build.env; \
            echo "PROCESSOR=arm" >> /etc/static-build.env; \
            echo "DEB_ARCH=armhf" >> /etc/static-build.env; \
            echo "RUST_TARGET=armv7-unknown-linux-musleabihf" >> /etc/static-build.env; \
            echo "RUST_STD_SHA256=18a10d9a1a78d91eca8e378ed87e4d754704ec2f7d5a5bcaa878b629c0e426f8" >> /etc/static-build.env;; \
        arm64) \
            echo "TOOLCHAIN_URL=$BOOTLIN/aarch64/tarballs/aarch64--musl--$BOOTLIN_RELEASE.tar.xz" >> /etc/static-build.env; \
            echo "TOOLCHAIN_SHA256=defba831ffa1175236f137069333e21ed46d4d19feb5080a90cf248b6fc2cb08" >> /etc/static-build.env; \
            echo "CROSS_TRIPLET=aarch64-buildroot-linux-musl" >> /etc/static-build.env; \
            echo "PROCESSOR=aarch64" >> /etc/static-build.env; \
            echo "DEB_ARCH=arm64" >> /etc/static-build.env; \
            echo "RUST_TARGET=aarch64-unknown-linux-musl" >> /etc/static-build.env; \
            echo "RUST_STD_SHA256=e7d89a29abcc2cf2f31cfe3d898c1713fb12f395e788809d3b01b23fdd5813b4" >> /etc/static-build.env;; \
        x86_64) \
            echo "TOOLCHAIN_URL=$BOOTLIN/x86-64/tarballs/x86-64--musl--$BOOTLIN_RELEASE.tar.xz" >> /etc/static-build.env; \
            echo "TOOLCHAIN_SHA256=09fca3aa89540f1b01b5f4210d488cbeb00f522044c53e9989b1dd8a38076912" >> /etc/static-build.env; \
            echo "CROSS_TRIPLET=x86_64-buildroot-linux-musl" >> /etc/static-build.env; \
            echo "PROCESSOR=x86_64" >> /etc/static-build.env; \
            echo "DEB_ARCH=amd64" >> /etc/static-build.env; \
            echo "RUST_TARGET=x86_64-unknown-linux-musl" >> /etc/static-build.env; \
            echo "RUST_STD_SHA256=4db24564076c243b377585bec0b938388638301ea5003d6245c4cbf9d86b11d0" >> /etc/static-build.env;; \
        *) echo "unsupported ARCH '$ARCH' (armv7, arm64, x86_64)" >&2; exit 1;; \
    esac

RUN . /etc/static-build.env \
    && curl -fsSL -o /tmp/toolchain.tar.xz "$TOOLCHAIN_URL" \
    && echo "$TOOLCHAIN_SHA256  /tmp/toolchain.tar.xz" | sha256sum -c \
    && mkdir /opt/toolchain \
    && tar -xf /tmp/toolchain.tar.xz --strip-components=1 -C /opt/toolchain \
    && rm /tmp/toolchain.tar.xz

ENV PATH=/opt/toolchain/bin:$PATH
# Node and Rust for the can-hub-web admin panel (Rust daemon, embedded React
# SPA). Host tools are x86_64 (the build runs on amd64); the daemon is
# cross-compiled to the musl RUST_TARGET, reusing the Bootlin musl gcc as the
# C compiler for rusqlite's bundled SQLite. Both downloads are sha256-pinned.
ARG NODE_VERSION=22.22.3
ARG NODE_SHA256=2e5d13569282d016861fae7c8f935e741693c269101a5bebcf761a5376d1f99f
RUN curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
    && echo "$NODE_SHA256  /tmp/node.tar.xz" | sha256sum -c \
    && mkdir /opt/node && tar -xf /tmp/node.tar.xz --strip-components=1 -C /opt/node \
    && rm /tmp/node.tar.xz
ENV PATH=/opt/node/bin:$PATH

ARG RUST_VERSION=1.96.0
ARG RUST_SHA256=c295047583a56238ea06b43f849f4b877fa12bfd4c7103f8d9a74c94c9c4e108
RUN curl -fsSL -o /tmp/rust.tar.xz "https://static.rust-lang.org/dist/rust-$RUST_VERSION-x86_64-unknown-linux-gnu.tar.xz" \
    && echo "$RUST_SHA256  /tmp/rust.tar.xz" | sha256sum -c \
    && mkdir /tmp/rust && tar -xf /tmp/rust.tar.xz --strip-components=1 -C /tmp/rust \
    && /tmp/rust/install.sh --prefix=/opt/rust \
        --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu \
    && rm -rf /tmp/rust /tmp/rust.tar.xz
ENV PATH=/opt/rust/bin:$PATH
RUN . /etc/static-build.env \
    && curl -fsSL -o /tmp/rust-std.tar.xz "https://static.rust-lang.org/dist/rust-std-$RUST_VERSION-$RUST_TARGET.tar.xz" \
    && echo "$RUST_STD_SHA256  /tmp/rust-std.tar.xz" | sha256sum -c \
    && mkdir /tmp/rust-std && tar -xf /tmp/rust-std.tar.xz --strip-components=1 -C /tmp/rust-std \
    && /tmp/rust-std/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/rust-std /tmp/rust-std.tar.xz

COPY . /src

# Cross-compile the web admin panel to the musl target. The Bootlin musl gcc
# compiles rusqlite's bundled SQLite and links the fully static binary.
RUN . /etc/static-build.env \
    && cd /src/web/ui && npm ci && npm run build \
    && cd /src/web/daemon \
    && cc_target="$(echo "$RUST_TARGET" | tr '-' '_')" \
    && export "CC_$cc_target=$CROSS_TRIPLET-gcc" \
    && export "AR_$cc_target=$CROSS_TRIPLET-ar" \
    && export "CARGO_TARGET_$(echo "$RUST_TARGET" | tr 'a-z-' 'A-Z_')_LINKER=$CROSS_TRIPLET-gcc" \
    && cargo build --release --target "$RUST_TARGET" --features embed-ui \
    && $CROSS_TRIPLET-strip "target/$RUST_TARGET/release/can-hub-web" \
    && file "target/$RUST_TARGET/release/can-hub-web" \
    && file "target/$RUST_TARGET/release/can-hub-web" | grep -qE "statically linked|static-pie linked" \
    && mkdir /web-out && cp "target/$RUST_TARGET/release/can-hub-web" /web-out/can-hub-web
RUN . /etc/static-build.env \
    && export CAN_HUB_CROSS_TRIPLET=$CROSS_TRIPLET CAN_HUB_PROCESSOR=$PROCESSOR \
    && cmake -S /src -B /build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=/src/cmake/toolchain-musl-static.cmake \
        -DCAN_HUB_STATIC=ON \
        -DCAN_HUB_PACKAGING=ON \
        -DCAN_HUB_DEB_STATIC=ON \
        -DCAN_HUB_DEB_ARCH=$DEB_ARCH \
        -DCAN_HUB_WEB_BINARY=/web-out/can-hub-web \
    && cmake --build /build --target can-hub can-hub-agent can-hub-client can-hub-cli \
    && $CROSS_TRIPLET-strip /build/can-hub /build/can-hub-agent /build/can-hub-client /build/can-hub-cli \
    && file /build/can-hub /build/can-hub-agent /build/can-hub-client /build/can-hub-cli \
    && ls -la /build/can-hub /build/can-hub-agent /build/can-hub-client /build/can-hub-cli \
    && file /build/can-hub | grep -q "statically linked" \
    && file /build/can-hub-agent | grep -q "statically linked" \
    && file /build/can-hub-client | grep -q "statically linked" \
    && file /build/can-hub-cli | grep -q "statically linked" \
    && mkdir /out \
    && ( cd /build && cpack -G DEB -B /out ) \
    && ls -la /out/*.deb

FROM scratch AS artifact
COPY --from=build /build/can-hub /can-hub
COPY --from=build /build/can-hub-agent /can-hub-agent
COPY --from=build /build/can-hub-client /can-hub-client
COPY --from=build /build/can-hub-cli /can-hub-cli
COPY --from=build /web-out/can-hub-web /can-hub-web
COPY --from=build /out/*.deb /

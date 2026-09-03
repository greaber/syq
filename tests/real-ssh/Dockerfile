# syntax=docker/dockerfile:1

FROM rust:1.94.1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY schemas ./schemas
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --bin syq \
    && cp target/debug/syq /tmp/syq

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        diffutils \
        iptables \
        iproute2 \
        netcat-openbsd \
        openssh-client \
        openssh-server \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 syq \
    && useradd --uid 1000 --gid syq --create-home --shell /bin/sh syq \
    && passwd --delete syq \
    && install -d -m 0700 -o syq -g syq /home/syq/.ssh \
    && install -d -m 0755 /run/sshd

COPY --from=builder /tmp/syq /usr/local/bin/syq
COPY --chmod=0755 tests/real-ssh/entrypoint.sh /usr/local/libexec/syq-real-ssh-entrypoint
COPY --chmod=0755 tests/real-ssh/scenarios.sh /usr/local/libexec/syq-real-ssh-scenarios
COPY tests/real-ssh/sshd_config /etc/ssh/sshd_config

ENTRYPOINT ["/usr/local/libexec/syq-real-ssh-entrypoint"]

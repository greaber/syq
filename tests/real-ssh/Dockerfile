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
        dbus \
        libnotify-bin \
        fish \
        iptables \
        iproute2 \
        netcat-openbsd \
        openssh-client \
        openssh-server \
        procps \
        perl \
        python3 \
        python3-dbus \
        python3-gi \
        zsh \
        rsync \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 syq \
    && useradd --uid 1000 --gid syq --create-home --shell /bin/sh syq \
    && passwd --delete syq \
    && install -d -m 0700 -o syq -g syq /home/syq/.ssh \
    && install -d -m 0755 /run/sshd

COPY --from=builder /tmp/syq /usr/local/bin/syq
COPY --chmod=0755 tests/real-ssh/ssh-wrapper.sh /usr/local/bin/ssh
COPY --chmod=0755 tests/real-ssh/entrypoint.sh /usr/local/libexec/syq-real-ssh-entrypoint
COPY --chmod=0755 tests/real-ssh/scenarios.sh /usr/local/libexec/syq-real-ssh-scenarios
COPY --chmod=0755 scripts/try-benchmark.sh /usr/local/libexec/syq-try-benchmark
COPY tests/real-ssh/sshd_config /etc/ssh/sshd_config

COPY tests/real-ssh/test-completion-display.py /usr/local/libexec/syq-test-completion-display.py

COPY tests/real-ssh/test-receive-notifications.py /usr/local/libexec/syq-test-receive-notifications.py

COPY tests/real-ssh/test-forward-copy.py /usr/local/libexec/syq-test-forward-copy.py

COPY tests/real-ssh/test-return-exec.py /usr/local/libexec/syq-test-return-exec.py

ENTRYPOINT ["/usr/local/libexec/syq-real-ssh-entrypoint"]

# Shared gdb base image p2s-fpm426-gdb for the 8.4.26-fpm gdb labs (cw grail hl tp glc flp seat brleak).
# Digest-pinned so the php binary (and every exploit offset) stays byte-identical.
FROM php:8.4.26-fpm@sha256:f5431b57bda75455d5271967cc6b67df8f0d0b943832756e0c78eccdc98767dd

RUN apt-get update && apt-get install -y gdb procps binutils \
    && rm -rf /var/lib/apt/lists/*

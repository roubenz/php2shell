# Shared gdb base image p2s-apache426-gdb for the 8.4.26-apache mod_php gdb labs (apfl).
# Digest-pinned so the php binary (and every exploit offset) stays byte-identical.
FROM php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

RUN apt-get update && apt-get install -y --no-install-recommends gdb procps \
    && rm -rf /var/lib/apt/lists/*

# Apache mod_php lab image for apache_offsetfree_rce (gdb+procps for OBSERVE-only geometry
# measurement; the fire + AIM sweep are pure HTTP). PHP_VERSION picks the minor; the ini, mpm
# pin, html and genA_big are mounted by the compose service.
ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-apache

RUN apt-get update && apt-get install -y --no-install-recommends gdb procps \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 80

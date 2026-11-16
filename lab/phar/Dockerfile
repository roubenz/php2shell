# php-fpm side of AVENUE #2 (phar:// deserialization). PHP 8.4.26-fpm, stock-ish
# multi-worker pool, with a REAL framework (monolog/monolog ^3.1) vendored and an
# exposed composer.lock in the docroot so poc/gadget_fingerprint.py can detect
# the framework over HTTP and auto-select the Monolog file-write POP chain.
#
#   *** AVENUE #2 is a TRIGGER-SIDE route: a filesystem function called on an
#   *** attacker-controlled phar:// path unserializes the phar metadata ->
#   *** object injection -> __destruct POP chain -> RCE. It is an APPLICATION /
#   *** PHP-feature issue, NOT a PHP-core memory-corruption bug and NOT in the
#   *** CVE-2026-109618/109619 family.
#
# HONEST 8.x NOTE (empirically verified on 8.4.26, see poc docstrings):
#   PHP 8.0 made phar metadata LAZY. Plain fs-functions (file_exists, is_file,
#   filesize, file_get_contents, ...) and even `new Phar()` NO LONGER unserialize
#   the metadata. Metadata is unserialized ONLY when Phar::getMetadata() (phar or
#   per-entry) is called -- with allowed_classes defaulting to TRUE, so object
#   injection is live once that call is reached. The app therefore carries an
#   endpoint that reaches getMetadata() on an attacker-named upload (realistic:
#   archive/metadata inspectors), and a negative-control endpoint that only does
#   file_exists() -> no injection, proving the hardening.
FROM php:8.4.26-fpm

RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY lab/phar/html/ /var/www/html/
COPY lab/phar/zz-phar.ini /usr/local/etc/php/conf.d/zz-phar.ini

RUN set -eux; \
    cd /var/www/html; \
    composer require monolog/monolog:^3.1 --no-interaction --no-progress; \
    mkdir -p /var/www/html/uploads; \
    chown -R www-data:www-data /var/www/html; \
    chmod -R u+w /var/www/html

WORKDIR /var/www/html

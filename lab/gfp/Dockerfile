ARG PHP_VERSION=8.5
FROM php:${PHP_VERSION}-apache

# ---------------------------------------------------------------------------
# Lab variant for Hope-A4 (gadget-fingerprint). Apache mod_php (uid=www-data),
# fully-patched PHP 8.5.12, with a REAL framework (monolog/monolog ^3.1)
# vendored AND an exposed composer.lock in the docroot (a common misconfig) so
# poc/gadget_fingerprint.py can auto-detect the framework over HTTP and
# auto-select the Monolog file-write POP chain -- no operator-specified chain.
#
# Same application-level mechanism as lab/shmismatch and lab/pggc: a
# serialize_handler mismatch (write=php_serialize, read=php) + the
# upload-progress key, which carries the auto-sourced gadget. This is NOT a
# PHP-core bug and NOT in the CVE-2026-109618/109619 family.
#
# cleanup=Off -> deterministic base variant (the fingerprint demo is about
# chain selection, not the cleanup race; the race is covered in lab/pggc).
# ---------------------------------------------------------------------------
ARG CLEANUP=Off

RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY lab/gfp/html/ /var/www/html/

RUN set -eux; \
    { \
      echo "session.serialize_handler = php_serialize"; \
      echo "session.save_path = /var/www/sess"; \
      echo "session.upload_progress.enabled = On"; \
      echo "session.upload_progress.cleanup = ${CLEANUP}"; \
      echo "session.use_strict_mode = On"; \
      echo "display_errors = Off"; \
      echo "log_errors = On"; \
    } > /usr/local/etc/php/conf.d/zz-gfp.ini; \
    cd /var/www/html; \
    composer require monolog/monolog:^3.1 --no-interaction --no-progress; \
    mkdir -p /var/www/sess; \
    chmod 1777 /var/www/sess; \
    chown -R www-data:www-data /var/www/sess /var/www/html; \
    chmod -R u+w /var/www/html; \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

WORKDIR /var/www/html

ARG PHP_VERSION=8.5
FROM php:${PHP_VERSION}-apache

# ---------------------------------------------------------------------------
# Lab for the "session serialize_handler mismatch" primitive -- an
# APPLICATION-LEVEL PHP Object Injection that still works on fully-patched
# PHP 8.5.12 (the 2026-10-21 security release). This is NOT a PHP-core memory
# corruption bug and is NOT in the CVE-2026-109618/109619 family: it needs a
# non-default config mismatch AND an app-reachable destructor gadget. It is the
# "handler-mismatch / session-gaps" logic-RCE our corpus tracked as an open
# question -- landed here as a verified-but-conditional primitive, with its
# exact gates pinned by the matching verifier.
#
# Mechanism:
#   (1) The rfc1867 upload-progress hook writes the RAW value of the
#       PHP_SESSION_UPLOAD_PROGRESS multipart field into the session key
#       (ext/session/session.c: smart_str_append prefix + appendl value), with
#       NO grammar check, BEFORE any script runs. This behaviour is unchanged on
#       8.5.12 (the patch reset session globals; it did not validate the key).
#   (2) The WRITE side serializes $_SESSION with the `php_serialize` handler
#       (the config PHP's own docs recommend), so the attacker key persists as a
#       string inside the serialized array.
#   (3) A READ side that uses the legacy `php` handler (ini_set/per-dir/legacy
#       shim -- the MISMATCH) parses that file as `key|value;` pairs. The `|`
#       the attacker embedded in the key splits it, dropping the trailing
#       `O:..` serialized object into a VALUE position -> unserialize() runs it.
#   (4) The injected object's __destruct (a POP gadget in the reader's scope)
#       fires -> RCE.
#
# Gates (all required; two are non-default):
#   * session.serialize_handler mismatch: write=php_serialize, read=php    [NON-DEFAULT]
#   * a destructor gadget reachable in the reader (here: DeferredWriter)   [APP-DEPENDENT]
#   * session.upload_progress.enabled=On                                   (default On)
#   * save_path known (default /tmp) + controllable SID (cookie)           (default)
# cleanup=On (default) is NOT a blocker: a slow/trickle upload holds the
# poisoned key in the file during the cleanup window for a concurrent reader
# (the "race" variant). The CLEANUP build arg selects Off (deterministic base
# variant) or On (stock, race variant).
#
# Default multi-worker prefork is kept (NOT pinned to one child): the race
# variant needs a second worker free to serve the reader while the trickle
# upload occupies the first.
# ---------------------------------------------------------------------------

ARG CLEANUP=On

COPY lab/shmismatch/html/ /var/www/html/

RUN set -eux; \
    { \
      echo "session.serialize_handler = php_serialize"; \
      echo "session.save_path = /var/www/sess"; \
      echo "session.upload_progress.enabled = On"; \
      echo "session.upload_progress.cleanup = ${CLEANUP}"; \
      echo "session.use_strict_mode = On"; \
      echo "display_errors = Off"; \
      echo "log_errors = On"; \
    } > /usr/local/etc/php/conf.d/zz-shmismatch.ini; \
    mkdir -p /var/www/sess; \
    chmod 1777 /var/www/sess; \
    chown -R www-data:www-data /var/www/sess /var/www/html; \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

WORKDIR /var/www/html

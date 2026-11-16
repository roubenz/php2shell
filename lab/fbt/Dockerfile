ARG PHP_VERSION=8.5
FROM php:${PHP_VERSION}-apache

# ---------------------------------------------------------------------------
# Lab for the "fbt" primitive: EG(last_fatal_error_backtrace) use-after-free
# (Bhavye-Malhotra). 8.5.x mod_php / Apache ONLY.
#
# Mechanism (8.5.12 == php:8.5-apache):
#   (1) An E_USER_ERROR captures a backtrace into EG(last_fatal_error_backtrace)
#       (zend.c, fatal_error_backtraces=On by default on 8.5).
#   (2) shutdown_executor() clears that zval only under `if (!fast_shutdown)`
#       (zend_execute_API.c). On a normal request fast_shutdown is taken, so the
#       clear is SKIPPED and the zval survives RSHUTDOWN still pointing at
#       request-heap that is then bulk-freed.
#   (3) Next request on the SAME child: mod_php applies per-dir INI at
#       PHP_INI_STAGE_HTACCESS BEFORE request startup (apache_config.c). An
#       invalid `php_value memory_limit <junk>` in a .htaccess triggers
#       zend_error(E_WARNING); zend_error() ALWAYS clears
#       EG(last_fatal_error_backtrace) first -> zval_ptr_dtor on the STALE freed
#       zval -> UAF, before init_executor would have UNDEF'd it.
#
# As-shipped impact: UAF -> SIGSEGV worker kill (a crash / vuln-signature
# oracle, NOT a proven stale-frame leak or write primitive).
#
# Needs a PRISTINE child: fatal.php must be the first request a child serves.
# A single immortal prefork worker (mpm-one.conf) + crash-respawn gives each
# attack a fresh child for free (the previous attack's SIGSEGV respawns a
# pristine sibling).
#
# Attacker-controlled .htaccess is the realistic precondition, so we enable
# AllowOverride All on the docroot and ship a real junkdir/.htaccess.
# ---------------------------------------------------------------------------

COPY lab/fbt/index.php        /var/www/html/index.php
COPY lab/fbt/fatal.php        /var/www/html/fatal.php
COPY lab/fbt/pid.php          /var/www/html/pid.php
COPY lab/fbt/cleandir/        /var/www/html/cleandir/
COPY lab/fbt/junkdir/         /var/www/html/junkdir/
COPY lab/fbt/allowoverride.conf /etc/apache2/conf-enabled/zz-allowoverride.conf
COPY lab/fbt/mpm-one.conf       /etc/apache2/conf-enabled/zz-mpm-one.conf
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
WORKDIR /var/www/html

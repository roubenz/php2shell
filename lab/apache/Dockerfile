ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-apache

# Apache + mod_php (prefork MPM). Unlike php-fpm (which exits a child whose
# STARTUP fails, so the pre-RINIT PS(id)/upload-progress family cannot land a
# second request on the same process), mod_php runs php_request_shutdown()
# unconditionally after a failed startup AND prefork children fork from the
# master, so a crashed child is replaced by a sibling sharing the master's
# ASLR (same binary base / request-heap chunk). That makes the a6 cookie
# disclosure usable even though the leaking request crashes: it flushes the
# Set-Cookie during php_request_shutdown (before the module RSHUTDOWN poison),
# then dies, and the follow-on rce round runs on a same-ASLR sibling.

RUN mkdir -p /tmp/sess && chown www-data:www-data /tmp/sess
COPY lab/app/ /var/www/html/
COPY lab/apache/php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY lab/apache/mpm-one.conf /etc/apache2/conf-enabled/zz-mpm-one.conf
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
WORKDIR /var/www/html

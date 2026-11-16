# php-fpm side of the AVENUE #8 redis-session-poison lab (nginx + redis are
# separate services). PHP 8.4.26-fpm with the phpredis extension and
# session.save_handler=redis -> session records live in redis, not on disk.
#
# Stock multi-worker pool (pm=dynamic, default children) so the optional
# upload-progress storm can hold one worker while readers use others.
FROM php:8.4.26-fpm

# phpredis (the PECL ext that backs session.save_handler=redis).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends $PHPIZE_DEPS; \
    pecl install redis; \
    docker-php-ext-enable redis; \
    apt-get purge -y --auto-remove $PHPIZE_DEPS; \
    rm -rf /var/lib/apt/lists/*

COPY lab/redissess/html/ /var/www/html/
COPY lab/redissess/zz-redissess.ini /usr/local/etc/php/conf.d/zz-redissess.ini

RUN chown -R www-data:www-data /var/www/html
WORKDIR /var/www/html

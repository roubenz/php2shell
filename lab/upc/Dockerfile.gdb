# upc lab -- :gdb calibration variant. IDENTICAL stock php-fpm binary + ini + pool as the
# runtime target (so measured chunk-relative offsets transfer 1:1); only adds gdb/binutils
# for OFFSET CALIBRATION. The shipped chain stays gdb-free on the real target.
ARG PHP_VERSION=8.3.26
FROM php:${PHP_VERSION}-fpm

ARG MEMORY_LIMIT=512M

COPY lab/upc/html/ /var/www/html/
COPY lab/upc/zz-upc.ini /usr/local/etc/php/conf.d/zz-upc.ini
COPY lab/upc/pool.conf /usr/local/etc/php-fpm.d/zz-upc.conf
RUN printf '; written by Dockerfile ARG MEMORY_LIMIT\nmemory_limit = %s\n' "$MEMORY_LIMIT" \
      > /usr/local/etc/php/conf.d/zz-mem.ini
RUN chown -R www-data:www-data /var/www/html && chmod -R 0777 /var/www/html

RUN apt-get update \
 && apt-get install -y --no-install-recommends gdb binutils python3 procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /var/www/html

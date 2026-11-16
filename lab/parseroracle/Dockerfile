# php-fpm side of the native-parser crash-oracle lab (Hope-B4).
# Stock PHP 8.4.26-fpm with the three near-universal file-upload parsers
# compiled in: exif, gd (TIFF/ICC/gd2 paths), zip (ZipArchive -> system libzip).
# The app (html/upload.php) feeds an UPLOADED file to one of these parsers and
# NEVER echoes the result -- the only channel is worker liveness (nginx 200 vs
# 502/reset), i.e. the page-probe crash oracle of fpm_intrinsic_reflect.py.
FROM php:8.4.26-fpm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libzip-dev libpng-dev libjpeg62-turbo-dev libfreetype6-dev; \
    docker-php-ext-configure gd --with-jpeg --with-freetype; \
    docker-php-ext-install -j"$(nproc)" exif gd zip; \
    rm -rf /var/lib/apt/lists/*

COPY lab/parseroracle/html/ /var/www/html/
COPY lab/parseroracle/zz-parseroracle.ini /usr/local/etc/php/conf.d/zz-parseroracle.ini
COPY lab/parseroracle/pool.conf /usr/local/etc/php-fpm.d/zz-pool.conf

RUN mkdir -p /tmp/uploads && chown -R www-data:www-data /tmp/uploads /var/www/html
WORKDIR /var/www/html

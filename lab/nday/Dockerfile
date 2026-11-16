# n-day native-parser OOB lab (survey companion to Hope-B4).
# PHP 7.2.17-fpm == the CLASSIC pre-patch exif build (CVE-2019-11036 class,
# fixed in 7.2.18). exif is compiled in (no external deps). Purpose: EMPIRICALLY
# measure whether the pre-guard exif IFD-offset deref is a STEERABLE far deref
# that faults on a chosen unmapped address (B14-rideable) or a bounded over-read
# (not rideable). Same upload sink / liveness channel as the parseroracle lab.
# Lab/analysis use only, on systems you own.
FROM php:7.2.17-fpm

RUN set -eux; docker-php-ext-install -j"$(nproc)" exif

COPY lab/parseroracle/html/ /var/www/html/
COPY lab/nday/zz-nday.ini /usr/local/etc/php/conf.d/zz-nday.ini
COPY lab/parseroracle/pool.conf /usr/local/etc/php-fpm.d/zz-pool.conf

RUN mkdir -p /tmp/uploads && chown -R www-data:www-data /tmp/uploads /var/www/html
WORKDIR /var/www/html

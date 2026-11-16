ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-fpm

RUN mkdir -p /tmp/sess && chown www-data:www-data /tmp/sess
COPY lab/app/ /var/www/html/
COPY lab/fpm/php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY lab/fpm/pool.php2shell.conf /usr/local/etc/php-fpm.d/zz-php2shell.conf

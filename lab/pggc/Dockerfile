# php-fpm side of the gadget-phpggc lab. PHP 8.4.26-fpm (stock multi-worker)
# with a REAL framework (monolog/monolog ^3.1) vendored so the phpggc
# Monolog/FW1 file-write gadget chain is reachable in the reader's scope.
FROM php:8.4.26-fpm
RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY lab/pggc/html/ /var/www/html/
COPY lab/pggc/zz-pggc.ini /usr/local/etc/php/conf.d/zz-pggc.ini
WORKDIR /var/www/html
RUN composer require monolog/monolog:^3.1 --no-interaction --no-progress \
    && mkdir -p /var/sess && chmod 1777 /var/sess \
    && chown -R www-data:www-data /var/sess /var/www/html \
    && chmod -R u+w /var/www/html

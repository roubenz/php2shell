# upc lab -- stock PHP-fpm target (NO custom compile), version via PHP_VERSION (the reference target runs
# 8.3.26; 8.4.26 also builds). Clean stand-in for the stock phpMyAdmin reference target, carrying
# the reference target's parameter set with session.upload_progress.cleanup=On. Follows the repo lab
# convention (a7r5 / vd24481): build context is the repo root, dockerfile is lab/upc/Dockerfile.
ARG PHP_VERSION=8.3.26
FROM php:${PHP_VERSION}-fpm

# The ONLY directive that differs between the 512M and 32M targets.
ARG MEMORY_LIMIT=512M

COPY lab/upc/html/ /var/www/html/
COPY lab/upc/zz-upc.ini /usr/local/etc/php/conf.d/zz-upc.ini
COPY lab/upc/pool.conf /usr/local/etc/php-fpm.d/zz-upc.conf
RUN printf '; written by Dockerfile ARG MEMORY_LIMIT\nmemory_limit = %s\n' "$MEMORY_LIMIT" \
      > /usr/local/etc/php/conf.d/zz-mem.ini

# Docroot world-writable (base image default drwxrwxrwt) so a www-data worker can drop
# the forged x.php; keep it that way after the COPY.
RUN chown -R www-data:www-data /var/www/html && chmod -R 0777 /var/www/html
WORKDIR /var/www/html

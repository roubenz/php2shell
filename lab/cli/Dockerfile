ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-cli

RUN mkdir -p /tmp/sess
COPY lab/app/ /var/www/html/
WORKDIR /var/www/html

# php -S with one worker (default) matches mod_php request lifecycle semantics
# that the advisories describe for the demonstrated exploit:
#  - php_hash_environment() (multipart + session upload progress) runs before RINIT
#  - php_request_shutdown() runs unconditionally, even after failed startup
# See sapi/cli/php_cli_server.c: php_cli_server_request_shutdown().
CMD ["php", \
    "-d", "memory_limit=16M", \
    "-d", "post_max_size=32M", \
    "-d", "max_input_vars=1000000", \
    "-d", "max_file_uploads=1000000", \
    "-d", "max_multipart_body_parts=1000000", \
    "-d", "session.save_path=/tmp/sess", \
    "-d", "session.upload_progress.enabled=1", \
    "-d", "session.upload_progress.freq=1%", \
    "-d", "session.upload_progress.min_freq=0", \
    "-d", "session.use_cookies=1", \
    "-d", "session.use_only_cookies=0", \
    "-d", "session.use_strict_mode=0", \
    "-d", "session.sid_length=256", \
    "-d", "error_reporting=E_ALL", \
    "-d", "display_errors=0", \
    "-d", "log_errors=1", \
    "-S", "0.0.0.0:80", "-t", "/var/www/html"]

# trixie (gcc-14) not bookworm (gcc-12): the host kernel runs
# vm.mmap_rnd_bits=32 and bookworm's libasan hits probabilistic
# AddressSanitizer:DEADLYSIGNAL startup spin loops there, which stalls
# ./configure on the first AC_RUN_IFELSE. gcc-14's runtime handles it.
FROM debian:trixie-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git autoconf bison re2c make gcc g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG PHP_TAG=php-8.4.26
RUN git clone --depth 1 --branch ${PHP_TAG} https://github.com/php/php-src /src
WORKDIR /src
RUN ./buildconf --force
RUN CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-all --enable-cli --enable-session \
        --without-pear --disable-cgi --disable-phpdbg
RUN make -j"$(nproc)"

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libasan8 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/sess
COPY --from=build /src/sapi/cli/php /usr/local/bin/php
COPY lab/app/ /var/www/html/
WORKDIR /var/www/html

# USE_ZEND_ALLOC=0 + USE_TRACKED_ALLOC=1 routes emalloc() to malloc() (one
# ASan heap chunk per request allocation; use-after-frees on request memory
# become deterministic ASan reports instead of silent ZendMM bin reuse) while
# USE_TRACKED_ALLOC keeps memory_limit enforced (tracked_check_limit) and
# frees every request allocation at shutdown (tracked_free_all), so the OOM
# producers still fire. (USE_ZEND_ALLOC=0 alone disables memory_limit.)
ENV USE_ZEND_ALLOC=0
ENV USE_TRACKED_ALLOC=1
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

EXPOSE 80
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
    "-d", "session.use_cookies=0", \
    "-d", "session.use_only_cookies=0", \
    "-d", "session.use_strict_mode=0", \
    "-d", "error_reporting=E_ALL", \
    "-d", "display_errors=0", \
    "-d", "log_errors=1", \
    "-S", "0.0.0.0:80", "-t", "/var/www/html"]

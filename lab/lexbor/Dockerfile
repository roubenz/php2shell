# ASAN PHP 8.4.26 CLI build with ext/dom (lexbor) + ext/json enabled, for
# verifying two memory-safety candidates against the bundled lexbor/json:
#   (1) :lexbor-contains() CSS-selector heap overflow (ext/dom/lexbor
#       pseudo_state.c: lxb_css_selectors_state_pseudo_class_function_lexbor_contains)
#   (2) json_encode() live-properties HashTable resize UAF (ext/json json_encoder.c)
#
# trixie (gcc-14) not bookworm: the host kernel runs vm.mmap_rnd_bits=32 and
# bookworm's libasan hits AddressSanitizer:DEADLYSIGNAL startup spin loops that
# stall ./configure. gcc-14's runtime handles it. (Same rationale as lab/asan.)
FROM debian:trixie-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git autoconf bison re2c make gcc g++ pkg-config \
        libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

ARG PHP_TAG=php-8.4.26
RUN git clone --depth 1 --branch ${PHP_TAG} https://github.com/php/php-src /src
WORKDIR /src
RUN ./buildconf --force
# ext/dom (new Dom\HTMLDocument API) is what drives the bundled lexbor CSS
# selector parser; ext/json is always compiled in since PHP 8.
RUN CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address" \
    ./configure --disable-all --enable-cli \
        --with-libxml --enable-dom \
        --without-pear --disable-cgi --disable-phpdbg
RUN make -j"$(nproc)"

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libasan8 libstdc++6 libxml2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/sapi/cli/php /usr/local/bin/php

# USE_ZEND_ALLOC=0 routes emalloc()/__zend_malloc()/erealloc() to glibc
# malloc/realloc so each allocation is its own ASan-poisoned chunk; the lexbor
# mraw pool chunk and the object-properties arData buffer then become real ASan
# heap objects, making the overflow / use-after-free deterministic reports
# instead of silent ZendMM bin reuse.
ENV USE_ZEND_ALLOC=0
ENV USE_TRACKED_ALLOC=1
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

WORKDIR /work
CMD ["php", "-v"]

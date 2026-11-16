#!/usr/bin/env python3
"""verify_upc.py -- self-documenting health check for the `upc` session-upload-progress lab
(CVE-2026-109619; stock PHP 8.3.26-fpm, the reference target's version), session.upload_progress.cleanup=On.

Canonical compose invocation (one profile at a time -- all three reuse the fpm/web aliases):
    docker compose -f docker-compose.versions.yml --profile upc83      up -d --build   # 512M
    docker compose -f docker-compose.versions.yml --profile upc8332    up -d --build   # 32M
    docker compose -f docker-compose.versions.yml --profile upc8332gdb up -d --build   # 32M + gdb (calibration)
    python3 -I lab/upc/verify_upc.py

profile -> container:port map:
    upc83      -> p2s-upc83-fpm      / p2s-upc83-web       http://127.0.0.1:8195   512M  mirrors reference target
    upc8332    -> p2s-upc8332-fpm    / p2s-upc8332-web     http://127.0.0.1:8196    32M  fast-fill variant
    upc8332gdb -> p2s-upc8332gdb-fpm / p2s-upc8332gdb-web  http://127.0.0.1:8198    32M  + gdb (ptrace), CALIBRATION

Checks, per profile that is up: HTTP reachability (/pid.php, /plain.php, index.php session_start),
PHP version == 8.3.26, the reference target directive set incl. cleanup=On and the per-target
memory_limit, and a world-writable docroot. Exits non-zero if any running profile fails.
"""
from __future__ import annotations

import http.client
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "poc")
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.labharness import container_up, dexec  # noqa: E402

PHP_VERSION = os.environ.get("UPC_PHP", "8.3.26")
PROFILES = {
    "upc83":      {"fpm": "p2s-upc83-fpm",      "web": "p2s-upc83-web",      "port": 8195, "ml": "512M"},
    "upc8332":    {"fpm": "p2s-upc8332-fpm",    "web": "p2s-upc8332-web",    "port": 8196, "ml": "32M"},
    "upc8332gdb": {"fpm": "p2s-upc8332gdb-fpm", "web": "p2s-upc8332gdb-web", "port": 8198, "ml": "32M"},
}
# the reference target's info.php directive set the lab must carry (cleanup=On is the condition).
WANT = {
    "session.upload_progress.cleanup": "On",
    "session.upload_progress.enabled": "On",
    "session.use_strict_mode": "On",
    "session.serialize_handler": "php",
    "post_max_size": "8M",
    "upload_max_filesize": "20M",
    "opcache.enable": "On",
}


def http_code(port, path):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read().decode("latin1", "replace")
    except Exception as e:
        return 0, repr(e)


def ini_val(container, key):
    out = dexec(container, "php", "-i", check=False)
    for line in out.splitlines():
        if line.lower().startswith(key.lower() + " =>"):
            return line.split("=>")[1].strip()
    return None


def main() -> int:
    passn = failn = 0

    def ok(m):
        nonlocal passn
        passn += 1
        print("  ok   " + m)

    def no(m):
        nonlocal failn
        failn += 1
        print("  FAIL " + m)

    ran = []
    for name, cfg in PROFILES.items():
        if not container_up(cfg["web"]) or not container_up(cfg["fpm"]):
            print(f"[skip] profile {name} not up (docker compose -f docker-compose.versions.yml "
                  f"--profile {name} up -d --build)")
            continue
        ran.append(name)
        print(f"\n######## profile {name}  http://127.0.0.1:{cfg['port']}  ({cfg['ml']}) ########")
        for path in ("/pid.php", "/plain.php"):
            st, _ = http_code(cfg["port"], path)
            (ok if st == 200 else no)(f"{name} {path} -> {st}")
        st, body = http_code(cfg["port"], "/index.php")
        (ok if st == 200 and body.startswith("OK") else no)(
            f"{name} index.php session_start -> {st} {body.strip()!r}")

        v = dexec(cfg["fpm"], "php", "-v", check=False).split("\n")[0]
        (ok if PHP_VERSION in v else no)(f"{name} php version: {v.strip()}")
        for k, want in WANT.items():
            got = ini_val(cfg["fpm"], k)
            (ok if got == want else no)(f"{name} {k} = {got} (want {want})")
        got_ml = ini_val(cfg["fpm"], "memory_limit")
        (ok if got_ml == cfg["ml"] else no)(f"{name} memory_limit = {got_ml} (want {cfg['ml']})")
        wr = dexec(cfg["fpm"], "sh", "-c",
                   "case $(stat -c %A /var/www/html) in *w*w*w*) echo yes;; *) echo no;; esac",
                   check=False).strip()
        (ok if wr == "yes" else no)(f"{name} docroot world-writable: {wr}")

    print(f"\n==== verify_upc: {passn} ok, {failn} FAIL, profiles up: {ran or 'none'} ====")
    if not ran:
        print("  bring up a profile first (see header).")
        return 2
    return 0 if failn == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

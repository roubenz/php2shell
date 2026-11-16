#!/usr/bin/env python3
"""Generic live-process readers (gdb + /proc), stdlib only.

Provides a docker-compose exec wrapper (``compose_exec``), fpm worker/pid
liveness probes (``worker_pids`` / ``pid_alive``), an in-container batch gdb
runner (``gdb``), and the /proc maps reader (``Maps`` / ``read_maps``) with its
php image base + .bss lookups. ``GdbDriver`` holds the compose/service/size
config the primitive driver classes share; subclasses add the exploit-specific
gdb payload methods. Compose, service and image names are always caller
arguments. stdlib/subprocess only.
"""
from __future__ import annotations

import re
import subprocess

from common.zend_mm import CHUNK_SIZE as CHUNK_ALIGN  # ZEND_MM_CHUNK_SIZE / PIE p_align


def compose_exec(compose_file, service, *cmd, user_root=True, timeout=90):
    """Run `cmd` in `service` via `docker compose exec -T`; return stdout+stderr."""
    full = ["docker", "compose", "-f", compose_file, "exec", "-T"]
    if user_root:
        full += ["--user", "root"]
    full += [service] + list(cmd)
    r = subprocess.run(full, capture_output=True, timeout=timeout)
    return r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")


def worker_pids(compose_file, service):
    """Return the sorted pids of the `pool www` php-fpm workers in `service`."""
    out = compose_exec(compose_file, service, "sh", "-c",
                       "ps -eo pid,args | grep 'pool www' | grep -v grep",
                       user_root=False)
    pids = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        first = line.split(None, 1)[0]
        if first.isdigit():
            pids.append(int(first))
    return sorted(pids)


def pid_alive(compose_file, service, pid):
    """True iff `pid` is still a live process inside `service`."""
    out = compose_exec(compose_file, service, "sh", "-c",
                       f"ps -p {pid} -o pid= >/dev/null 2>&1 && echo ALIVE || echo DEAD",
                       user_root=False)
    return "ALIVE" in out


def gdb(compose_file, service, pid, exprs, timeout=90):
    """Attach batch gdb to `pid` in `service`, run each `-ex` expr, return output."""
    argv = ["gdb", "-p", str(pid), "-batch", "-nx", "-ex", "set confirm off"]
    for e in exprs:
        argv += ["-ex", e]
    argv += ["-ex", "quit"]
    return compose_exec(compose_file, service, *argv, timeout=timeout)


class Maps:
    """Parse /proc/<pid>/maps into rows; expose the php image base + .bss."""

    def __init__(self, text):
        self.rows = []
        for line in text.splitlines():
            p = line.split(None, 5)
            if len(p) < 5 or "-" not in p[0]:
                continue
            try:
                s, e = (int(x, 16) for x in p[0].split("-"))
            except ValueError:
                continue
            self.rows.append({
                "start": s, "end": e, "size": e - s, "perm": p[1],
                "off": p[2], "ino": p[4],
                "path": p[5].strip() if len(p) > 5 else "",
            })

    def binbase(self):
        for x in self.rows:
            if x["path"].endswith(("/php-fpm", "/php")):
                return x["start"]
        return None

    def image_bss(self):
        """The anon rw-p .bss right after the php-fpm image's rw-p .data seg."""
        for i, x in enumerate(self.rows):
            if x["perm"] == "rw-p" and x["path"].endswith(("/php-fpm", "/php")):
                nxt = self.rows[i + 1] if i + 1 < len(self.rows) else None
                if nxt and nxt["perm"] == "rw-p" and nxt["path"] == "" \
                        and nxt["off"] == "00000000":
                    return nxt
        return None

    def _first(self, pred):
        for x in self.rows:
            if pred(x):
                return x
        return None

    def libc(self):
        x = self._first(lambda r: "libc.so.6" in r["path"])
        return x["start"] if x else None

    def ld(self):
        x = self._first(lambda r: "ld-linux" in r["path"])
        return x["start"] if x else None

    def heap_chunk(self):
        """A ZendMM request chunk: a >=2 MiB anon rw-p span in the HIGH mmap
        region (co-located with libc), representative of the request-heap
        cluster the steered-write groom lives in. Returns the aligned 2 MiB base."""
        libc = self.libc() or 0
        bases = zendmm_chunk_bases(self.rows, require_off0=True, require_ino0=True,
                                   high_only=True, align="start", require_fit=False)
        if not bases:
            return None
        return min(bases, key=lambda b: abs(b - libc))


def zendmm_chunk_bases(rows, *, min_size=CHUNK_ALIGN, max_size=None,
                       require_off0=False, require_ino0=False, high_only=False,
                       libc=None, near_libc=None, align="start",
                       require_fit=True, perm="rw-p"):
    """Locate 2 MiB-aligned ZendMM request-chunk base(s) among anon rw-p rows,
    in /proc row order. A ZendMM chunk is an anonymous (path-less) rw-p span of at
    least ``min_size`` bytes; ``align='start'`` rounds the mapping start up to the
    2 MiB granule (``require_fit`` then demands the whole 2 MiB window fit inside the
    mapping), while ``align='end'`` takes the 2 MiB window ending at the mapping end
    (which must itself be 2 MiB-aligned). ``perm`` is ``'rw-p'`` for an exact match
    or ``'rw'`` for the substring test; the rest are optional filters (off==0, ino==0,
    a HIGH-mmap start, or proximity to ``libc`` within ``near_libc``). Returns the
    list of candidate bases in row order; callers apply their own selection."""
    out = []
    for x in rows:
        pm = x["perm"]
        if perm == "rw" and "rw" not in pm:
            continue
        if perm == "rw-p" and pm != "rw-p":
            continue
        if x["path"] != "":
            continue
        size = x["end"] - x["start"]
        if size < min_size or (max_size is not None and size > max_size):
            continue
        if require_off0 and x.get("off") != "00000000":
            continue
        if require_ino0 and x.get("ino") != "0":
            continue
        if high_only and x["start"] < 0x700000000000:
            continue
        if near_libc is not None and (libc is None
                                      or abs(x["start"] - libc) > near_libc):
            continue
        if align == "end":
            if x["end"] % CHUNK_ALIGN != 0:
                continue
            base = x["end"] - CHUNK_ALIGN
        else:
            base = (x["start"] + CHUNK_ALIGN - 1) & ~(CHUNK_ALIGN - 1)
            if require_fit and base + CHUNK_ALIGN > x["end"]:
                continue
        out.append(base)
    return out


def derive_core_globals(compose_file, service):
    """Derive the php-fpm core_globals vaddr from the binary (exported symbol),
    the way the module header documents. Returns (vaddr, how)."""
    for tool, pat in (("nm", "nm -D /usr/local/sbin/php-fpm"),
                      ("readelf", "readelf -sW /usr/local/sbin/php-fpm")):
        out = compose_exec(compose_file, service, "sh", "-c",
                           f"command -v {tool} >/dev/null 2>&1 && {pat} 2>/dev/null "
                           f"| grep -w core_globals", user_root=False)
        if out.strip():
            m = re.search(r"([0-9a-fA-F]{6,16})\b", out)
            if m:
                return int(m.group(1), 16), f"{tool}: {out.strip()}"
    return None, None


def fpm_base_of(compose_file, service, pid):
    """php-fpm PIE base for worker <pid> from /proc/<pid>/maps."""
    for x in read_maps(compose_file, service, pid).rows:
        if x["path"].endswith("/php-fpm"):
            return x["start"]
    return None


def proc_seed(compose_file, service, pid):
    """The two values the single-write CVE primitive consumes as INPUTS -- read
    here from /proc/<pid>/maps to make the "seeded, not discovered" boundary
    concrete. Returns {'binbase':..., 'chunk':...}. On fork-fixed fpm ASLR both
    are identical on every worker, but neither is disclosable app-free (the
    oracle CONFIRMS a guess, it does not DISCOVER these from nothing)."""
    maps = read_maps(compose_file, service, pid)
    seed = {"binbase": None, "chunk": None, "source": f"/proc/{pid}/maps (LAB)"}
    for x in maps.rows:
        if x["path"].endswith("/php-fpm") and seed["binbase"] is None:
            seed["binbase"] = x["start"]
    bases = zendmm_chunk_bases(maps.rows, require_off0=True, align="end")
    if bases:
        seed["chunk"] = bases[0]
    return seed


def dump_mem(compose_file, service, pid, addr, size):
    """Dump `size` bytes of /proc/<pid>/mem at `addr` (page-aligned skip via dd)."""
    page = 0x1000
    lo = addr & ~(page - 1)
    pad = addr - lo
    npages = (pad + size + page - 1) // page
    full = ["docker", "compose", "-f", compose_file, "exec", "-T",
            "--user", "root", service, "dd", f"if=/proc/{pid}/mem",
            "bs=4096", f"skip={lo // page}", f"count={npages}", "status=none"]
    raw = subprocess.run(full, capture_output=True).stdout
    return raw[pad:pad + size]


def read_maps(compose_file, service, pid):
    """Read /proc/<pid>/maps from `service` and return a parsed ``Maps``."""
    return Maps(compose_exec(compose_file, service, "cat", f"/proc/{pid}/maps",
                             user_root=False))


class GdbDriver:
    """Holds the compose/service/size/verbose config the live-allocator write
    primitives share. Subclasses add the exploit-specific gdb payload methods."""

    def __init__(self, compose_file, service, size, verbose=False):
        self.compose_file = compose_file
        self.service = service
        self.size = size
        self.verbose = verbose

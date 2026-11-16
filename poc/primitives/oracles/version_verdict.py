#!/usr/bin/env python3
# INDEX: php version -> cve-2026-109618/109619 + lexbor patch verdict | all | passive
"""Map a PHP version (+SAPI) to a patch verdict for the php2shell bugs.

Pure arithmetic over the coordinated 21-Oct-2026 release line
(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12), which closed all four bugs at once:
  * CVE-2026-109618  (OOM half-built-state request-shutdown walk)
  * CVE-2026-109619  (stale-global / upload-progress / unserialize dangle)
  * lexbor :lexbor-contains() CSS-selector heap buffer overflow
  * lexbor IDNA ToASCII heap over-read (ChangeLog item (c))

verdict() returns the core-CVE verdict; lexbor_verdict() the lexbor-family one
(8.4/8.5-only reachable classes, and the per-branch fix version for the 8.2-8.4
branches is not independently confirmed here - flagged in `caveats`).

A version in the vulnerable range is only LIKELY_VULNERABLE: distros backport
the fix without bumping the upstream version string, and expose_php=Off removes
the banner entirely. Never read a stronger claim than the level that produced it.
"""
from __future__ import annotations

import re

# minor -> first FIXED patch release
CORE_FIXED = {(8, 1): None,          # 8.1 is EOL: no fixed release exists
              (8, 2): (8, 2, 35),
              (8, 3): (8, 3, 36),
              (8, 4): (8, 4, 27),
              (8, 5): (8, 5, 12)}

# lexbor family: same coordinated release closed it, but the per-branch fix
# version for 8.2-8.4 is not independently confirmed in-repo (module tests only
# 8.4.26 vuln / 8.5.12 fixed). Reachable sinks are 8.4+ (Dom\HTMLDocument) and
# 8.5+ (Uri\WhatWg\Url), so pre-8.4 is not-affected for this family.
LEXBOR_MINORS = {(8, 4), (8, 5)}
LEXBOR_FIXED = {(8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}

LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
LIKELY_PATCHED = "LIKELY_PATCHED"
NOT_AFFECTED = "NOT_AFFECTED"
UNKNOWN = "UNKNOWN"

_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(s):
    """'PHP/8.4.26', '8.4.26-1~deb', ... -> (8,4,26) or None."""
    if not s:
        return None
    m = _VER_RE.search(s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _geq(a, b):
    return a >= b


def verdict(version):
    """Core-CVE verdict. `version` is a (maj,min,patch) tuple or a string.
    Returns {verdict, reason, caveats:[...]}."""
    v = version if isinstance(version, tuple) else parse_version(version)
    if v is None:
        return {"verdict": UNKNOWN,
                "reason": "no PHP version available (banner suppressed or not probed)",
                "caveats": ["expose_php=Off removes X-Powered-By; supply the version "
                            "out of band or use a soft/dangerous probe"]}
    maj, minor, _ = v
    key = (maj, minor)
    caveats = []
    if maj != 8 or minor < 1 or minor > 5:
        return {"verdict": NOT_AFFECTED,
                "reason": f"PHP {_s(v)} is outside the affected 8.1-8.5 range",
                "caveats": []}
    if key == (8, 1):
        return {"verdict": LIKELY_VULNERABLE,
                "reason": "PHP 8.1 is EOL; no fixed release exists for this branch",
                "caveats": ["8.1 receives no upstream security releases; confirm the "
                            "distro has not backported the fix"]}
    fixed = CORE_FIXED[key]
    caveats.append("version string alone cannot see distro backports; confirm with a "
                   "soft/dangerous probe before acting")
    if _geq(v, fixed):
        return {"verdict": LIKELY_PATCHED,
                "reason": f"PHP {_s(v)} >= {_s(fixed)} (fixed release for the {maj}.{minor} branch)",
                "caveats": caveats}
    return {"verdict": LIKELY_VULNERABLE,
            "reason": f"PHP {_s(v)} < {_s(fixed)} (fixed release for the {maj}.{minor} branch)",
            "caveats": caveats}


def lexbor_verdict(version):
    """lexbor-family verdict (contains-overflow + IDNA over-read). Sink-gated and
    8.4/8.5-only; see module docstring."""
    v = version if isinstance(version, tuple) else parse_version(version)
    if v is None:
        return {"verdict": UNKNOWN,
                "reason": "no PHP version available",
                "caveats": ["lexbor sinks are 8.4+/8.5+ only"]}
    maj, minor, _ = v
    key = (maj, minor)
    if key not in LEXBOR_MINORS:
        return {"verdict": NOT_AFFECTED,
                "reason": f"lexbor sinks (Dom\\HTMLDocument 8.4+, Uri\\WhatWg\\Url 8.5+) "
                          f"do not exist on PHP {_s(v)}",
                "caveats": []}
    fixed = LEXBOR_FIXED[key]
    caveats = ["lexbor is application-sink-gated (querySelector / Url::parse); absence "
               "of a sink is INCONCLUSIVE, not safe",
               "per-branch fix version for 8.2-8.4 is not independently confirmed here"]
    if _geq(v, fixed):
        return {"verdict": LIKELY_PATCHED,
                "reason": f"PHP {_s(v)} >= {_s(fixed)}",
                "caveats": caveats}
    return {"verdict": LIKELY_VULNERABLE,
            "reason": f"PHP {_s(v)} < {_s(fixed)}",
            "caveats": caveats}


def _s(v):
    return ".".join(map(str, v))


if __name__ == "__main__":
    # self-test: the knife-edges around each branch's fix release
    cases = [
        ("8.4.26", LIKELY_VULNERABLE), ("8.4.27", LIKELY_PATCHED),
        ("8.3.35", LIKELY_VULNERABLE), ("8.3.36", LIKELY_PATCHED),
        ("8.2.34", LIKELY_VULNERABLE), ("8.2.35", LIKELY_PATCHED),
        ("8.5.11", LIKELY_VULNERABLE), ("8.5.12", LIKELY_PATCHED),
        ("8.1.99", LIKELY_VULNERABLE), ("8.0.30", NOT_AFFECTED),
        ("8.6.0", NOT_AFFECTED), ("7.4.33", NOT_AFFECTED), (None, UNKNOWN),
    ]
    ok = True
    for ver, want in cases:
        got = verdict(ver)["verdict"]
        flag = "ok" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] core {str(ver):>8} -> {got} (want {want})")
    lx = [("8.3.35", NOT_AFFECTED), ("8.4.26", LIKELY_VULNERABLE),
          ("8.4.27", LIKELY_PATCHED), ("8.5.11", LIKELY_VULNERABLE),
          ("8.5.12", LIKELY_PATCHED)]
    for ver, want in lx:
        got = lexbor_verdict(ver)["verdict"]
        flag = "ok" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] lexbor {str(ver):>8} -> {got} (want {want})")
    print("ALL OK" if ok else "SELF-TEST FAILED")
    raise SystemExit(0 if ok else 1)

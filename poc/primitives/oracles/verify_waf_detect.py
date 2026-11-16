#!/usr/bin/env python3 -I
"""Classifier verifier for waf_detect.py (offline; no lab needed).

Asserts the WAF/CDN fingerprint (header/Server/cookie signatures) and the
block-vs-crash classifier -- that a 403/429/challenge is NOT read as a worker
crash, while a true transport failure (status None) is.

    python3 -I poc/primitives/oracles/verify_waf_detect.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.oracles import waf_detect as W         # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## fingerprint from headers / Server / cookies")
    ok &= check("CF-RAY -> Cloudflare", W.fingerprint({"CF-RAY": "abc", "Server": "x"}) == "Cloudflare")
    ok &= check("Server: cloudflare", W.fingerprint({"Server": "cloudflare"}) == "Cloudflare")
    ok &= check("Server: AkamaiGHost", W.fingerprint({"Server": "AkamaiGHost"}) == "Akamai")
    ok &= check("X-Sucuri-ID -> Sucuri", W.fingerprint({"X-Sucuri-ID": "11/x"}) == "Sucuri")
    ok &= check("X-Amz-Cf-Id -> CloudFront", W.fingerprint({"X-Amz-Cf-Id": "z"}) == "AWS CloudFront")
    ok &= check("Incapsula cookie", W.fingerprint({"Set-Cookie": "visid_incap_1=y; path=/"}) == "Imperva Incapsula")
    ok &= check("plain nginx -> None", W.fingerprint({"Server": "nginx/1.27.5"}) is None)

    print("## classify: WAF interference is NOT a crash")
    ok &= check("403 -> blocked", W.classify(403, {}, b"Forbidden") == "blocked")
    ok &= check("406 -> blocked", W.classify(406, {}, b"") == "blocked")
    ok &= check("429 -> ratelimited", W.classify(429, {}, b"") == "ratelimited")
    ok &= check("503+Retry-After -> ratelimited", W.classify(503, {"Retry-After": "30"}, b"") == "ratelimited")
    ok &= check("200 + cf challenge body -> challenge",
                W.classify(200, {}, b"<html>Just a moment... /cdn-cgi/challenge-platform</html>") == "challenge")
    ok &= check("403 + challenge body -> challenge (challenge wins)",
                W.classify(403, {}, b"Attention Required! __cf_chl") == "challenge")
    ok &= check("blocked/ratelimited/challenge are interference",
                all(W.is_interference(W.classify(s, h, b)) for s, h, b in
                    [(403, {}, b""), (429, {}, b""), (200, {}, b"just a moment")]))

    print("## classify: real liveness signals are preserved")
    ok &= check("200 -> ok", W.classify(200, {"Server": "nginx"}, b"<html/>") == "ok")
    ok &= check("None -> down (transport failure = worker-liveness signal)",
                W.classify(None, {}, b"") == "down")
    ok &= check("down is NOT interference", not W.is_interference("down"))
    ok &= check("502 -> other (own/app 5xx, not a WAF verdict)", W.classify(502, {}, b"") == "other")
    ok &= check("500 empty -> other", W.classify(500, {}, b"") == "other")

    print("## retry_after parse")
    ok &= check("Retry-After: 30 -> 30", W.retry_after({"Retry-After": "30"}) == 30)
    ok &= check("no Retry-After -> None", W.retry_after({}) is None)

    print("\n==== verify_waf_detect: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

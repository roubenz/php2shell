#!/usr/bin/env python3
"""verify_config_probe.py - self-test for config_probe (header/JSON/phpinfo parse).

No lab needed (parses representative response shapes). Invocation:
    python3 -I poc/primitives/oracles/verify_config_probe.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))  # poc/
from primitives.oracles.config_probe import read_fingerprint  # noqa: E402

if __name__ == "__main__":
    fp = read_fingerprint(200, {"Server": "nginx/1.27.5", "X-Powered-By": "PHP/8.4.27"},
                          b'{"php":"8.4.27","sapi":"fpm-fcgi","memory_limit":"16M"}')
    ok = (fp["version"] == (8, 4, 27) and fp["sapi"] == "fpm"
          and fp["config"].get("memory_limit") == "16M")
    fp2 = read_fingerprint(200, {"Server": "Apache/2.4.69", "X-Powered-By": "PHP/8.4.26"}, b"")
    ok &= fp2["sapi"] == "apache"
    # no Server header + no JSON -> SAPI is ambiguous (php -S vs stripped proxy)
    fp3 = read_fingerprint(200, {"X-Powered-By": "PHP/8.4.26"}, b"not json")
    ok &= fp3["version"] == (8, 4, 26) and fp3["sapi"] is None
    # but the JSON sapi field resolves it (as the labs expose)
    fp4 = read_fingerprint(200, {"X-Powered-By": "PHP/8.4.26"},
                           b'{"php":"8.4.26","sapi":"cli-server"}')
    ok &= fp4["sapi"] == "cli-server"
    print(f"  fpm={fp['sapi']} apache={fp2['sapi']} headeronly={fp3['sapi']} "
          f"json-cli={fp4['sapi']}")
    print("PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)

#!/usr/bin/env python3 -I
"""Verifier for upload_progress_output.py (offline; no lab needed).

Asserts the webshell-output parser: slices command output between the 'upload_progress_' key
prefix and the serialized-array tail (b"|a:" / b"|a:5"), with graceful fallback when absent.

    python3 -I poc/primitives/oracles/verify_upload_progress_output.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.oracles import upload_progress_output as upo  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    body = b"...junk...upload_progress_XXuid=33(www-data) gid=33|a:5:{s:5:...}tail"
    ok &= check("extracts between key prefix and |a:5",
                upo.webshell_output(body, tail=b"|a:5") == "XXuid=33(www-data) gid=33")
    ok &= check("default tail |a: also works",
                upo.webshell_output(body) == "XXuid=33(www-data) gid=33")
    ok &= check("no key prefix -> stripped body fallback",
                upo.webshell_output(b"  plain output  ") == "plain output")
    ok &= check("key present but tail absent -> rest of body",
                upo.webshell_output(b"upload_progress_ZZhello") == "ZZhello")
    print("\n==== verify_upload_progress_output: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

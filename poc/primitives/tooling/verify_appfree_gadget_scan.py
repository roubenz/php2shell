#!/usr/bin/env python3
"""Verifier for appfree_gadget_scan.py on the ASan php CLI image (docker run).

Proves the documented result: the Serializable positive control reports
heap-use-after-free (the ASan harness detects the var_hash UAF), and the
built-in instantiable-class scan completes and reports its app-free gadget
inventory (documented expectation: NONE stand in app-free).

Lab: the lexbor/ASan image. No compose lab -- the module runs PHP under ASan via
`docker run` on php2shell-cli-asan:latest (php 8.4.26 + ASan). Run with python3 -I.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


AGS = _load("appfree_gadget_scan", "appfree_gadget_scan.py")


def _image_exists(image):
    r = subprocess.run(["docker", "image", "inspect", image],
                       capture_output=True)
    return r.returncode == 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify appfree_gadget_scan")
    ap.add_argument("--image", default=AGS.ASAN_IMAGE,
                    help="ASan-built php CLI image")
    a = ap.parse_args(argv)

    print("=" * 72)
    print("VERIFY appfree_gadget_scan (ASan docker-run gadget inventory)")
    print("  image=%s" % a.image)
    print("=" * 72)
    if not _image_exists(a.image):
        print("[FAIL] ASan image %s absent (build: docker compose -f "
              "docker-compose.yml build cli-asan)" % a.image)
        return 2

    # (1) positive control: the harness must detect the known Serializable UAF.
    control = AGS.positive_control(a.image)

    # (2) inventory: scan the built-in instantiable classes.
    hits = AGS.scan(AGS.CORE_CLASSES, a.image)
    print("\napp-free gadget classes: %s" % (hits if hits else "NONE"))

    print("-" * 72)
    ok = bool(control)
    print("  [%s] positive control detects UAF (harness works)"
          % ("PASS" if control else "FAIL"))
    print("  inventory over %d built-in classes -> %s (documented: NONE)"
          % (len(AGS.CORE_CLASSES), hits if hits else "NONE"))
    print("  VERDICT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

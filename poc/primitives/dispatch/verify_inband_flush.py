#!/usr/bin/env python3
"""Harness for inband_flush.py.

Proves the in-band output-recovery primitive WITHOUT the full crashing chain, by
standing in for the target: we run the exact wrapped shell command via /bin/sh
and check extract() against the output (and against a simulated Apache tail-drop).

  T1  wrap -> run -> extract round-trips the command output
  T2  the >8 KB flush pad survives an Apache-style <8 KB tail drop, where an
      un-padded command loses its end marker (the primitive's whole point)
  T3  the pad out-sizes Apache's ~8 KB unflushed tail (END-to-EOF >= 8192 B)
  T4  (optional, reuses a running apache lab) the wrapped command run inside the
      container round-trips through extract(); SKIPPED if no apache lab is up

Run from OUTSIDE the project:
    python3 -I poc/primitives/dispatch/verify_inband_flush.py
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from inband_flush import END, wrap_command, extract  # noqa: E402

RESULTS = []
_DROP = 8000  # simulated Apache unflushed-tail drop (< the 8 KB threshold)


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name, (" - " + detail) if detail else ""))


def _run(wrapped):
    return subprocess.run(["/bin/sh", "-c", wrapped], capture_output=True,
                          text=True, timeout=60).stdout


def t1_roundtrip():
    out = _run(wrap_command("echo marker-123; echo second-line"))
    got = extract(out)
    record("T1 wrap/run/extract round-trip", got == "marker-123\nsecond-line",
           "got=%r" % got)


def t2_pad_survives_drop():
    padded = _run(wrap_command("echo keep-me"))
    plain = _run(wrap_command("echo keep-me", flush_pad=0))
    padded_after = extract(padded[:-_DROP])            # pad absorbs the drop
    plain_after = extract(plain[:-_DROP])              # end marker lost
    ok = padded_after == "keep-me" and plain_after is None
    record("T2 flush pad survives an <8KB tail drop (un-padded loses it)", ok,
           "padded=%r plain=%r" % (padded_after, plain_after))


def t3_pad_outsizes_tail():
    out = _run(wrap_command("echo x"))
    tail = len(out) - (out.rfind(END) + len(END))
    record("T3 pad out-sizes Apache's ~8KB tail (END-to-EOF >= 8192)",
           tail >= 8192, "end_to_eof=%dB" % tail)


def t4_container():
    svc = None
    for name in ("php2shell-apache-stock-1", "php2shell-apache-pool-1", "php2shell-cli-stock-1"):
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == "true":
            svc = name
            break
    if svc is None:
        record("T4 container round-trip", True, "SKIPPED: no running apache/cli lab")
        return
    r = subprocess.run(["docker", "exec", svc, "sh", "-c",
                        wrap_command("id -u; echo in-container")],
                       capture_output=True, text=True, timeout=60)
    got = extract(r.stdout)
    record("T4 container round-trip via %s" % svc,
           got is not None and "in-container" in got, "got=%r" % got)


def main():
    t1_roundtrip()
    t2_pad_survives_drop()
    t3_pad_outsizes_tail()
    t4_container()
    passed = sum(1 for _, ok in RESULTS if ok)
    print("\n%d/%d checks passed" % (passed, len(RESULTS)))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())

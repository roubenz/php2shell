#!/usr/bin/env python3
"""Offline self-test for oom_classifier.

Pure arithmetic / no network: checks page_fatal_size against the worked
example and edge cases, checks aligned_request_size, and drives classify()
over synthetic response bodies for every category.

Run:
    python3 -I poc/primitives/oracles/verify_oom_classifier.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oom_classifier as D  # noqa: E402


def selftest_arithmetic():
    print("== pure-arithmetic self-test (no network) ==")
    # Worked example from the spec.
    assert D.page_fatal_size(1048576) == 1052672, D.page_fatal_size(1048576)
    assert D.page_fatal_size(1048576) == 257 * 4096
    # General shape: round_up(L + 24, 4096).
    assert D.page_fatal_size(0) == 4096
    assert D.page_fatal_size(4072) == 4096          # 4072 + 24 == 4096 exactly
    assert D.page_fatal_size(4073) == 8192
    assert D.page_fatal_size(6000000) == 6000640    # 1465 * 4096
    print("  page_fatal_size: worked example 1048576 -> 1052672 OK; "
          "edge cases OK")

    # Empirical aligned request size (what PHP's OOM message reports): L + 32
    # for L divisible by 8 (header 24 + NUL 1, rounded to 8).
    assert D.aligned_request_size(6000000) == 6000032
    assert D.aligned_request_size(5000000) == 5000032
    assert D.aligned_request_size(1048576) == 1048608
    print("  aligned_request_size: 6000000 -> 6000032 (= L+32) OK")

    # classify() over synthetic bodies, exercising every category.
    L = 6000000
    body_target_aligned = (b"...Allowed memory size of 16777216 bytes exhausted "
                           b"(tried to allocate %d bytes) in ..."
                           % D.aligned_request_size(L))
    cat, m, pred = D.classify(body_target_aligned, L)
    assert cat == "target-size", (cat, m, pred)
    assert m == D.aligned_request_size(L)
    assert pred == D.page_fatal_size(L)

    body_target_page = (b"Allowed memory size of 16777216 bytes exhausted "
                        b"(tried to allocate %d bytes)" % D.page_fatal_size(L))
    cat2, _, _ = D.classify(body_target_page, L)
    assert cat2 == "target-size", cat2

    body_intermediate = (b"Allowed memory size of 16777216 bytes exhausted "
                        b"(tried to allocate 20480 bytes)")
    cat3, m3, _ = D.classify(body_intermediate, L)
    assert cat3 == "intermediate", (cat3, m3)

    # Sub-L headroom value (the value-buffer ceiling case) -> intermediate.
    cat3b, _, _ = D.classify(b"tried to allocate 6296371 bytes", 16000000)
    assert cat3b == "intermediate", cat3b

    body_blind = b"<html>normal 200, no fatal here</html>"
    cat4, m4, _ = D.classify(body_blind, L)
    assert cat4 == "blind" and m4 is None, (cat4, m4)

    # Alternate phrasing extraction.
    assert D.extract_m(b"bytes exhausted (tried to allocate 40960)") == 40960
    assert D.extract_m(b"tried to allocate 123456 bytes") == 123456
    print("  classify: target-size (aligned & page), intermediate (small & "
          "sub-L), blind, and both error phrasings OK")
    print("  PASS (arithmetic/offline)")


if __name__ == "__main__":
    selftest_arithmetic()

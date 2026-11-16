#!/usr/bin/env python3
# INDEX: classify oom response for groom calibration | all | needs display_errors on
"""Classify a PHP OOM "tried to allocate M" response for groom calibration.

When display_errors is On, an exhausted memory_limit prints "Allowed memory
size of N bytes exhausted (tried to allocate M bytes)". M names the allocation
that hit the ceiling. Given the field length L that provoked it, classify()
labels the response target-size (M is the field allocation itself),
intermediate (a smaller internal allocation tripped first), blind (no M in the
body) or other, and extract_m() pulls M out. This lets memory_limit groom
calibration pick the field size whose OOM is the field allocation rather than a
premature resize. Pure regex + arithmetic, no external dependencies.
"""
import re

PAGE = 4096
ZSTR_HEADER = 24          # _ZSTR_HEADER_SIZE on 64-bit
ZSTR_NUL = 1              # trailing NUL byte
ZEND_MM_ALIGNMENT = 8     # ZEND_MM_ALIGNED_SIZE granularity

M_PATTERNS = (
    re.compile(rb"tried to allocate (\d+) bytes"),
    re.compile(rb"bytes exhausted \(tried to allocate (\d+)\)"),
)


def page_fatal_size(length, page=PAGE):
    """Spec model: round_up(length + 24, page). Worked check:
    page_fatal_size(1048576) == 1052672 (== 257 * 4096)."""
    return ((length + ZSTR_HEADER + page - 1) // page) * page


def aligned_request_size(length, alignment=ZEND_MM_ALIGNMENT):
    """The size zend_mm reports for a zend_string of `length` bytes: the
    8-aligned struct size (header + length + NUL), BEFORE page rounding
    (== length + 32 for length % 8 in the common case)."""
    raw = length + ZSTR_HEADER + ZSTR_NUL
    return ((raw + alignment - 1) // alignment) * alignment


def extract_m(body):
    """Regex-extract M (tried-to-allocate bytes) from an HTTP response body, or
    None if no fatal is present."""
    if body is None:
        return None
    if isinstance(body, str):
        body = body.encode("latin1", "replace")
    for pat in M_PATTERNS:
        m = pat.search(body)
        if m:
            return int(m.group(1))
    return None


def classify(body, length):
    """Return (category, M, predicted) for an observed response body and the
    field length that produced it. `predicted` is the spec page_fatal_size(L).
    category in {"target-size", "intermediate", "blind", "other"}."""
    predicted = page_fatal_size(length)
    aligned = aligned_request_size(length)
    m = extract_m(body)
    if m is None:
        return ("blind", None, predicted)
    # target-size: M names the field-sized allocation. Accept the spec
    # page-rounded value, the empirical 8-aligned request size, or any M that
    # tracks the field length within a couple of pages (header/rounding slack).
    if m == predicted or m == aligned or (length <= m <= length + 2 * PAGE):
        return ("target-size", m, predicted)
    # intermediate: a smaller internal allocation tripped first - either a
    # clean small page multiple (the observed 20480/40960 case) or any grow
    # that capped out below the field length.
    if m < length or (m % PAGE == 0 and m < (1 << 21)):
        return ("intermediate", m, predicted)
    return ("other", m, predicted)

#!/usr/bin/env python3
"""session_ids.py - shared PHPSESSID test constants (project plumbing).

Two fixed session ids the PoCs reuse: a fat/producer session and a small,
non-empty consumer session. Kept in one place so every chain and PoC grooms
with identical ids.
"""

SID_A = "abcdef0123456789abcdef0123456789"  # fat session: the producer's OOM target
SID_B = "0123456789abcdef0123456789abcdef"  # small, non-empty consumer session

#!/usr/bin/env python3
r"""Shared scaffolding for the two ZendMM free-list write primitives (in-slot
next+shadow poison; raw unshadowed head seat). Build constants, the gdb
printf-tag parser, the human size formatter, the live-allocator heap_of() driver
base, and the report skeleton. The two distinct write mechanisms live in their
own modules.
"""
from __future__ import annotations

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.proc_gdb import GdbDriver, gdb as _gdb  # noqa: E402
from common.zend_mm import (  # noqa: E402
    CHUNK_SIZE as CHUNK_ALIGN, BIN_DATA_SIZE, SHADOW_OFFSET)

# Build constants (php-src 8.4.26, Zend/zend_alloc.c + zend_alloc_sizes.h).
# A 280-byte emalloc rounds up to the 320-byte size class (bin index 16): the
# bins run ... 256, 320, 384 ... so 257..320 land in bin-320. CHUNK_ALIGN (the
# 2 MiB chunk size), BIN_DATA_SIZE and SHADOW_OFFSET are re-exported above from
# common/zend_mm.py.
DEFAULT_ALLOC_SIZE = 280

# repo root is four levels up: .../poc/primitives/write/<file>
DEFAULT_COMPOSE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))),
    "docker-compose.fpm-avenues.yml")

MASK64 = 0xFFFFFFFFFFFFFFFF

FORWARD_CAP = 253 * 64            # 253*64 ~= 16 KiB reference bound


# gdb printf-tag parser.
def _parse_tags(text, prefix="FLP"):
    """Collect labeled '<prefix> <tag>=<hex-or-string>' lines the gdb printf emits."""
    out = {}
    for m in re.finditer(rf"{prefix} (\w+)=(.+)", text):
        k, v = m.group(1), m.group(2).strip()
        try:
            out[k] = int(v, 16) if v.startswith("0x") else int(v)
        except ValueError:
            out[k] = v
    return out


def _human(n):
    n = abs(n)
    for u, s in ((1 << 40, "TiB"), (1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")):
        if n >= u:
            return "%.1f %s" % (n / u, s)
    return "%d B" % n


# Live-allocator driver base: heap_of() is identical bar the gdb printf label.
class _FreeListGdb(GdbDriver):
    """Drives the LIVE allocator via its exported symbols through gdb; TAG names
    the gdb printf label the subclass emits and parses back."""

    TAG = "FLP"

    def heap_of(self, pid):
        txt = _gdb(self.compose_file, self.service, pid, [
            f'printf "{self.TAG} heap=%#lx\\n", (unsigned long)zend_mm_get_heap()'])
        return _parse_tags(txt, self.TAG).get("heap")


# Report skeleton shared by the two print_report()/report builders.
def _report_banner(title, workers):
    print("=" * 78)
    print("%s -- php-fpm 8.4.26 (workers %s)" % (title, workers))
    print("=" * 78)


def _base_report(workers, size):
    return {"workers": workers, "size": size, "bin_data_size": BIN_DATA_SIZE}

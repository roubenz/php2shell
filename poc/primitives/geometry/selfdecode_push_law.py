#!/usr/bin/env python3
# INDEX: rfc1867 upload_progress self-decode var_push count + channel-reachability law | source-derived
"""Push geometry of the rfc1867 upload_progress session self-decode
(ext/session/session.c php_session_rfc1867_callback FILE_START + FILE_END;
ext/standard/var_unserializer.re). Finisher-agnostic: what the built-in,
app-code-free re-decode of a persisted progress array drives through a reused
`BG(unserialize)` dangle.

The progress array rfc1867 builds is pure arrays + scalars with UNIQUE keys and
NO objects:
    { start_time:L, content_length:L, bytes_processed:L, done:B,
      files: [ 0 => { field_name:S, name:S, tmp_name:(null|S), error:L,
                      done:B, start_time:L, bytes_processed:L }, 1 => {...}, ... ] }

`php_var_unserialize_internal` runs `var_push(var_hash, rval)` at the top of every
non-'R' value decode -> each decoded VALUE (scalar or array container) pushes ONE
destination-zval pointer onto the E channel (`d->last`, stride 8). Keys decode with
var_hash=NULL -> never push. `var_push_dtor_value` fires ONLY on a duplicate key
(Z_TYPE_INFO != IS_NULL) and `var_tmp_var` only for objects/__wakeup -> NEITHER
occurs in this array. So the self-decode drives the E channel EXCLUSIVELY; the DT
(var_dtor / last_dtor / clean .bss auto_append) finisher family is structurally
unreachable from it.

Counts (per file: 7 scalar/array leaf values during upload, 8 once tmp_name is
added at FILE_END):
    push_count(k, tmp_name) = 6 + (8 if tmp_name else 7) * k
The top frame contributes 6 (top array + 4 scalars + files array); minimum k is 1
(upload_progress only creates the entry on an actual file part) -> floor 14. The run
is CONTIGUOUS and the final leaf is always a LONG (bytes_processed), so the last
push's rval points at a long-valued bucket -> a ps_files->basedir landed on it is
not a usable path. Source-derived; see verify_selfdecode_push_law.py.
"""
from __future__ import annotations

TOP_VALUES = 6          # top array + {start_time, content_length, bytes_processed, done} + files array
FILE_VALUES_UPLOAD = 7  # field_name, name, tmp_name(null), error, done, start_time, bytes_processed
FILE_VALUES_FINAL = 8   # + tmp_name promoted to a string at FILE_END (still unique key)


def push_count(k_files, tmp_name=True):
    """E-channel var_push count for a persisted progress array with `k_files`
    file sub-arrays. tmp_name=True once FILE_END promoted tmp_name to a string."""
    if k_files < 1:
        raise ValueError("upload_progress creates the entry only on a file part (k>=1)")
    per = FILE_VALUES_FINAL if tmp_name else FILE_VALUES_UPLOAD
    return TOP_VALUES + per * k_files


def reaches_dt_channel():
    """The self-decode never drives var_push_dtor/var_tmp_var: rfc1867's array has
    unique keys and no objects. The clean .bss/auto_append (last_dtor) finisher is
    unreachable from it."""
    return False

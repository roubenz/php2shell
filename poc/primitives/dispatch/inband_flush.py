#!/usr/bin/env python3
# INDEX: mark command output and recover it | fpm apache
"""Mark a command's output in an HTTP response and recover it.

wrap_command() returns a single shell-command string that brackets the
command's output with markers and appends a block of throwaway lines
(`seq 1 PAD`) after the end marker. extract() returns the text framed between
the markers in a response (bytes or str), or None if the markers are absent.

Ported from JoasASantos/php2shell-exploit (exploit.py INBAND_FLUSH_PAD).

    full = wrap_command("id; uname -a")
    out = extract(resp)

stdlib only.
"""
from __future__ import annotations

START = "<<<P2S_INBAND>>>"
END = "<<<P2E_INBAND>>>"
# number of `seq` lines of padding after the end marker; 3000 ~ 13 KB.
FLUSH_PAD = 3000


def wrap_command(cmd, start=START, end=END, flush_pad=FLUSH_PAD):
    """Wrap `cmd` so its output is bracketed by markers and followed by
    `flush_pad` throwaway lines (one shell command string, no newlines)."""
    return "echo '%s';%s;echo '%s';seq 1 %d" % (start, cmd, end, flush_pad)


def extract(resp, start=START, end=END):
    """Return the output framed between the markers in an HTTP response (bytes or
    str), or None if they are absent."""
    text = resp.decode("utf-8", "replace") if isinstance(resp, (bytes, bytearray)) else resp
    if "\r\n\r\n" in text:                       # drop headers if a raw response
        text = text.split("\r\n\r\n", 1)[1]
    s = text.find(start)
    e = text.find(end)
    return text[s + len(start):e].strip() if (s >= 0 and e > s) else None


if __name__ == "__main__":  # smoke test (no network): wrap -> run -> extract
    import subprocess
    full = wrap_command("echo marker-123")
    out = subprocess.run(["/bin/sh", "-c", full], capture_output=True, text=True).stdout
    print("extract ->", extract(out))

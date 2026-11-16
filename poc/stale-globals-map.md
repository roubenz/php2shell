# Stale-globals map — pre-RINIT OOM dangling globals (CVE-2026-109618/619)

Reference catalog of every engine/module global that the official patch
[`3584a98`](https://github.com/php/php-src/commit/3584a98bda) had to reset, the
mechanism that leaves each one stale, whether we already weaponise it, and the
exploitation status of each.

Captured 2026-10-23 from triage of **`segfo/php2shell-poc`** (a fork of
`ikow`/Qi Deng's repo that adds a "Chain D" OOM/stale-global line of work:
`docs/CHAIN_D_ANALYSIS.md`, `docs/CHAIN_D_CLAIM_VERIFICATION.md`,
`docs/chain_d_rce_handoff.md`, `poc/chain_d_rce_final.py`).

This is **reference material**, not a runnable module. It cross-references the
dangle catalog against our own chains so we never (a) re-derive what the patch
already tells us, or (b) mis-count a known-stale global as a "new primitive".

---

## 0. The shared mechanism (all rows below depend on it)

The request lifecycle (`main/main.c` `php_request_startup`, 8.4.26, already
`/proc`+gdb-verified in `poc/primitives/groom/rshutdown_dangle.py`):

```
zend_activate();              # ZMM init + init_executor()  -> EG() RE-initialised
sapi_activate();
php_hash_environment();       # POST BODY PARSED HERE  <-- rfc1867 OOM fires here
  -> treat_data(PARSE_POST) -> rfc1867 multipart parser
     -> php_session_rfc1867_update -> php_session_initialize (session decode, pre-RINIT)
     -> big tail field exhausts memory_limit -> zend_bailout()/longjmp()
zend_activate_modules();      # module RINIT (session RINIT) -- NEVER REACHED on OOM
PG(modules_activated)=1;      # NEVER REACHED on OOM
```

Because the OOM `longjmp`s out of `php_hash_environment`, **module RINIT and
`php_rshutdown_session_globals()` are skipped**, so the module-global `PS()`
pointers allocated during the pre-RINIT session decode are never cleared and are
left dangling into freed request-heap once the ZMM request arena is torn down.
The patch closes the window by calling `php_rinit_session_globals()` from
`MULTIPART_EVENT_START` (before the rfc1867 callback can run).

Two independent patch hardenings sit on top:
- `in_rfc1867_update` + **`incomplete_classes_only`** decode mode — the pre-RINIT
  session decode now restores every `O:` object as `__PHP_Incomplete_Class`
  (no autoload, no `__wakeup`, no `__unserialize`), neutering object-injection on
  this path.
- **delayed-OOM** (`ZEND_HAS_OOM` macro + `zend_handle_delayed_oom()`,
  `femalloc`/`safe_ferealloc`) — replaces the immediate `longjmp` inside the
  rfc1867 parser with flag-based unwinding, so the parser's own
  `param`/`filename`/`key` frees are no longer skipped (fixes the partially-built
  `$_FILES`/`$_SESSION` residue).

---

## 1. The catalog

| Global | Where/how it dangles | Patch reset | Our coverage | Exploit status |
|---|---|---|---|---|
| `PS(http_session_vars)` (the `$_SESSION` reference) | allocated by `php_session_track_init()` during pre-RINIT decode; RSHUTDOWN skipped → ref into freed heap | `php_rinit_session_globals()` | **HAVE — `poc/primitives/groom/rshutdown_dangle.py`** (deterministic reclaim, confirmed on 8.4.26 apache) | UAF proven; needs a leak for RCE (AUGMENT) |
| `PS(mod_data)` (`ps_files*`) | allocated in pre-RINIT `php_session_initialize`; dangling after arena teardown | `php_rinit_session_globals()` | partial — same family/mechanism as above; our live-carrier grooms `ps_files` via `last_key`, so the struct is already in scope | UAF real; segfo did not weaponise (see §2) |
| `PS(id)`, `PS(session_vars)`, `PS(rfc1867_progress)`, `PS(session_status)` | same pre-RINIT path; `session_status` retains `php_session_active`/stale value | `php_rinit_session_globals()` | implied by the mechanism we already drive | not individually weaponised |
| `EG(objects_store).object_buckets` + `.top` | `shutdown_executor()` fast-path leaves `object_buckets` pointing at freed ZMM | `object_buckets=NULL; top=1;` | **NOT present** before this doc | **DoS/SIGSEGV only — RCE unproven, cross-request reality DUBIOUS (see §2)** |
| `EG(user_error_handler)` | stale handler ptr from previous request | reset to UNDEF in `zend_shutdown_executor_values()` | not modelled | reset-only; no public weaponisation |
| `EG(exception)` | stale exception object (dangling) | reset | not modelled | reset-only |
| `EG(record_errors)` / `num_errors` / `errors` | stale error buffer | reset | not modelled | reset-only |
| `BG(serialize)` cache (`var_hash` struct at `BG+0x350`, `refcount BG+0x358`, `lock BG+0x338`) | `php_var_unserialize_init` REUSE-path returns the stale struct without re-init | reset via the delayed-OOM/cleanup path | **HAVE — var_hash_rw** (`primitives/read_leak/var_hash_rw.py`, `universal_remote_rce.py`) | this is our var_hash_rw var_hash UAF |
| `$_SESSION` symbol-table global | populated in `incomplete_classes_only` mode, leaks into script scope | `zend_delete_global_variable("_SESSION")` at `MULTIPART_EVENT_END` | not modelled (we don't use the leaked-$_SESSION path) | type-confused-object leak; neutered by incomplete-classes |

Patch footprint (per author): 389 files, +10,759 lines; CVSS 9.2. The breadth is
evidence every row above was reachable — but breadth is **not** proof each row is
independently RCE-able.

---

## 2. Verdicts on the two flagged "new" items

### (a) `EG(objects_store).object_buckets` UAF — NOT a new RCE primitive

**Verdict: CONFIRMED-author-only as a DoS (SIGSEGV) on PHP 8.2.33; cross-request
UAF mechanism DUBIOUS/likely-misattributed; NOT a weaponizable RCE primitive.**

- The author's own `CHAIN_D_CLAIM_VERIFICATION.md` concludes:
  *"Chain D 単独での RCE: 現時点では未実証"* — DoS CONFIRMED, UAF primitive
  CONFIRMED, **RCE not demonstrated** (heap feng-shui + ASLR bypass unimplemented).
- The shipped "Chain D RCE achieved" commit (`poc/chain_d_rce_final.py`) does
  **not use `object_buckets` at all**. It is a different primitive entirely —
  see §3.
- **Mechanism doubt (ours, source-grounded):** the claimed crash is a
  *cross-request* follow-up ("Request 3 deserializes objects through stale
  `object_buckets`"). But `zend_activate() → init_executor()` runs at the start
  of **every** request and calls `zend_objects_store_init()`, allocating a
  **fresh** `object_buckets` **before** `sapi_activate()`/the rfc1867 decode on
  that follow-up request. So on the follow-up the decode writes through the
  *fresh* store, not the stale one. The author flags exactly this in
  `chain_d_rce_handoff.md` §5.2 ("init_executor が EG を再初期化するなら
  objects_store.object_buckets は fresh のはず… クラッシュが本当に stale
  object_buckets 経由なのか…不明"). The observed SIGSEGV is far more likely the
  **PS()-family dangle we already own** (`poc/primitives/groom/rshutdown_dangle.py`) or a generic
  corrupted-session-decode crash, mis-attributed to `object_buckets`.
- `object_buckets` genuinely *does* dangle **within the same request**, between
  `shutdown_executor()` and ZMM teardown — but there is no attacker-controlled
  path that *creates objects* in that interval, so it is not reachable.
- **Value to us:** low. As a DoS oracle it is redundant with
  `poc/primitives/oracles/munmap_sigsegv_oracle.py` and `poc/primitives/groom/rshutdown_dangle.py`. No module built (no
  proven RCE, dubious cross-request reality, redundant with existing oracles).
  Not attempted live on our stack because a distinguishing repro would need a
  gdb watchpoint on `object_buckets` to separate it from the PS-family crash,
  which is high-effort for a DoS-only, likely-misattributed primitive. Author's
  harness (`chain_d_uaf_verify.py`) is referenced but **not shipped** in the
  repo, so there was nothing to run directly.

### (b) Stale-globals map — CONFIRMED valuable, landed as this doc

The catalog in §1 is the capturable deliverable. It is authoritative because it
is derived from the official patch's reset list, and it tells us precisely which
dangles we already own vs. which are reset-only dead-ends. **Net new to us:** the
`EG()` error/exception resets and the `object_buckets` row (documented here as a
dead-end so nobody re-chases it).

### (c) Chain C handler-mismatch — deferred to the parallel effort

Being actively built by another agent in this tree **right now** (untracked
`lab/shmismatch/` with `index.php`/`legacy.php`/`safe.php`, and a modified
`poc/php2shell.py`). Not duplicated here. segfo-specific contributions worth
folding into that work:
- **Payload-in-filename:** gadget delivered as the upload *filename*
  `x|O:CLASS:N:{...}` written in `php_serialize` format, read back under the
  `php` handler which splits on `|` → deserialize (`exploit/chain_c_mismatch_rce.py`,
  `exploit/chain_d_oom_rce.py`).
- **`__destruct` fires on decode FAILURE:** the trailing data makes the `php`
  decoder return FAILURE, but `__destruct` has **already fired** during
  `PHP_VAR_UNSERIALIZE_DESTROY(var_hash)` — the "session destroyed" is the
  trigger, not a guard (`docs/ANALYSIS.md` §3.5). Matches rafalohaki/repo-3.
- **Two delivery variants:** (i) two-dir `.user.ini`
  (`php_serialize` dir + `php` dir, pre-auth, FPM) — what `lab/shmismatch`
  models; (ii) **same-dir `PS(serializer)` leak across FPM workers** — any
  endpoint doing `ini_set('session.serialize_handler','php_serialize')`
  (Laravel/Symfony) pollutes the persistent worker, no second dir needed. Variant
  (ii) is the stronger "no two-dir config" angle for the parallel build.

---

## 3. Shipped "Chain D RCE" = ZMM-header `custom_heap` hijack (local /proc write)

`poc/chain_d_rce_final.py` achieves RCE but is a **local, `/proc/PID/mem`-seeded
arbitrary-write** exploit (same trust class as our `/proc`-seeded var_hash_rw paths),
**not** a remote delivery and **not** via `object_buckets`:

1. OOM leaves the 2MB ZMM main chunk mapped (`full=false` teardown keeps it).
2. `/proc/PID/mem` poisons `heap->free_slot[24]` → redirects a 1280-byte-bin
   (`arData` for a 20-entry mixed HashTable) allocation to a controlled page.
3. During a `sleep()` window it writes the shell command into the first 128 B of
   that page (the hash-indices area — no gc header, so byte 0 *is* the command,
   dodging the `zend_string` refcount=1 → `system("\x01")` problem).
4. Sets `heap->custom_heap._free = system` (+ `_malloc`/`_realloc`) and
   `heap->use_custom_heap = 1`.
5. On cleanup `zend_hash_destroy()` → `efree(hash_indices)` → `system(cmd)`.

We do **not** currently have the `custom_heap._free=system` single-write RCE
technique in-tree (our cookie over-read uses forward-HT `pDestructor→libphp`). It is a clean,
build-independent finisher given any ZMM-chunk arbitrary write; recorded here as
a technique, not built (redundant with our existing `/proc`-seeded RCE and owned
by a local-only threat model).

### ZMM `zend_mm_heap` chunk-header offsets (build-independent structural)

From `chain_d_rce_final.py`, relative to the 2MB chunk base (the chunk header
*is* the heap struct for the main chunk). These are struct layout, not per-binary
symbols — reusable across builds (verify per major PHP version):

| field | offset | meaning |
|---|---|---|
| `heap->use_custom_heap` | `0x40` | int; set to 1 to route all (e)malloc/free through custom fns |
| `heap->free_slot[0..29]` | `0x60` | per-bin free-list heads; `free_slot[bin]` at `0x60 + bin*8` |
| `heap->custom_heap._malloc` | `0x1A8` | fn ptr |
| `heap->custom_heap._free` | `0x1B0` | fn ptr ← set to `system` |
| `heap->custom_heap._realloc` | `0x1B8` | fn ptr |
| `heap->map[512]` | `0x208` | per-page run map; `0x80000000\|bin` marks a page SRUN(bin) |

Bin math used: 20-entry mixed HashTable → `nTableSize=32` → hash `128B` + data
`32*sizeof(Bucket)=1024B` = `1152B` → bin 24 (1280B), 3 slots/4KB page.

---

## 4. Foreign-build offsets (reference only — do NOT cross-apply)

From `docs/chain_d_rce_handoff.md`, derived on the author's **PHP 8.2.33 mod_php
`libphp` (Apache, Debian)** — a *different* binary than any of our builds. Record
for provenance; re-derive before use (same discipline as `offsets-reference.md`).

| symbol | offset | seg |
|---|---|---|
| `zif_system` | `0x4C0A80` | .text |
| `var_destroy` | `0x3ebb50` | .text |
| `php_var_unserialize_init` | `0x3e9610` | .text |
| `php_var_unserialize_destroy` | `0x3ebea0` | .text |
| `ps_srlzr_decode_php` | `0x346dd0` | .text |
| `zend_hash_destroy` | `0x49b490` | .text |
| `rc_dtor_func` | `0x487060` | .text |
| `basic_globals` (BG) | `0xf4b020` | BSS |
| `core_globals` (PG) | `0xf4ee80` | BSS |
| `ps_globals` (PS) | `0xf39120` | BSS |
| `ps_serializers` | `0xf33220` | .data (rw-p) |

BG struct field offsets (8.2.x, matches our var_hash_rw model): `serialize_lock BG+0x338`,
`cached var_hash ptr BG+0x350`, `refcount BG+0x358`; within the var_hash struct
`var_entries +0x00`, `first_dtor +0x08`, `last_dtor +0x10`.
`php_var_unserialize_init` ALLOC path `emalloc(0x2018=8216B)`; REUSE path entered
when `lock==0 && refcount!=0` and returns the stale struct **without
re-initialising fields** — this is the var_hash_rw primitive, independently
corroborated here.

---

## 5. Provenance
- Source: `segfo/php2shell-poc` @ commit `3932045` ("Chain D RCE achieved: arData
  hijack via free_slot poisoning + custom_heap"), cloned 2026-10-23.
- Upstream author of the repo body: `ikow` / Qi Deng (segfo is a fork adding the
  Chain D work).
- Our overlapping chains: `poc/primitives/groom/rshutdown_dangle.py` (PS dangle),
  `poc/primitives/read_leak/var_hash_rw.py` + `poc/chains/universal_remote_rce.py` (BG var_hash),
  `poc/primitives/oracles/munmap_sigsegv_oracle.py` (DoS oracle).

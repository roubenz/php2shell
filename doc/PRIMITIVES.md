# Primitives

Index of `poc/primitives/**` — 

**Legend** — `sapi`: fpm · apache · cli · all (a version only when the primitive
is narrow, e.g. `8.4-8.5`). `gate`: the one condition of use (e.g. `sink-free`,
`needs /proc`, `gdb-calib`, `1-request`); omitted when there is none.

**Row** — `` `path` — what · sapi · gate ``, one per primitive, sorted
by path. Sections mirror the subfolders of `poc/primitives/`.

sapi is suggestive, where it is tested. It does not mean it won't work on other sapis.

## read_leak

- `apache_cookie_window_leak.py` — heap-window forward over-read via set-cookie · apache · multi-request, fresh worker
- `carrier_base_locate.py` — recover carrier buffer base from self-pointers · all · needs self-referential carrier buffer
- `elf_resolver.py` — offset-free elf base scan and symbol resolve · all · needs zend_string read backend
- `fpm_binbase_leak.py` — write-free remote php-fpm binbase leak · fpm · needs unserialize-uaf transport
- `fpm_cookie_window_leak.py` — sink-free php-fpm set-cookie over-read -> chunk K + binbase · fpm · survivable arm + send_cookie, use_only_cookies
- `functable_resolver.py` — table-free rce-target resolve via function_table walk · cli fpm · needs binbase + eg_off
- `got_pltrelsz_read.py` — read dso .got.plt via dt_pltrelsz length · all · needs zend_string read backend
- `leak_parsers.py` — parse disclosure leaks into address families · all · needs per-build offsets table
- `proc_maps_bootstrap.py` — seed binbase and heap chunk from /proc maps · cli · lab-only, needs docker exec
- `ps_files_warning_disclosure.py` — sink-free post-decode disclosure via ps_files_open's open-failure warning · fpm · needs display_errors=on + html_errors=off, NUL-capped
- `rtc_transplant_resolver.py` — table-free fn/zif_system resolve by value transplant · cli fpm · needs one-time eg calibration
- `symbol_resolver.py` — offset-free symbol resolve via gnu_hash and got · all · needs zend_string read backend
- `uncaught_exception_overread_leak.py` — NUL-safe post-decode disclosure via the uncaught-exception (%S) display path; emits message zend_string BY LENGTH into the HTTP body · fpm · needs display_errors=on + html_errors=off; corruptible-arg seat still open
- `var_destroy_ptr_leak.py` — userland is_long heap-pointer leak via var_destroy uaf · cli · single var_push payload
- `var_hash_rw.py` — arbitrary read via unserialize uaf write · cli apache · rw memory only

## write

- `basedir_write_stage.py` — upload-progress stage POST triggering basedir write · all · needs freed decoder blocks
- `bss_last_dtor_forge.py` — fake-free last_dtor->.bss forge writing a chosen ptr at PG(auto_append_file) · fpm · needs binbase+carrier-base leak
- `fpm_clean_pg_write.py` — clean persistent auto_append dispatch via narrow write · fpm · gdb-calib
- `freelist_head_seat.py` — free-list head seat, one-write arbitrary dest · fpm · gdb-seated
- `freelist_slot_poison.py` — shadow-encoded free-list poison, arbitrary-address write · fpm · needs per-image groom calibration
- `fresh_dtor_placement.py` — fake ps_files basedir in fresh dtor block · fpm · needs full dtor block
- `high_dt_slot_placement.py` — high-slot dtor forge for basedir placement · all · needs dangling BG decoder
- `kfree_stagefed_forge.py` — K-free ps_files->basedir file-write, SETTLED/warm-endpoint, stage-fed DT backing · fpm · per-build offsets, NO K leak, works on already-compiled (realistic) endpoints
- `kfree_staletail_forge.py` — K-free (leak-free) ps_files->basedir file-write via stale-tail d->last redirect · fpm · needs only per-build offsets, NO chunk-base K leak
- `last_dtor_forge.py` — forge last_dtor bookkeeping to write chosen zval · all · needs known groom addresses
- `last_key_safe_reopen.py` — safe-reopen last_key forcer for basedir write · all · needs per-dangle aliasing calibration
- `lexbor_farreach_write.py` — lexbor-contains linear heap overflow, far reach · all · needs attacker-controlled selector
- `lexbor_write_what_where.py` — chosen qword overwrite of groomed forward victim · cli · needs filler-below groom
- `map_psfiles_neighbors.py` — non-perturbing black-box map of ps_files' 40-byte-bin heap neighbors (flock-park) · fpm · lab instrument, verifier-only /proc, groom-analysis
- `measure_psfiles_flock.py` — non-perturbing black-box ps_files chunk-offset measurement (flock-park) · fpm · lab instrument, verifier-only /proc
- `ps_files_basedir_forge.py` — forge ps_files basedir for arbitrary file write · all · needs dangling BG decoder
- `ps_files_single_carrier_forge.py` — single-carrier ps_files->basedir file-write forge (K-seated) · fpm · needs chunk-base K + dangling BG decoder

## groom

- `clean_request_reset.py` — reset zendmm real_size between groom rounds · apache fpm · worker survives oom bailout
- `groom_scaling.py` — calibrated groom sizing table by memory_limit · apache
- `huge_alloc_pressure.py` — drive ZendMM real_size to the limit off-chunk via huge $_POST fields · apache · pure HTTP
- `keepalive_fence.py` — fence prefork workers via options keep-alive · apache · prefork mpm
- `nested_field_pressure.py` — build deeply-nested multipart heap-pressure fields · fpm
- `nested_field_prime.py` — prime parse-peak so session decode ooms · fpm
- `post_oom_arreclaim_seat.py` — urlencoded $_POST OOM-abandoned-bucket arm: memshift OOM-table steer + bin-28 dup-key arData reclaim · cli apache fpm
- `prefork_pool.py` — fan-out scheduler reserving whole prefork pool · apache · prefork mpm
- `rshutdown_dangle.py` — dangle session_vars via pre-rinit rshutdown-skip · apache · chunk-base leak to weaponize
- `script_unserialize_oom_arm.py` — script-level unserialize-OOM BG(unserialize) dangle arm, fpm-survivable · fpm apache cli · approved unserialize sink
- `serialize_oom_arm.py` — seat BG(serialize) dangle over pure HTTP · apache · flush encode-OOM at the flush-ceiling
- `session_decode_dangle.py` — app-free session-decode-oom unserialize dangle arm · cli apache · needs raised memory_limit
- `session_start_oom_arm.py` — session_start()-decode-OOM BG(unserialize) dangle arm, fpm-survivable, no explicit unserialize() · fpm apache cli · ordinary session_start()+$_SESSION write
- `stage_session_seat.py` — seat a two-scalar session via a real app endpoint over http · apache · pure http
- `stale_bucket_value_seat.py` — binary-safe POST-value channel -> stale $_FILES bucket val.value (full 8 bytes, NUL-tolerant) · cli apache fpm
- `upload_progress_accumulate.py` — accumulate on-disk session records despite cleanup=on · fpm · upload_progress enabled, cleanup=on
- `upload_progress_cookie_seed.py` — cookie-targeted pure-HTTP upload_progress session seed · apache fpm · use_only_cookies=on
- `upload_progress_seed.py` — build pre-rinit upload-progress dangle seed body · apache cli · must be sent chunked
- `worker_pin.py` — pin prefork pool onto one child · apache · multi-worker prefork pool

## oracles

- `auto_include_fire_oracle.py` — sink-free auto-include fire confirmation · all · needs no-include landing page
- `blind_anchor_oracle.py` — black-box file-write oracle locating the K-free forge carrier anchor (d->last redirect offset); folds {d_choff,carrier_base,fakee} into one ps_files-relative residue · fpm · exact locator, but needs an externally supplied search window (cheap crash-bsearch narrowing is REFUTED)
- `blind_psfiles_oracle.py` — black-box ps_files locator; residue-page sweep over the EXACT GET-fire file-write signal pins ps_files_choff given a located X and the SAPI sub-page slot · fpm · no gdb/leak, needs X* + a residue window
- `blind_x_survive_oracle.py` — black-box X=(d_choff-carrier_base) PRE-FILTER via crash/survive with a benign in-carrier AIM; ps_files-independent, prunes X to a small survivor SET (has false-survives over a wide window), disambiguated by the file-write · fpm · needs an X window, no gdb/leak/ps_files
- `config_probe.py` — non-destructive fingerprint + config read for the vuln checker · all · passive
- `fatal_backtrace_oracle.py` — fatal-backtrace UAF crash-signature oracle · apache · pristine child required
- `fpm_behavior.py` — black-box fpm behavioral probes + honest crash-signal semantics · fpm · no-sink
- `fpm_content_oracle.py` — crash-bit content oracle at chosen address · fpm · needs write and chunk anchor
- `fpm_session_growth.py` — fpm session-growth OOM-flip -> sink-free patch differential (flip=vulnerable) · fpm · upload_progress on
- `munmap_sigsegv_oracle.py` — munmap huge-alloc deterministic-crash triage oracle · all · dangle must hit huge alloc
- `oom_classifier.py` — classify oom response for groom calibration · all · needs display_errors on
- `parser_crash_oracle.py` — exif IFD offset map-bit liveness oracle · fpm · needs unguarded native oob deref
- `sideeffect_exfil_apps.py` — auto-classify app sink, exfil pointer/binbase bits · fpm · needs app branching on decoded field
- `sideeffect_exfil_oracle.py` — non-echo side-effect exfil of injected pointer · fpm · needs attacker-influenced operand
- `timing_oracle.py` — blind sleep timing oracle · apache · single prefork worker
- `upload_progress_output.py` — upload-progress webshell output parser · all · response must echo session
- `version_verdict.py` — php version -> cve-2026-109618/109619 + lexbor patch verdict · all · passive
- `waf_detect.py` — WAF/CDN passive fingerprint + block-vs-crash response classifier · all
- `webroot_write_fire_oracle.py` — fire a webshell written to a web-served path by GETting it (nonce-verified cmd exec) · fpm/apache · needs the written .php reachable under docroot
- `wp_probe.py` — unauthenticated wordpress-core fingerprint + endpoint discovery · all · detection

## dispatch

- `auto_prepend_persist.py` — persist auto_prepend_file into per-request backdoor · apache fpm · narrow write + on-disk php file
- `auto_prepend_persist_narrow.py` — narrow-write fallbacks for auto_prepend dispatch · apache fpm · narrow write, pg(apf) already set
- `fire.py` — forge stdclass system() fire payload · all · resolved addresses + gpf offset
- `fire_zif.py` — forge stdclass zif_system fire with free-arg1 inline command · fpm · resolved addresses + gpf offset
- `inband_flush.py` — mark command output and recover it · fpm apache
- `longcmd_carrier.py` — external-field carrier lifting command-length cap · fpm apache · calibrated cmdoff per body
- `oob_output.py` — out-of-band command-output side channel · fpm apache · needs target outbound egress
- `spray_slot.py` — locate var_hash-uaf spray slot in chunk · all · needs read primitive + chunk base
- `survive_dispatch.py` — worker-surviving rce via jump_fcontext rop · apache · forged-dtor reclaim landed

## encode

- `waf_bypass.py` — WAF-evasion request transforms (client-IP/UA spoof, CT jitter, boundary-desync, chunked TE) for the detector · all
- `zend_array_forge.py` — forge fake zend_array carrier with system destructor · all
- `zend_string_forge.py` — pack zend_string header into byte buffer · all

## shm

- `opcache_handler_locate.py` — locate opcache op_array handler in shm · fpm · live worker /proc maps available
- `shm_maps.py` — parse shm-aware proc maps regions · fpm

## tooling

- `appfree_gadget_scan.py` — scan builtin classes for app-free uaf · cli · asan-built php cli image
- `gadget_fingerprint.py` — fingerprint target and select pop gadget · fpm apache · session serialize_handler mismatch configured
- `gadget_phpggc.py` — generate phpggc framework pop chain payload · fpm apache · session serialize_handler mismatch configured
- `waf_serialize.py` — hex-escape serialize strings to evade waf · all

## geometry

- `carrier_e_gap.py` — E-to-DT decode-allocation stride per model · all · model must match target build
- `pud_reclaim_class.py` — php_unserialize_data d-reclaim size-class + out-carrier length · all · derived, no addresses
- `selfdecode_push_law.py` — rfc1867 upload_progress self-decode var_push count + channel-reachability law · source-derived
- `singleshot_anchor.py` — derive singleshot E_OFF from decode anchor a_off + CARRIER_E · all · calibrated fit (gdb: version-sensitive)
- `stagefed_forge_geom.py` — collapse the K-free stagefed/staletail forge consts to one d_choff anchor · fpm · derivation EMPIRICAL-grounded 8.4/8.5, not black-box-fired

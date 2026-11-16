# Chains

Index of `poc/chains/*.py` — end-to-end chains that compose primitives and bugs
into a working exploit.

**Legend** — `sapi`: fpm · apache · cli · all. Each row then carries three
capability chips. **access** (what the live run touches beyond HTTP): `pure`
(HTTP only) · `gdb` (gdb-seeded anchors) · `/proc` (proc-maps seed). **sink**
(what the app must do): `none` · `session_start()` · `serialize+unserialize` ·
`other(...)`. **offset** (per-target offset knowledge, most→least portable):
`free` (by-name resolve) · `minor` (per PHP minor) · `minor+` (per-minor + small
build-sensitive residue) · `build` (per minor×config×patch table).

**Row** — `` `path` — what · sapi · access · sink · offset · gate ``, one per
chain, sorted by path; the free-text gate shows only when present.

sapi is suggestive, where it is tested. It does not mean it won't work on other sapis.

- `apache_cookie_disclose.py` — zero-knowledge cookie over-read chunk/module-base disclosure · apache · other(lab --service) · session_start() · build · fresh worker per shot
- `apache_cookie_rce.py` — cookie-leak one-shot system() rce · apache · pure · session_start() · build · fresh worker per shot
- `apache_rce_singleshot.py` — single-request session-uaf file-write rce · apache · other(docker-exec arm) · session_start() · minor+ · armed worker, 128M
- `apache_route.py` — var_hash-uaf rce, window-free binbase · apache · pure · serialize+unserialize · build · 8.1-8.4
- `enum_trigger.py` — enum-autoload second trigger for var_hash uaf · all · pure · other(reentrant-unserialize autoloader) · free
- `fire_8426_shim.py` — monkeypatch shim porting uaf->rce fire to 8.4.26 · fpm · pure · serialize+unserialize · free · given binbase
- `fpm_campaign.py` — resolve-once fire-many rce campaign driver · fpm · pure · serialize+unserialize · free · multi-worker pool
- `fpm_echo_route_driver.py` — end-to-end uaf->rce driver · fpm · pure · serialize+unserialize · free
- `fpm_fullchain_8426.py` — uaf rce, 8.4.26 build · fpm · pure · serialize+unserialize · build
- `fpm_fullchain_multiworker.py` — uaf rce across scattered worker pool · fpm · pure · serialize+unserialize · free · scatter or fcgi-pin
- `fpm_fullchain_rce.py` — uaf rce, 8.5.11 build · fpm · pure · serialize+unserialize · build
- `fpm_fullchain_sinkexfil.py` — uaf->rce via no-echo comparison-sink leak · fpm · pure · other(comparison sink) · build · fire needs --read-url
- `fpm_offsets_fire.py` — rce fire for no-echo comparison sink · fpm · pure · other(comparison sink) · build · consumes stage-1 leak
- `fpm_pool.py` — scatter-safe front-end, pins worker on fallback · fpm · pure · serialize+unserialize · free · scatter or fcgi-pin
- `fpm_rce_singleshot.py` — single-request session-uaf file-write rce · fpm · other(docker-exec arm) · session_start() · minor+ · armed worker, 8.3.26
- `fpm_route.py` — rce fire driver given binbase · fpm · pure · serialize+unserialize · free · given binbase
- `proc_seeded_rce.py` — arbitrary-zval-write leak->rce chain · fpm cli · /proc · other(lab session oracle) · build
- `remote_rce_route.py` — var_hash-uaf rce SAPI router (apache · fpm) · both · pure · serialize+unserialize · build
- `sinkexfil_stage1.py` — stage-1 chunk+binbase leak via sort sink · fpm · pure · other(comparison sink) · build
- `stale_bucket_value_rce.py` — stale $_FILES bucket value-channel -> forged zend_array -> system(cmd) · cli; addresses from gdb/proc seed
- `universal_remote_rce.py` — var_hash-uaf system() rce engine · all · pure · serialize+unserialize · free
- `upc_rce_singleshot.py` — session-uaf file-write rce · fpm · pure · session_start() · minor+ · upload_progress cleanup=on, writable docroot

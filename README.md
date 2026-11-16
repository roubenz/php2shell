# php2shell

Exploit lab and PoC toolkit for CVE-2026-109618 (GHSA-w8hw-w9fx-j79w, "RCE via
OOM corruption") and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp, "RCE via stale
global state"), two PHP 8.1-8.5 memory-safety bugs.

**Lab / analysis use only, on systems you own or are explicitly authorized to
test.** The exploit modules default to decide-only / dry-run; firing is opt-in.

## The two vulnerabilities

**CVE-2026-109618**: an out-of-memory `zend_bailout()` (`longjmp`) could fire
while request memory was only partially initialized, e.g. mid-multipart-parse
in `php_hash_environment()`, before module RINIT. mod_php and `php -S` call
`php_request_shutdown()` unconditionally after that failed startup and walk
the half-built state: use-after-free / type confusion before any application
code runs. Fixed by replacing the bailout with a delayed soft OOM plus a hard
`_exit()`, and `ZEND_HAS_OOM()` checks through the parsing paths.

**CVE-2026-109619**: worker-global state pointing at request-owned memory
(session upload-progress, `PG(last_error_message)`, session/serializer
globals) isn't reset when a request dies before its matching reset. The heap
is freed but the worker keeps the stale pointers, and the next request on
that worker consumes them before init replaces them: heap use-after-free. A
variant surviving a fatal inside `unserialize()` after a successful startup
reaches php-fpm too. Fixed by resetting the state early
(`php_basic_early_rinit()`, session reset at `MULTIPART_EVENT_START`,
`clear_last_error()` in shutdown).

## The code

`poc/` holds the exploit code; the catalogue is three generated indexes, one
line per module:

- [doc/PRIMITIVES.md](doc/PRIMITIVES.md): single-capability building blocks.
- [doc/CHAINS.md](doc/CHAINS.md): end-to-end chains, each tagged with its
  **access** (`pure` HTTP / `gdb` / `/proc`), **sink** (what the app must do),
  and **offset** portability.
- [doc/BUGS.md](doc/BUGS.md): the minimal single-bug reproducers.

Regenerate the indexes after editing a module's `# INDEX:` line with
`python3 -I poc/utils/gen_docs.py`. Everything is Python 3 stdlib only; run in
isolated mode: `python3 -I poc/<path>.py …`.

## The lab

Each lab is a Docker Compose service; avenues are selected by **profile**, one at
a time. Bring the core labs up with:

```bash
docker compose up -d --build
```

| Service | Port | PHP | Server | Purpose |
|---|---|---|---|---|
| cli-vuln | 8081 | 8.4.26 | `php -S`, 16M | vulnerable CLI baseline |
| cli-vuln83 | 8087 | 8.3.35 | `php -S` | vulnerable 8.3 build |
| cli-fixed | 8082 | 8.4.27 | `php -S` | patched counterpart |
| web-vuln | 8083 | 8.4.26 | nginx → php-fpm (`pm.max_children=1`) | vulnerable fpm stack |
| web-fixed | 8084 | 8.4.27 | nginx → php-fpm | patched fpm stack |
| cli-asan | 8085 | 8.4.26 | `php -S`, ASan | AddressSanitizer differential |
| cli-asan-fixed | 8086 | 8.4.27 | `php -S`, ASan | ASan, patched |
| cli-asan-128 | 8405 | 8.4.26 | `php -S`, ASan, 128M | session-decode-dangle lab |
| cli-stock | 8091 | 8.4.26 | `php -S`, stock INI | default-config target |
| apache-stock | 8089 | 8.4.26 | Apache mod_php ×1, `php.ini-production` | default-config Apache |
| apache-pool | 8093 | 8.4.26 | Apache mod_php prefork ×10 | worker-pin lab |

`fpm-vuln` / `fpm-fixed` publish no host port. Reach them via `web-vuln` /
`web-fixed`. The fpm pool is pinned to one child so a chain's requests hit the
same worker; the master respawns a crashed child instantly, so fpm differentials
read the response text and `docker compose logs fpm-*` (`child N exited on
signal 11`) rather than a liveness probe.

Beyond the core file, each themed compose file carries its own labs, selected by
profile (each compose file's header comments list its invocations):

| File | Theme |
|---|---|
| `docker-compose.versions.yml` | version / SAPI variant stacks (8.3.26, 8.5.11, …) |
| `docker-compose.fpm-avenues.yml` | per-avenue php-fpm labs |
| `docker-compose.apache-avenues.yml` | per-avenue Apache mod_php labs |
| `docker-compose.apps.yml` | real apps (phpMyAdmin, WordPress) |
| `docker-compose.reuse.yml` | labs reusing prebuilt images |

The Apache labs in `apache-stock` / `apache-pool` / the reuse file / the
memory-scale overlays share one base image that only the `versions.yml` `c2`
profile builds. Build it first:
`docker compose -f docker-compose.versions.yml --profile c2 build`.

Verifiers are self-documenting: every `poc/**/verify_*.py` docstring carries its
compose profile and canonical invocation. A verifier that reaches its lab prints
PASS/FAIL; an unreachable lab is SKIPPED.

## Running the PoCs

The operator capstone is `poc/php2shell_driver.py`: given a target URL (and any
app endpoints that expose an unserialize sink) it fingerprints the build,
classifies the sink by behaviour, selects the lab-proven route, and runs the
chain only on an explicit `--fire`, reporting delivery. It is **assembly only**
and never prints a claim stronger than the module that proved it
([poc/DRIVER.md](poc/DRIVER.md)).

```bash
# decide only (default is dry-run):
python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/remote_app.php

# fire (fpm, comparison-leak sink + a declared survivable dispatch):
python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/ \
    --sort-path /order.php --dispatch-survivable /jsonapi.php \
    --fire --cmd 'id>/dev/shm/x'
```

`poc/php2shell.py` is the simpler front-end (`check`, `remote-rce`,
`apache-cookie-rce`, `var-hash-rw`, `proc-seeded-rce`). The single-bug
reproducers run standalone against the lab:

```bash
python3 -I poc/php2shell.py check            http://localhost:8081
python3 -I poc/bugs/parse_oom_halfbuilt.py   http://localhost:8081        # CVE-2026-109618
python3 -I poc/bugs/files_key_stale_bucket.py http://localhost:8085 http://localhost:8086  # 109618 ASan differential
python3 -I poc/bugs/upload_progress_uaf.py   http://localhost:8081        # CVE-2026-109619 (session upload-progress)
python3 -I poc/bugs/unserialize_dangle_uaf.py http://localhost:8085       # CVE-2026-109619 (unserializer bookkeeping)
```

## What's demonstrated

Each row names the SAPI, the uid when a command ran, and the
method. "RCE" here means a command executed with its output or an out-of-band
marker observed; the RCE routes are **gated on an application that unserializes
attacker-influenced input** (an echo/serialize-reflecting endpoint or a
comparison/sort sink). A fully sink-free, zero-knowledge, pure-HTTP black-box
chain is not landed.

| Result | Target | Method |
|---|---|---|
| CVE-2026-109618: request-shutdown walk of half-built `$_FILES` state kills the worker; patched build answers clean | cli-asan / cli-asan-fixed | deterministic ASan differential |
| CVE-2026-109619: session upload-progress UAF, vulnerable worker hangs on the next request, patched answers | cli-vuln / cli-fixed | black-box differential (no ASan) |
| CVE-2026-109619: unserializer stale-bookkeeping UAF in the next request's session decode | cli-asan, web-vuln (fpm) | ASan differential; reaches fpm (fatal after startup) |
| Arbitrary zval write + OOB info leak + command exec (`uid=0`) by steering the freed unserializer bookkeeping | cli-vuln (lab worker) | black-box; per-boot addresses from a gdb replica or `/proc` |
| Full leak-driven chain: `uid=0` (cli) / `uid=33` (fpm), version-universal via a per-build offsets table | cli-vuln, cli-vuln83, web-vuln | **`/proc`-seeded** (two region facts), not pure-HTTP |
| fpm RCE over a comparison/sort sink, worker-surviving, output in-band (`uid=33`, 5/5) | php-fpm | per-build offset table; needs a declared survivable dispatch |
| fpm RCE over an echo (serialize-reflecting) sink (`uid=33`) | php-fpm | one-shot, fire SIGSEGVs, confirm out of band; no `/proc` |
| Apache mod_php RCE, offset-table-free by-name resolve (`uid=33`, 8.5.x) | Apache mod_php | one-shot, unpinned scatter across prefork children |

The CVE reproducers (the first three rows) are the cleanest, build-differential
results. The RCE rows are the lab-proven routes behind the driver's decision
table ([poc/DRIVER.md](poc/DRIVER.md)); each traces to the module and commit that
proved it.

## Leak-channel note

[`uncaught_exception_overread_leak.py`](poc/primitives/read_leak/uncaught_exception_overread_leak.py)
leaks heap bytes through PHP's `%S` uncaught-exception display, NUL-safe and
response-reflected, byte-exact verified. cookiengineer's `actual-php2shell`
named this mechanism first (`docs/info-leak.md` §3) but never built it; this
is the first working version, and it contradicts Bhavye-Malhotra's "0
confirmed bits" HTTP-leak conclusion from the same corpus. Everyone else's
NUL-safe leak rides a different carrier, mostly the Set-Cookie `PHPSESSID`
over-read.
 
## Disclaimer

Published for defensive security research and education, and released under the
MIT License ([LICENSE](LICENSE)).

**Attribution.** This project combines work from several sources. Many of the
techniques come from other researchers and are credited inline in the module
that uses them. Some primitives were arrived at independently here and only
later found to have already been published by others on GitHub. The remainder is
original AI-assisted research.

Use this **only** on systems you own or are explicitly authorized to test.
Unauthorized access to computer systems is illegal in most jurisdictions. The
exploit modules default to decide-only / dry-run and firing is opt-in, but you
alone are responsible for how you use them.

Provided "as is", without warranty of any kind; the author accepts no liability
for misuse or damage.

## References

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.php.net/archive/2026.php#2026-10-21-5
- https://github.com/NCSC-NL/php2shell
- Fix commit: https://github.com/php/php-src/commit/3584a98bda0f

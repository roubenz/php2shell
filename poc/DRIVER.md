# php2shell_driver — the operator-facing capstone

`poc/php2shell_driver.py` turns the project's settled map into one operator-usable
tool: given a target URL (and, where known, the app endpoints that expose an
unserialize sink), it **fingerprints**, **classifies the sink(s) by behaviour**,
**selects the lab-proven route**, and — only on an explicit `--fire` — **runs the
full chain** and **reports delivery with in-band or out-of-band evidence**.

It is **assembly only**. It defines no new primitive and makes no new claim; it
imports the already-proven route modules **read-only** and never re-implements or
edits them. Every claim it prints traces to a module that proved it (table
below), and it never prints a claim stronger than that module's own verdict.

```
# decide only (safe — default is DRY-RUN):
python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/remote_app.php

# survivable in-band RCE (fpm): comparison leak sink + declared dispatch:
python3 -I poc/php2shell_driver.py --url http://127.0.0.1:8170/ \
    --sort-path /order.php --dispatch-survivable /jsonapi.php \
    --fire --cmd 'id>/dev/shm/x'
```

## Safety / house rules

- **Default mode is dry-run.** The driver decides and prints the plan + evidence
  *without firing*. Running a chain crashes workers and executes `--cmd` on the
  target, so it needs an explicit `--fire`. (This is a deliberate deviation from
  the brief's "dry-run is a mode" wording, in favour of the house rule that
  hard-to-reverse / outward-facing actions are opt-in.)
- **Ambiguity stops, never defaults.** If SAPI can't be determined, the PHP
  version banner is absent, a dispatch sink's tier isn't declared, or the version
  is outside the proven window, the driver *says so and exits non-zero* (code 2)
  rather than guessing. Overrides: `--sapi`, `--php-version`, `--allow-81-83`,
  `--dispatch-survivable/--dispatch-oneshot`.
- **Config routes are report-only here.** With no unserialize sink the driver
  names the config-route modules (fcgi autoprepend / include-race / filter-chain
  / pathinfo); it does not fire them. Run those with their own modules.
- Lab/analysis use only, on systems you own.

## Honesty of the success oracle

Priority **in-band marker/uid → OOB marker → crash-liveness** — never conflated:

- A worker-killing hit on a **survivable-tier** sink is reported as a **FAILED**
  fire (house definition). The worker-alive canary is read as success *only* when
  the fire was delivered.
- **One-shot** fires SIGSEGV after `system()` returns, so the HTTP response is not
  a signal: the driver reports `verified=None` and tells you to confirm the
  command's effect **out of band**. It does not claim `verified=True` for a
  one-shot route.
- The `<=14 B` fire budget cannot carry the OOB `curl` wrapper in-line; the
  driver warns when `--oob-host` is combined with a capped fire, and the realistic
  one-shot evidence is a short marker command (`cmd>file`, already exit-0).

## The decision table → the module/commit that proved each row

| Fingerprint + sinks | Route (module) | Fire mode | Proven by |
|---|---|---|---|
| fpm + comparison leak sink **+** declared SURVIVABLE dispatch | `fpm_offsets_fire.run` | **survivable, in-band** | commit `2d9760f` — leak+resolve over the sort sink, fire via a `get_properties_for` dispatch path; uid=33 5/5, worker-surviving. Spray slot = the build-table const (`--no-probe`), selected by the Stage-1 `&zval_ptr_dtor mod 2 MiB` fingerprint. |
| fpm + echo (serialize-reflecting) sink | `fpm_echo_route_driver.echo_route` | **one-shot**, OOB | commit `f9d6d77` — remote binbase leak + UAF fire over one echo sink; uid=33 5/5, no `/proc`. Fire SIGSEGVs → verify OOB. |
| fpm + echo sink **+** multi-command (`--campaign N`/`--cmd-list`) | `fpm_campaign.run_campaign` | **one-shot per cmd** (resolve cached) | commit `76ef83f` — resolve-once (~352 req) reused across the respawn (binbase/chunk invariant, fork-shared ASLR); each leak-primed shot SIGSEGVs → verify each OOB. |
| Apache mod_php + echo sink | `universal_remote_rce.run_chain` (×scatter) | **one-shot**, OOB | commit `aa7e34e` — by-name offset-table-free RCE; uid=33 on 8.5.x, unpinned scatter across children. Driver delivers `--fire-retries` passes (prefork scatter); marker is the oracle. |
| fpm/Apache + comparison sink only (no echo, no dispatch) | `sideeffect_exfil_apps.run` | **none** (exfil-only) | commit `87e6035` — recovers chunk+binbase over a comparison/branch sink with NO echo (WALL-1); no fire transport without a dispatch or echo endpoint. |
| Apache pool instability (`--fence N`) | wrap in `primitives/groom/keepalive_fence.PreforkFence` | — | commit `a241f83` — OPTIONS keep-alive fence parks N−1 children onto one, 16%→100% per-cmd pinning. |
| no unserialize sink | **report only** (fcgi autoprepend / include-race / filter-chain / pathinfo) | corruption-free | reported, not fired; run the named modules with their own flags. |

Out-of-band evidence channel: `primitives/dispatch/oob_output.OOBListener` + `wrap_command` (commit
`4000aeb`). Framework/gadget signal: `primitives/tooling/gadget_fingerprint.fingerprint`
(best-effort, never fatal).

## Version gates (enforced before any route)

- The UAF (CVE-2026-109618) is present on every line **8.1–8.5**.
  Variant `8.5` for ≥ 8.5, else the `8.4` shim.
- **8.1–8.3** is gated behind `--allow-81-83` (offset-free auto-land depends on the
  crash-tolerant R-6 probe; the 8.2/8.3 table-route is pending the in-flight
  offsets-table run).
- Below 8.1 → no proven route → stop.
- Unknown version → stop and ask (`--php-version X.Y.Z`).

## How sinks are classified (and what is NOT black-box determinable)

- **Behavioural, reliable:** echo-serialize (benign serialized probe reflected),
  sort / ordered / equality (`sideeffect_exfil_apps.autodetect`, #6).
- **Operator-declared only:** a dispatch sink's **tier** — SURVIVABLE
  (`get_object_vars`/`(array)`/`foreach`/`var_export`/json-with-options,
  null-checking `get_properties_for`) vs ONE-SHOT (`serialize`/json-direct,
  null-wall) — is **not** determinable from a black-box response. The driver trusts
  only `--dispatch-survivable` / `--dispatch-oneshot`; it neither guesses a tier
  nor stops on the mere presence of a responsive page. Without a declared dispatch
  the fpm route falls back to the echo sink (one-shot) or exfil-only, both
  behaviourally grounded. `json_encode`-direct does **not** fire; the survivable shape is
  decode → `get_object_vars` → `json_encode` the array.

## Verifier

`poc/verify_php2shell_driver.py` drives the driver exactly as an operator would
(`python3 -I`) and scores the five DoD cases against the committed labs, reading
markers/PIDs out of band via `docker exec` on the labs it owns:

| Case | What | Lab |
|---|---|---|
| 1 | dry-run selects the correct route per shape | erd `:8170` (survivable + echo), apache `:18185` |
| 2 | survivable-tier uid + **pool stays alive** (the module's HTTP-200 survival metric; worker PID changes from the *leak*, not the fire — informational) | erd `:8170` |
| 3 | one-shot tier fires, confirmed by an **OOB marker**, driver did not overclaim | erd `:8170` |
| 4 | no-sink target **declines** to config routes (no fire) | nosink `:8080` |
| 5 | `--campaign 3` resolve-once, three markers land | erd `:8170` |

```
python3 -I poc/verify_php2shell_driver.py               # all five (fires)
python3 -I poc/verify_php2shell_driver.py --dry-run-only # fast: cases 1 & 4
```

Unreachable labs are **SKIPPED**, not failed. Green = no FAIL and at least one
PASS.

# Bugs

Index of `poc/bugs/*.py` — the underlying vulnerabilities (UAF, OOM dangle,
overflow, over-read) the chains build on.

**Legend** — `sapi`: fpm · apache · cli · all (a version only when the bug is
narrow, e.g. `8.4-8.5`). `gate`: the one trigger condition (e.g. `needs /proc`,
`1-request`, `needs raised memory_limit`); omitted when there is none.

**Row** — `` `path` — what · sapi · gate ``, one per bug, sorted by path.

sapi is suggestive, where it is tested. It does not mean it won't work on other sapis.

- `controlled_fault_groom.py` — unserialize stale-bookkeeping dangle groomed to attacker-controlled fault · cli · fixed 2-request groom sequence
- `files_key_stale_bucket.py` — use of counted-but-uninitialized $_files hashtable bucket · cli · oom at nested-key alloc
- `lexbor_contains_overflow.py` — lexbor :lexbor-contains() selector heap buffer overflow · all · needs queryselector sink
- `lexbor_idna_leak.py` — lexbor idna toascii buffer-grow heap over-read · all · needs url::parse() sink
- `parse_oom_halfbuilt.py` — shutdown-walk of half-built $_files state · cli · startup oom mid-parse
- `session_decode_dangle_uaf.py` — app-free session-decode-oom unserialize dangle uaf · cli apache · needs raised memory_limit
- `stale_bucket_groom_crash.py` — groomed $_files stale-bucket val -> controlled-address shutdown crash · cli apache · stock non-asan, single request
- `unserialize_dangle_uaf.py` — app unserialize() oom leaves stale BG(unserialize) uaf · cli · consumer must be next request
- `upload_progress_uaf.py` — upload-progress startup-oom stale ps(id) reuse uaf · cli apache · needs survive-startup sapi
- `var_destroy_24481_remote.py` — remote heap-pointer leak via var_destroy reentry uaf · all · needs reentrant __destruct + reflected array

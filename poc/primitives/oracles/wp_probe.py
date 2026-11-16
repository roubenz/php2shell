#!/usr/bin/env python3
# INDEX: unauthenticated wordpress-core fingerprint + endpoint discovery | all | detection
"""WordPress-core detection surface for the php2shell checker (unauthenticated).

What WordPress core adds for DETECTION (established by source review, not
assumption): it confirms the target is WordPress, recovers the WordPress version,
and gives guaranteed PHP-executing POST endpoints (wp-login.php, admin-ajax.php,
xmlrpc.php) so the behavioral probes work even when the site root is static /
page-cached. What it does NOT add: WordPress core does not leak the PHP version
anywhere unauthenticated (only expose_php's X-Powered-By does), and core has no
unauthenticated HTTP->unserialize() sink, so it does not by itself turn the
sink-free php-fpm CVE-2026-109619 bug into an observable crash. The one core
path that engages the bug's machinery unauthenticated is the wp-login.php
password-reset Set-Cookie over-read (action=rp sets wp-resetpass-<COOKIEHASH>
to sprintf('%s:%s', login, key) from raw $_GET) -- used by the repo's
routes/wordpress/resetpass_* modules.

detect_wordpress() returns {is_wp, wp_version, signals, endpoints}. Pure GETs,
non-destructive. stdlib only; python3 -I safe.
"""
from __future__ import annotations

import re

# Reliable unauthenticated WP-core entry files (exist in core root).
POST_ENDPOINTS = ("wp-login.php", "wp-admin/admin-ajax.php", "xmlrpc.php")

_GEN_META = re.compile(rb'name=["\']generator["\']\s+content=["\']WordPress\s*([0-9.]+)', re.I)
_GEN_FEED = re.compile(rb'wordpress\.org/\?v=([0-9.]+)', re.I)
_GEN_ATOM = re.compile(rb'generator[^>]*version=["\']([0-9.]+)["\']', re.I)
_VER_QS = re.compile(rb'[?&]ver=([0-9][0-9.]+)')
_WP_PATHS = re.compile(rb'/wp-(content|includes)/', re.I)


def _wp_version(body):
    for pat in (_GEN_META, _GEN_FEED, _GEN_ATOM):
        m = pat.search(body or b"")
        if m:
            return m.group(1).decode()
    return None


def detect_wordpress(http_full_fn, base):
    """`http_full_fn(url, timeout=...)` -> (status, headers, body). Probes a few
    unauthenticated pages and returns a WordPress fingerprint dict."""
    base = base.rstrip("/")
    signals = []
    wp_version = None
    is_wp = False

    st, _, body = http_full_fn(base + "/", timeout=8)
    if body and _WP_PATHS.search(body):
        is_wp = True
        signals.append("wp-content/wp-includes asset paths on /")
    v = _wp_version(body)
    if v:
        is_wp, wp_version = True, v
        signals.append(f"generator meta -> WordPress {v}")

    # feed generator survives wp_head generator removal
    if wp_version is None:
        st, _, fbody = http_full_fn(base + "/?feed=rss2", timeout=8)
        v = _wp_version(fbody)
        if v:
            is_wp, wp_version = True, v
            signals.append(f"feed generator -> WordPress {v}")
        if fbody and _WP_PATHS.search(fbody):
            is_wp = True

    # REST index confirms WP without a version
    if not is_wp:
        st, _, jbody = http_full_fn(base + "/wp-json/", timeout=8)
        if jbody and (b'"namespaces"' in jbody and b'wp/v2' in jbody):
            is_wp = True
            signals.append("/wp-json/ REST index (namespaces wp/v2)")

    # core asset ?ver= as a last-resort version tell
    if is_wp and wp_version is None:
        st, _, body2 = http_full_fn(base + "/", timeout=8)
        m = _VER_QS.search(body2 or b"")
        if m:
            wp_version = m.group(1).decode()
            signals.append(f"core asset ?ver={wp_version}")

    endpoints = {}
    if is_wp:
        for ep in POST_ENDPOINTS:
            st, _, _ = http_full_fn(base + "/" + ep, timeout=6)
            if st in (200, 302, 400, 405):     # exists / rejects method, not 404
                endpoints[ep] = st
    return {"is_wp": is_wp, "wp_version": wp_version,
            "signals": signals, "endpoints": endpoints}


if __name__ == "__main__":
    # offline parse self-test
    samples = {
        "generator_meta": b'<meta name="generator" content="WordPress 6.5.2" />',
        "feed": b'<generator>https://wordpress.org/?v=7.1.3</generator>',
        "atom": b'<generator uri="https://wordpress.org/" version="6.4.1">WordPress</generator>',
        "assets": b'<link href="/wp-content/themes/x/style.css?ver=6.3" />',
    }
    ok = True
    for k, b in samples.items():
        v = _wp_version(b) or (_VER_QS.search(b) and _VER_QS.search(b).group(1).decode())
        print(f"  {k}: version={v}  wp_paths={bool(_WP_PATHS.search(b))}")
        ok &= v is not None
    print("ALL OK" if ok else "SELF-TEST FAILED")
    raise SystemExit(0 if ok else 1)

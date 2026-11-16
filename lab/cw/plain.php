<?php
/* grail lab landing/oracle page.
 *
 * This is the "normal HTTP" surface the whole grail chain confirms against. It
 * does exactly two app-innocent things:
 *   1. session_start()  -- so the app hands out a PHPSESSID and the session save
 *      handler is active (the race poison writes save_path/sess_<sid>).
 *   2. echoes a banner.
 *
 * Crucially there is NO includable GET parameter here (no include($_GET[...])).
 * If a plain GET to this page ever emits the poison marker, it can ONLY be
 * because PG(auto_prepend_file) was redirected at the poisoned session file and
 * the engine auto-included it BEFORE this script ran. That makes any marker in
 * the response a BUILT-IN, app-agnostic success oracle for the PG write.
 */
session_start();
echo "grail-plain " . PHP_VERSION . " " . php_sapi_name() . " sid=" . session_id() . "\n";

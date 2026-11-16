<?php
/* hl lab landing/oracle page (identical in spirit to lab/grail/plain.php).
 *
 * The "normal HTTP" surface the 2-ptr integration confirms against. It does two
 * app-innocent things:
 *   1. session_start()  -- so the app hands out a PHPSESSID and the session save
 *      handler is active (the race poison writes save_path/sess_<sid>).
 *   2. echoes a banner.
 *
 * There is NO includable GET parameter here. If a plain GET to this page ever
 * emits the poison marker, it can ONLY be because PG(auto_prepend_file) was
 * redirected at the poisoned session file and the engine auto-included it BEFORE
 * this script ran -> a built-in, app-agnostic success oracle for the PG write.
 */
session_start();
echo "hl-plain " . PHP_VERSION . " " . php_sapi_name() . " sid=" . session_id() . "\n";

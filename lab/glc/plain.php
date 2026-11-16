<?php
/* glc lab landing/oracle page (a copy of the grail oracle).
 *
 * This is the "normal HTTP" surface the composed chain confirms against. It does
 * exactly two app-innocent things:
 *   1. session_start()  -- so the app hands out a PHPSESSID and the session save
 *      handler is active (the race poison writes save_path/sess_<sid>).
 *   2. echoes a banner.
 *
 * There is NO includable GET parameter here. If a plain GET to this page ever
 * emits the poison marker, it can ONLY be because PG(auto_append_file) was
 * redirected at the poisoned session file and the engine auto-included it ->
 * a BUILT-IN, app-agnostic success oracle for the clean write. NO gdb is in
 * this firing path.
 */
session_start();
echo "glc-plain " . PHP_VERSION . " " . php_sapi_name() . " sid=" . session_id() . "\n";

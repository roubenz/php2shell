<?php
/* transplant lab landing/oracle page (same role as the grail/cw plain.php).
 *
 * Two app-innocent things only: session_start() (so the save handler is active
 * and the PG dispatch has somewhere to fire) and a banner. There is NO
 * includable GET parameter. If a plain GET ever emits the poison marker, it can
 * ONLY be because PG(auto_prepend_file) was redirected -- the built-in,
 * app-agnostic success oracle (the "grail BLIND success-oracle").
 */
session_start();
echo "tp-plain " . PHP_VERSION . " " . php_sapi_name() . " sid=" . session_id() . "\n";

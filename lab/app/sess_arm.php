<?php
/* Ordinary session app, NO explicit unserialize(): session_start() decodes this
 * SID's record through php_session_decode -> php_var_unserialize over the shared
 * BG(unserialize). An attacker-shaped oversized record OOMs mid-decode; the
 * bailout (re-raised by php_session_decode's zend_catch) is caught by the SAPI's
 * script zend_first_try, so the worker SURVIVES with BG(unserialize) dangling.
 * The $_SESSION write is the mundane delivery line. SID via GET (use_cookies=0). */
if (isset($_REQUEST['sid'])) { session_id($_REQUEST['sid']); }
session_start();
if (isset($_POST['x'])) { $_SESSION['x'] = $_POST['x']; }
echo "SESSARM:" . getmypid();

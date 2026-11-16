<?php
// Ordinary session app: NO explicit unserialize() anywhere. session_start()
// reads this SID's session file and decodes it through PS(serializer)->decode
// (php_session_decode -> php_var_unserialize over the same BG(unserialize) the
// userland unserialize() uses). An attacker-shaped oversized record OOMs mid-
// decode; the bailout is re-raised by php_session_decode's zend_catch and caught
// by php_execute_script's zend_first_try -> the fpm worker SURVIVES with
// BG(unserialize) left dangling, same signature as the explicit-unserialize arm.
// The $_SESSION write is the mundane delivery line (drafts/carts/preferences).
session_start();
if (isset($_POST['x'])) { $_SESSION['x'] = $_POST['x']; }
echo "SESSARM-NOOOM:" . getmypid();

<?php
// The project's one approved sink: a single script-level unserialize(). The OOM
// payload (poc/primitives/groom/script_unserialize_oom_arm.py) exhausts
// memory_limit mid-decode; the bailout is caught by php_execute_script's
// zend_first_try so the fpm worker SURVIVES with BG(unserialize) left dangling.
@unserialize($_POST['d'] ?? '');
echo "ARMED-NOOOM:" . getmypid();

<?php
// Bare POST endpoint (no session_start). The pre-RINIT $_POST autoglobal build
// runs the rfc1867 upload_progress session decode -> reuses any dangling
// BG(unserialize) BEFORE PHP_RINIT(basic) memsets it. Used as the consumer.
echo "ECHO:" . getmypid();

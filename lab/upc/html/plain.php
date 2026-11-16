<?php
// Bare echo endpoint -- NO session_start(). The PHP_SESSION_UPLOAD_PROGRESS multipart
// decode runs pre-RINIT inside sapi_activate(), so the dangling-decoder forge and the
// file-write finish happen here without a script-level session call interfering. The
// stage request targets this page.
echo "OK\n";

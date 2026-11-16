<?php
// Bare echo endpoint (NO session_start). The upload_progress multipart decode runs
// pre-RINIT off the $_POST auto-global, so the arm/stage need no application code.
echo "OK\n";

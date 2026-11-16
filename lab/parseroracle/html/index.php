<?php
// Liveness probe target. A healthy worker answers 200 "OK"; a worker killed by
// a crash in upload.php makes nginx answer 502/reset on the next FastCGI call.
echo "OK";

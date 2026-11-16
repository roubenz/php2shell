<?php header('Content-Type: text/plain');
// Worker liveness/identity (no session). Used to wait for FPM to respawn the single
// static worker after a shaping request OOMed it.
echo "pid=", getmypid(), " ml=", ini_get('memory_limit'), "\n";

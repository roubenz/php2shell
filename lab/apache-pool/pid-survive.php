<?php
// Worker-identity + liveness probe for poc/verify_survive_dispatch.py.
// Echoes the serving prefork child's PID. On the single-worker survive lab a
// stable PID across the fire request proves the child BAILED OUT cleanly
// (worker survived); a changed PID means the child crashed and the master
// forked a replacement (the old one-shot zif_system behaviour).
echo "PID=", getmypid(), "\n";

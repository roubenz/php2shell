<?php
// Reveals the serving child PID (root dir = no junk INI). Used by the oracle
// only AFTER a suspected crash, to confirm a respawn (new PID), never before an
// attack (a pre-attack request would warm the pristine child).
echo getmypid() . "\n";

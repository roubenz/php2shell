<?php
// Control page: same role as junkdir/probe.php but its dir has NO junk
// .htaccess, so no E_WARNING fires at the per-dir INI stage and the stale zval
// (if armed) is instead UNDEF'd by init_executor -> no UAF, clean 200.
echo "cleandir-probe-ok pid=" . getmypid() . "\n";

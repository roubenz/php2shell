<?php
// Page in the dir whose .htaccess carries the junk php_value memory_limit.
// By the time PHP starts executing this script, the per-dir INI stage has
// already run (and, if a prior fatal.php armed the stale zval on this child,
// already crashed the worker). A plain 200 here means NO crash occurred.
echo "junkdir-probe-ok pid=" . getmypid() . "\n";

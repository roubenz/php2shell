<?php
// Victim page (kengwang FPM-chain shape): a script-level session_start(). For the
// accumulation route this is the ARM endpoint -- the script-level decode of a grown
// session file reaches memory_limit, zend_first_try absorbs the fatal, the worker
// survives, and BG(unserialize) is left dangling in it.
session_start();
echo "OK ", count($_SESSION), "\n";

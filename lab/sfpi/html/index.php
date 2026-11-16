<?php
// Benign landing page for the nginx+fpm SCRIPT_FILENAME/path-info lab.
// It session_start()s (so a sess_<sid> file appears under session.save_path,
// which the race variant poisons) and prints a banner. There is NO app bug
// here: the RCE comes entirely from the nginx pathinfo misconfig, not from
// anything this page does.
session_start();
echo "sfpi lab " . PHP_VERSION . " " . php_sapi_name() . "\n";

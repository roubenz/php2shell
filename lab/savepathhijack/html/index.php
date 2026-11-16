<?php
// savepath-hijack lab app: the session_start() page the chain primes against.
// No app bug at all -- no includable param, no gadget. RCE comes entirely from
// the pre-RINIT stale BG(unserialize) decoder rewriting the session writer's
// on-disk target into this (writable) docroot.
session_start();
echo "welcome " . PHP_VERSION . " " . php_sapi_name() . "\n";

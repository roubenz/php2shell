<?php
// AVENUE #3 lab app -- deliberately trivial and BENIGN. The whole point of
// file-cache poisoning is that this source text never changes and contains no
// bug: code execution comes from the compiled .bin in the OPcache file-cache
// dir, which (with file_cache_only=1 + validate_timestamps=0) is loaded and run
// in place of compiling this file. Poison the .bin => this page runs the
// attacker's opcodes instead of the line below.
//
// Lab/analysis use only, on systems you own.
echo "benign index " . PHP_VERSION . " " . php_sapi_name() . "\n";

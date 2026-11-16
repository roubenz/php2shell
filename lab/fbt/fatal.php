<?php
// Arms EG(last_fatal_error_backtrace): a deeply nested call chain carrying
// large string / array args, then an E_USER_ERROR at the bottom. On 8.5 with
// fatal_error_backtraces=On the fatal handler captures the whole backtrace
// (all these frames + their args) into EG(last_fatal_error_backtrace) on the
// request heap. shutdown_executor() skips the clear on a fast_shutdown request,
// so the zval survives into the next request on this child.
//
// The bigger / deeper the backtrace, the more request-heap zvals it references,
// so the stale dtor on the next request touches more freed memory -> more
// reliable SIGSEGV.

function frame_d($a, $b, $c) {
    // Deepest frame: raise the user-fatal with a large message arg.
    trigger_error(str_repeat('FBT_FATAL_', 2048), E_USER_ERROR);
}
function frame_c($a, $b) {
    $c = array_fill(0, 256, str_repeat('cc', 512));
    frame_d($a, $b, $c);
}
function frame_b($a) {
    $b = str_repeat('bbbb', 4096);
    frame_c($a, $b);
}
function frame_a() {
    $a = ['big' => str_repeat('aaaa', 4096), 'list' => range(0, 1024)];
    frame_b($a);
}

frame_a();
echo "unreachable\n";

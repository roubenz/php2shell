<?php
/* erd ECHO sink -- the SINGLE app precondition the full echo-route leak+fire
 * end-to-end needs: an application that unserialize()s request input and echoes
 * serialize() of the result. This one reflective endpoint carries EVERYTHING:
 *   - the a7 R: chunk leak,
 *   - the write-free forged-IS_STRING binbase image-pointer reads,
 *   - the a7 fire's by-name RESOLUTION reads (R-3 executor_globals, R-4
 *     libc/system, R-5 stdClass ce, R-6 spray slot).
 * The a7 fpm driver posts the serialized payload in the `cook` field
 * (a7_fpm_rce._fpm_send_http / fpm_binbase_rleak). It also accepts `rows`/`sess`
 * so the verifier can read a sort/gate shape's echo ground truth here.
 *
 * Assign to a local first ($r = unserialize(...); echo serialize($r);) so the
 * result-construction allocations -- and thus the a7 reclaim slot the leaked
 * pointer lands in -- match an ordinary app.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string)$b);
echo serialize($r);

<?php
/* COMPARISON SINK (erd): session/cache ACCESS GATE -> ordered side effect.
 * The client presents a serialized session blob (`sess`) and the clearance
 * marker it wants (`need`). The app decodes the session, reads the stored token,
 * and GRANTS (302 -> /area) iff the token sorts below the requested marker, else
 * DENIES (403) -- the everyday "gate on a decoded field" ordered strcmp. The
 * token's bytes are NEVER emitted; the client observes only the HTTP status
 * (302 vs 403) and the redirect Location -- one ordered boolean per request,
 * binary-searchable. In the driver's comparison mode this CROSS-AGREES the
 * leaked chunk pointer over an independent non-echo channel.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';

$sess = @unserialize((string)($_POST['sess'] ?? ''));
$need = (string)($_POST['need'] ?? '');
$tok  = erd_field($sess, 'tok');

if (is_string($tok) && strcmp($tok, $need) < 0) {
    http_response_code(302);
    header('Location: /area');          // ordered-true route (grant)
} else {
    http_response_code(403);            // ordered-false route (deny)
}
header('Content-Type: text/plain');
echo "gate\n";                          // fixed body -> no field reflection

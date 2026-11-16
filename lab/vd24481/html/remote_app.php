<?php
/* a7 echo sink on the SAME immortal worker as remote_app24481.php. Used by the
 * fully-remote fpm chain for the a7 forged-IS_STRING image-pointer read (binbase)
 * and the a7 UAF->RCE fire, GIVEN the chunk base sourced remotely from #24481.
 *
 * echo serialize(unserialize($cook)) -- the standard a7 read/resolution
 * transport. Assign to a local first so the result-construction allocations (and
 * thus the a7 reclaim slot) match an ordinary app.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? $_POST['rows'] ?? $_POST['sess'] ?? '';
$r = @unserialize((string) $b);
echo serialize($r);

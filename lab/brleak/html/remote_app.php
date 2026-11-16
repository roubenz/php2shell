<?php
/* brleak REFLECTIVE (echo) sink -- stands in for an application that
 * unserialize()s request input and echoes serialize() of the result. This is
 * the transport the a7 R: heap leak and the forged-IS_STRING image-pointer
 * reads ride on to recalibrate + prove poc/fpm_binbase_rleak.py's binbase leak.
 *
 * The a7 fpm transport posts the serialized payload in the `cook` field
 * (a7_unserialize_uaf.send_http). Assign to a local first so the
 * result-construction allocations -- and thus the reclaim slot the leaked
 * pointer lands in -- match an ordinary app.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['cook'] ?? '';
$r = @unserialize((string)$b);
echo serialize($r);

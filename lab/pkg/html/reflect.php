<?php
/* GROUND-TRUTH echo mirror (wex) -- VERIFIER ONLY; the channel this exercise
 * is proving it does NOT need.
 *
 * It accepts the SAME POST body shape as the side-effect apps (it reads
 * whichever payload field is present and ignores the operand fields), so the
 * pre-unserialize allocation sequence -- and therefore the a7 reclaim slot the
 * leaked pointer lands in -- is identical to the app under test. That makes its
 * echoed serialize() an EXACT byte-for-byte ground truth for the non-echo
 * recoveries. The exfil itself never touches this endpoint; only the verifier
 * does, to score the side-effect recoveries.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
header('Content-Type: text/plain');
$b = $_POST['sess'] ?? $_POST['rows'] ?? $_POST['ent'] ?? $_POST['blob'] ?? '';
/* Assign to a local first, exactly as the side-effect apps do
 * ($sess = unserialize(...); ...), so the result-construction allocations --
 * and thus the a7 reclaim slot the leaked pointer lands in -- match the app
 * under test. Unserializing inline (serialize(unserialize(...))) shifts the
 * slot and would make this a mismatched ground truth. */
$r = @unserialize((string)$b);
echo serialize($r);

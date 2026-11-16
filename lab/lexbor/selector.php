<?php
/**
 * Minimal app sink that applies an attacker-supplied CSS selector to an HTML
 * document via the new PHP 8.4+ DOM API. Represents the real-world reachable
 * pattern (HTML scrapers / templating / sanitizers that accept a user selector).
 *
 *   GET /selector.php?sel=<url-encoded CSS selector>&html=<optional html>
 *
 * A selector of the form :lexbor-contains("<16+ bytes>") drives the bundled
 * lexbor heap overflow in-process. On the ASan build this aborts the worker; on
 * a stock build it corrupts the lexbor mraw pool.
 */
$sel  = $_GET['sel']  ?? ':lexbor-contains("short")';
$html = $_GET['html'] ?? '<html><body><p class="test">Hello world</p></body></html>';

$doc = Dom\HTMLDocument::createFromString($html, LIBXML_NOERROR);
$nodes = $doc->querySelectorAll($sel);   // <-- selector reaches lexbor CSS parser
header('Content-Type: text/plain');
echo "matched " . $nodes->length . " node(s)\n";

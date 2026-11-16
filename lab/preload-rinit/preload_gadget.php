<?php
/* Lab-only gadget for poc/preload_rinit.py (CVE-2026-109619 pre-RINIT session
 * deserialization). It is made available before RINIT via opcache.preload so the
 * class exists when the RFC1867 upload-progress handler deserializes the session
 * record. This is a DELIBERATELY VULNERABLE gadget standing in for a real
 * framework class that happens to expose a dangerous __wakeup()/__unserialize().
 * NEVER deploy this to a real web root. */
class PreloadRceProbe
{
    public string $cmd = 'id';

    public function __wakeup(): void
    {
        $out = shell_exec($this->cmd);
        @file_put_contents('/tmp/preload_rinit_rce.txt', "preload_rinit CVE-2026-109619 __wakeup\n" . $out);
        echo "\nPRELOAD-RINIT-BEGIN\n" . $out . "PRELOAD-RINIT-END\n";
    }
}

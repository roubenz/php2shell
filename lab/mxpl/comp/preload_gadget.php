<?php
/* LAB-ONLY. Preloaded via opcache.preload so the class exists in every worker's
 * persistent class table BEFORE RINIT -- standing in for a real vendor class
 * (reachable through a framework preload list) that exposes a dangerous
 * __destruct POP head. CLEAN: no fatal, so the pre-RINIT decode that instantiates
 * it does not trip the exit(70) worker-fatal wall. NEVER deploy. */
class MxplGadget {
    public $cmd = 'id';
    public $path = '/tmp/mxpl_pwned.txt';
    public function __destruct() {
        // phpggc-shaped "file write" head, here made to also prove code-exec+uid.
        @file_put_contents($this->path, "MXPL-RCE uid=" . @posix_getuid() . " " . @shell_exec($this->cmd));
    }
}

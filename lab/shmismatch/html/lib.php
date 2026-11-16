<?php
// Realistic gadget surface. A deferred cache/temp writer whose __destruct has a
// filesystem side effect is a common pattern in real apps; here it is the POP
// gadget the injected object lands on.
class DeferredWriter {
    public $path;
    public $data;
    public function __destruct() { @file_put_contents($this->path, $this->data); }
}

<?php
// POP gadget reachable in the reader's scope (the app-dependent gate). A real
// target would supply an equivalent destructor gadget (file-write / call /
// phpggc chain); DeferredWriter is the lab stand-in, same shape as the
// shmismatch lab's gadget so the escalation payload is identical.
class DeferredWriter
{
    public $path;
    public $data;

    public function __destruct()
    {
        if ($this->path && $this->data !== null) {
            @file_put_contents($this->path, $this->data);
        }
    }
}

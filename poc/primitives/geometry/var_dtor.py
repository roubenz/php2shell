#!/usr/bin/env python3
"""var_dtor_entries data-slot geometry (Zend/zend_variables.c php_var_unserialize).

A var_dtor_entries block is a 0x10-byte header followed by an array of zval
(sizeof(zval) = 16), so the i-th deferred-dtor slot's data is at
    var_dtor_data_off(i) = 0x10 + i*16.
Finisher-agnostic ABI: the write-delivery placement primitives choose the slot i,
this gives its byte offset.
Stage: VERIFIED (8.3/8.4).
"""


def var_dtor_data_off(i):
    """Byte offset of var_dtor_entries->data[i] (header 0x10 + i*sizeof(zval)=16)."""
    return 0x10 + i * 16

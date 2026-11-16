#!/usr/bin/env python3
"""ZendMM allocator geometry (Zend/zend_alloc.c, zend_alloc_sizes.h): the 2 MiB
request chunk and the bin-320 slot layout the free-list write family shares.

CHUNK_SIZE / CHUNK_MASK  ZEND_MM_CHUNK_SIZE = 2 MiB; a request heap's chunk is
    CHUNK_SIZE-aligned (the zend_mm_heap struct sits at chunk+0x40), so
    chunk_base(addr) masks any chunk-interior pointer back to its chunk base.
BIN_DATA_SIZE  bin_data_size[16] = 320: a 257..320-byte emalloc lands in the 320 class.
SHADOW_OFFSET  ZEND_MM_FREE_SLOT_PTR_SHADOW = slot + BIN_DATA_SIZE - 8: the
    heap-protection shadow qword of a bin-320 slot.

Finisher-agnostic allocator ABI, consumed by the free-list seat/poison primitives,
the OPcache-SHM probe and chunk-base recovery.
Stage: VERIFIED (8.4.26).
"""

CHUNK_SIZE = 0x200000
CHUNK_MASK = CHUNK_SIZE - 1          # 0x1FFFFF

BIN_DATA_SIZE = 320                  # bin_data_size[16]
SHADOW_OFFSET = BIN_DATA_SIZE - 8    # slot + 320 - 8 = 312


def chunk_base(addr):
    """The CHUNK_SIZE-aligned ZendMM chunk base of a chunk-interior address."""
    return addr & ~CHUNK_MASK

/* aes128_dual_table: dual-block T-table AES. Wraps two AES_128_encrypt calls to
 *   give aes128_keygen's dual-block output. Round keys in DMEM (no WDR RK footprint).
 * in:  w18 = dual-block IV (block1 ctr @bytes 12..15 LE, block2 ctr @28..31 LE)
 *      x18 = round-key base in DMEM (176B, from AES_128_keyschedule)
 * out: w2 = 32B ciphertext (AES(block1) @0..15, AES(block2) @16..31)
 * clobber: x5..x8, x10..x16, x19..x22, x29, x31. preserves x1..x4,x9,x17,x18,x23..x28,x30.
 *   caller must save/restore its own x11, x12 (used as AES arg ptrs) around each call.
 * frame: 32B scratch (PT/CT). no GPR saves here.
 */
.section .text
.balign 4
.global aes128_dual_table
aes128_dual_table:
    /* 32 B scratch frame (PT/CT). 32-byte aligned (caller's x2 is). */
    addi x2, x2, -32

    /* Persist w18 to scratch so byteswap helpers can read LE counters. */
    li x6, 18
    bn.sid x6, 0(x2)

 /* BLOCK 1: counter at 12..15(x2), CT to 0..15(x2). */
    lw x5, 12(x2)                  /* x5 = block1 LE counter */
    /* Byte-swap x5 (LE) -> x6 (BE). */
    andi x6, x5, 0xff
    slli x6, x6, 24
    srli x7, x5, 8
    andi x7, x7, 0xff
    slli x7, x7, 16
    or   x6, x6, x7
    srli x7, x5, 16
    andi x7, x7, 0xff
    slli x7, x7, 8
    or   x6, x6, x7
    srli x7, x5, 24
    or   x6, x6, x7
    /* PT: bytes 0..11 = 0, bytes 12..15 = BE counter. */
    sw x0,  0(x2)
    sw x0,  4(x2)
    sw x0,  8(x2)
    sw x6, 12(x2)
    addi x10, x18, 0
    addi x11, x2,  0
    addi x12, x2,  0
    jal  x1, AES_128_encrypt

 /* BLOCK 2: counter still at 28..31(x2) (untouched by block 1). */
    lw x5, 28(x2)                  /* x5 = block2 LE counter */
    andi x6, x5, 0xff
    slli x6, x6, 24
    srli x7, x5, 8
    andi x7, x7, 0xff
    slli x7, x7, 16
    or   x6, x6, x7
    srli x7, x5, 16
    andi x7, x7, 0xff
    slli x7, x7, 8
    or   x6, x6, x7
    srli x7, x5, 24
    or   x6, x6, x7
    sw x0, 16(x2)
    sw x0, 20(x2)
    sw x0, 24(x2)
    sw x6, 28(x2)
    addi x10, x18, 0
    addi x11, x2, 16
    addi x12, x2, 16
    jal  x1, AES_128_encrypt

    /* Load full 32 B into w2 (block1 lo, block2 hi). */
    li x6, 2
    bn.lid x6, 0(x2)

    addi x2, x2, 32
    ret

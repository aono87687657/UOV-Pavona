/*
 * aes128_dualblock — encrypts 2 contiguous AES-CTR blocks (counters N, N+1).
 *
 * Aestable equivalent of bngfonly's aes128_sign dual-block operation. Output
 * placed in w2 = ct(N) || ct(N+1) (32B), matching bngfonly w2 byte layout.
 *
 * Calling convention:
 *   x10 (a0) = round-key base ptr (PRESERVED across call)
 *   x13 (a3) = LE counter (in: starting counter N; out: N + 2)
 *   x1  (ra) = link
 *
 * Output:
 *   w2 = AES_128(pt[0..15]=BE_IV(N)) || AES_128(pt[16..31]=BE_IV(N+1))
 *        — byte-identical to bngfonly aes128_sign's w2 for same (key, N).
 *
 * Stack: 64 bytes (32 B IV/ct scratch + 32 B GPR save slot, only 8 B used).
 *
 * Clobbers: GPRs — x6, x7, x9, x28, plus AES_128_encrypt clobbers
 *           (x10, x11, x12, x13 restored at exit). WDRs — w2 only.
 * Preserves: caller's x10, x11, x12, x13 (saved/restored on stack); all other
 *            WDRs/WSRs/CSRs.
 */
.section .text
.balign 4
.global aes128_dualblock
aes128_dualblock:
    /* 64B frame: 32B IV/ct scratch [0..31] + 32B GPR save slot [32..63]
     * (keeps x2 32-byte aligned for bn.sid/bn.lid; only 8 bytes of save
     *  slot are used — for x11/x12 — rest is padding). */
    addi x2, x2, -64
    sw x11, 32(x2)
    sw x12, 36(x2)
    addi x9, x13, 0                 /* x9 = counter (survives AES_128_encrypt) */
    addi x28, x10, 0                /* save rk base (AES clobbers x10) */

    /* ---- Build IV for block 0 at scratch[0..15]:
     *      bytes 0..11 = 0, bytes 12..15 = bswap32(x9) (BE counter) ---- */
    sw x0, 0(x2)
    sw x0, 4(x2)
    sw x0, 8(x2)
    andi x6, x9, 0xff
    slli x6, x6, 24
    srli x7, x9, 8
    andi x7, x7, 0xff
    slli x7, x7, 16
    or x6, x6, x7
    srli x7, x9, 16
    andi x7, x7, 0xff
    slli x7, x7, 8
    or x6, x6, x7
    srli x7, x9, 24
    or x6, x6, x7
    sw x6, 12(x2)

    /* ---- Build IV for block 1 at scratch[16..31] ---- */
    addi x9, x9, 1                  /* counter for block 1 */
    sw x0, 16(x2)
    sw x0, 20(x2)
    sw x0, 24(x2)
    andi x6, x9, 0xff
    slli x6, x6, 24
    srli x7, x9, 8
    andi x7, x7, 0xff
    slli x7, x7, 16
    or x6, x6, x7
    srli x7, x9, 16
    andi x7, x7, 0xff
    slli x7, x7, 8
    or x6, x6, x7
    srli x7, x9, 24
    or x6, x6, x7
    sw x6, 28(x2)
    addi x9, x9, 1                  /* x9 = N+2 (final value to return) */

    /* AES_128_encrypt block 0 in-place */
    addi x10, x28, 0                /* rk base */
    addi x11, x2, 0                 /* pt = scratch[0..15] */
    addi x12, x2, 0                 /* ct = scratch[0..15] */
    jal x1, AES_128_encrypt

    /* AES_128_encrypt block 1 in-place */
    addi x10, x28, 0                /* rk base */
    addi x11, x2, 16                /* pt = scratch[16..31] */
    addi x12, x2, 16                /* ct = scratch[16..31] */
    jal x1, AES_128_encrypt

    /* Load dual-block ciphertext into w2 (32B, byte-identical to bngfonly w2) */
    li x6, 2
    bn.lid x6, 0(x2)

    /* Restore caller-facing state */
    addi x10, x28, 0                /* x10 = rk base (preserved across call) */
    addi x13, x9, 0                 /* x13 = counter + 2 (advanced) */
    lw x11, 32(x2)                  /* restore caller's x11 */
    lw x12, 36(x2)                  /* restore caller's x12 */

    addi x2, x2, 64
    ret

/*
 * expand_352_table — aestable equivalent of bngfonly's expand_352.
 *
 * Generates 22 AES-CTR blocks (352 B) from round_keys, packs them into
 * 8 P1 entries via the same rshi-reorder pattern as bngfonly/bngfaes.
 * Since aes128table_352 produces byte-identical ciphertexts to bngfonly's
 * 11×aes128_sign sequence (both are AES-128-CTR for the same key+counter
 * range), the rshi pattern is reused verbatim.
 *
 * Calling convention:
 *   x10 (a0) = round-key base ptr (input; CLOBBERED — caller restores from x18)
 *   x13 (a3) = LE counter (in: starting; out: starting + 22)
 *   x1  (ra) = link
 *
 * Output (matches bngfonly expand_352 exactly):
 *   w1, w3, w5, w7, w9, w11, w13, w15 = 8 packed P1 entries
 *
 * Stack: 416 B (352 ct buffer + 64 GPR-save slot).
 *
 * Clobbers: w0..w15 (rshi reorder); w16-w31 preserved. GPRs: x10, x14-x16,
 *           x19, x22 (leaked from AES_128_encrypt); x13 returned advanced.
 * Preserves: x5-x9, x11, x12, x20, x21, x28-x31 (saved/restored — gf256trimat
 *            keeps its cursors and consts across the call).
 */
.section .text
.balign 4
.global expand_352_table
expand_352_table:
    addi x2, x2, -416               /* 352B ct buffer + 64B GPR saves */
    /* Save all AES-clobbered GPRs that gf256trimat depends on across this call.
     * AES_128_encrypt clobbers: x5..x8, x13..x16, x19..x22, x29, x31.
     * gf256trimat needs: x5, x6, x7, x8, x9, x11, x12, x20, x21, x31. (x13 is
     * managed I/O — counter; x9 actually preserved by AES_128_encrypt but
     * clobbered by aes128table_352 internally — save anyway.) */
    sw x5, 352(x2)
    sw x6, 356(x2)
    sw x7, 360(x2)
    sw x8, 364(x2)
    sw x9, 368(x2)
    sw x11, 372(x2)
    sw x12, 376(x2)
    sw x20, 380(x2)
    sw x21, 384(x2)
    sw x28, 388(x2)             /* aes128table_352 clobbers x28 (rk save) */
    sw x29, 392(x2)             /* AES_128_encrypt clobbers x29 */
    sw x30, 396(x2)             /* aes128table_352 clobbers x30 (output ptr cursor) */
    sw x31, 400(x2)

    /* Encrypt 22 blocks into buffer at scratch[0..351]; x13 += 22 */
    addi x11, x2, 0
    jal x1, aes128table_352

    /* Load 11 dual-block ciphertexts (32B each) into w0..w10 */
    li x6, 0
    bn.lid x6, 0(x2)
    addi x6, x6, 1
    bn.lid x6, 32(x2)
    addi x6, x6, 1
    bn.lid x6, 64(x2)
    addi x6, x6, 1
    bn.lid x6, 96(x2)
    addi x6, x6, 1
    bn.lid x6, 128(x2)
    addi x6, x6, 1
    bn.lid x6, 160(x2)
    addi x6, x6, 1
    bn.lid x6, 192(x2)
    addi x6, x6, 1
    bn.lid x6, 224(x2)
    addi x6, x6, 1
    bn.lid x6, 256(x2)
    addi x6, x6, 1
    bn.lid x6, 288(x2)
    addi x6, x6, 1
    bn.lid x6, 320(x2)

    /* rshi-reorder: pack 8 P1 entries into w1, w3, w5, ..., w15.
     * Preserved verbatim from bngfonly expand_352 (byte-identical AES output
     * means this rewrite is a no-op transformation). */
    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    bn.rshi w13, w9, w31 >> 160
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w9, w8 >> 64
    bn.rshi w11, w8, w7 >> 64
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w7, w6 >> 224
    bn.rshi w9, w6, w31 >> 224
    bn.rshi w9, w31, w9 >> 160
    bn.rshi w8, w6, w5 >> 128
    bn.rshi w7, w5, w31 >> 128
    bn.rshi w7, w31, w7 >> 160
    bn.rshi w6, w5, w4 >> 32
    bn.rshi w5, w4, w3 >> 32
    bn.rshi w5, w31, w5 >> 160
    bn.rshi w4, w3, w2 >> 192
    bn.rshi w3, w2, w31 >> 192
    bn.rshi w3, w31, w3 >> 160
    bn.rshi w2, w2, w1 >> 96
    bn.rshi w1, w1, w31 >> 96
    bn.rshi w1, w31, w1 >> 160

    lw x5, 352(x2)
    lw x6, 356(x2)
    lw x7, 360(x2)
    lw x8, 364(x2)
    lw x9, 368(x2)
    lw x11, 372(x2)
    lw x12, 376(x2)
    lw x20, 380(x2)
    lw x21, 384(x2)
    lw x28, 388(x2)
    lw x29, 392(x2)
    lw x30, 396(x2)
    lw x31, 400(x2)
    addi x2, x2, 416
    ret

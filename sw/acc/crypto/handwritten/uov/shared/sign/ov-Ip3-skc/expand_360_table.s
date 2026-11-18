/* expand_360_table: pack eight 45-byte entries from a 24-block AES-CTR batch.
 * in: x10 = 176 readable, word-aligned round-key bytes; with AES_INSTRUCTIONS,
 *     a 32-byte readable/aligned key slot (low 16 bytes used).
 *     x13 = counter (AES arm: <= 0xffffffe8); x16 = phase 0..3; w31 = 0.
 *     x2 is 32-byte aligned; key/round keys are disjoint from the stack frame.
 * out: x13 += 22,22,22,24 by phase, modulo 2^32; x16 = next phase.
 *      w0-w15 = eight pairs of 32 + 13 bytes, with zero-padded tails.
 * clob: AES arm: x13, x16, w0-w15, FG0.
 *       table arm: x10, x13-x16, x19, x22, w0-w15.
 * wdr: w16-w31 preserved.
 * stack: 448 writable bytes below x2 (384 ciphertext + 64 saves); x2 restored.
 */
.section .text
.balign 4
.global expand_360_table
expand_360_table:
    addi x2, x2, -448               /* 384B ct buffer + 64B GPR saves */
#ifdef AES_INSTRUCTIONS
    /* The hardware leaf changes x6; x11 selects the output buffer. */
    sw x6, 388(x2)
    sw x11, 404(x2)
#else
    /* AES_128_encrypt clobbers x5..x8, x13..x16, x19..x22, x29, x31 and
     * aes128table_384 adds x9, x28, x30; gf256trimat needs its cursors and
     * consts back, and x16 carries the phase across the call. */
    sw x5, 384(x2)
    sw x6, 388(x2)
    sw x7, 392(x2)
    sw x8, 396(x2)
    sw x9, 400(x2)
    sw x11, 404(x2)
    sw x12, 408(x2)
    sw x16, 412(x2)
    sw x20, 416(x2)
    sw x21, 420(x2)
    sw x28, 424(x2)
    sw x29, 428(x2)
    sw x30, 432(x2)
    sw x31, 436(x2)
#endif

    /* Encrypt 24 blocks into scratch[0..383]; x13 += 24 */
    addi x11, x2, 0
#ifdef AES_INSTRUCTIONS
    jal x1, aes128hw_384_sign     /* bnaesonly: x10 = AES key, no round keys */
    /* Ciphertext remains in w0-w11 after the leaf's stores. */
    lw x6, 388(x2)
    lw x11, 404(x2)
#else
    jal x1, aes128table_384

    /* Load the 12 dual-block ciphertexts (32B each) into w0..w11 */
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
    addi x6, x6, 1
    bn.lid x6, 352(x2)

    lw x5, 384(x2)
    lw x6, 388(x2)
    lw x7, 392(x2)
    lw x8, 396(x2)
    lw x9, 400(x2)
    lw x11, 404(x2)
    lw x12, 408(x2)
    lw x16, 412(x2)
    lw x20, 416(x2)
    lw x21, 420(x2)
    lw x28, 424(x2)
    lw x29, 428(x2)
    lw x30, 432(x2)
    lw x31, 436(x2)
#endif
    addi x2, x2, 448

    # phase dispatch: x16 = 0..3 in, next phase out
    beq x16, x0, exp360_p0
    addi x16, x16, -1
    beq x16, x0, exp360_p1
    addi x16, x16, -1
    beq x16, x0, exp360_p2

    # phase 3: window at buffer byte 24
    # entry 7 @ buf 339 (wdr 10 byte 19)
    bn.rshi w15, w31, w11 >> 152
    bn.rshi w14, w11, w10 >> 152
    # entry 6 @ buf 294 (wdr 9 byte 6)
    bn.rshi w13, w10, w31 >> 152
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w10, w9 >> 48
    # entry 5 @ buf 249 (wdr 7 byte 25)
    bn.rshi w11, w9, w8 >> 48
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 200
    # entry 4 @ buf 204 (wdr 6 byte 12)
    bn.rshi w9, w7, w31 >> 200
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 96
    # entry 3 @ buf 159 (wdr 4 byte 31)
    bn.rshi w7, w6, w5 >> 96
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 248
    # entry 2 @ buf 114 (wdr 3 byte 18)
    bn.rshi w5, w4, w31 >> 248
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 144
    # entry 0 @ buf 24 (wdr 0 byte 24)
    bn.rshi w0, w1, w0 >> 192
    bn.rshi w1, w2, w1 >> 40
    bn.rshi w1, w31, w1 >> 152
    # entry 1 @ buf 69 (wdr 2 byte 5)
    bn.rshi w2, w3, w2 >> 40
    bn.rshi w3, w3, w31 >> 144
    bn.rshi w3, w31, w3 >> 152
    li x16, 0
    ret

exp360_p0:
    # phase 0: window at buffer byte 0
    addi x13, x13, -2
    # entry 7 @ buf 315 (wdr 9 byte 27)
    bn.rshi w15, w11, w10 >> 64
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w10, w9 >> 216
    # entry 6 @ buf 270 (wdr 8 byte 14)
    bn.rshi w13, w9, w31 >> 216
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 112
    # entry 5 @ buf 225 (wdr 7 byte 1)
    bn.rshi w11, w8, w31 >> 112
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 8
    # entry 4 @ buf 180 (wdr 5 byte 20)
    bn.rshi w9, w7, w6 >> 8
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 160
    # entry 3 @ buf 135 (wdr 4 byte 7)
    bn.rshi w7, w5, w31 >> 160
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 56
    # entry 2 @ buf 90 (wdr 2 byte 26)
    bn.rshi w5, w4, w3 >> 56
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w3, w2 >> 208
    # entry 1 @ buf 45 (wdr 1 byte 13)
    bn.rshi w3, w2, w31 >> 208
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 104
    # entry 0 @ buf 0 (wdr 0 byte 0)
    bn.rshi w1, w1, w31 >> 104
    bn.rshi w1, w31, w1 >> 152
    li x16, 1
    ret

exp360_p1:
    # phase 1: window at buffer byte 8
    addi x13, x13, -2
    # entry 7 @ buf 323 (wdr 10 byte 3)
    bn.rshi w15, w11, w31 >> 128
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 24
    # entry 6 @ buf 278 (wdr 8 byte 22)
    bn.rshi w13, w10, w9 >> 24
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 176
    # entry 5 @ buf 233 (wdr 7 byte 9)
    bn.rshi w11, w8, w31 >> 176
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 72
    # entry 4 @ buf 188 (wdr 5 byte 28)
    bn.rshi w9, w7, w6 >> 72
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w6, w5 >> 224
    # entry 3 @ buf 143 (wdr 4 byte 15)
    bn.rshi w7, w5, w31 >> 224
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 120
    # entry 2 @ buf 98 (wdr 3 byte 2)
    bn.rshi w5, w4, w31 >> 120
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 16
    # entry 1 @ buf 53 (wdr 1 byte 21)
    bn.rshi w3, w3, w2 >> 16
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 168
    # entry 0 @ buf 8 (wdr 0 byte 8)
    bn.rshi w0, w1, w0 >> 64
    bn.rshi w1, w1, w31 >> 168
    bn.rshi w1, w31, w1 >> 152
    li x16, 2
    ret

exp360_p2:
    # phase 2: window at buffer byte 16
    addi x13, x13, -2
    # entry 7 @ buf 331 (wdr 10 byte 11)
    bn.rshi w15, w11, w31 >> 192
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w11, w10 >> 88
    # entry 6 @ buf 286 (wdr 8 byte 30)
    bn.rshi w13, w10, w9 >> 88
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w9, w8 >> 240
    # entry 5 @ buf 241 (wdr 7 byte 17)
    bn.rshi w11, w8, w31 >> 240
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w10, w8, w7 >> 136
    # entry 4 @ buf 196 (wdr 6 byte 4)
    bn.rshi w9, w7, w31 >> 136
    bn.rshi w9, w31, w9 >> 152
    bn.rshi w8, w7, w6 >> 32
    # entry 3 @ buf 151 (wdr 4 byte 23)
    bn.rshi w7, w6, w5 >> 32
    bn.rshi w7, w31, w7 >> 152
    bn.rshi w6, w5, w4 >> 184
    # entry 2 @ buf 106 (wdr 3 byte 10)
    bn.rshi w5, w4, w31 >> 184
    bn.rshi w5, w31, w5 >> 152
    bn.rshi w4, w4, w3 >> 80
    # entry 1 @ buf 61 (wdr 1 byte 29)
    bn.rshi w3, w3, w2 >> 80
    bn.rshi w3, w31, w3 >> 152
    bn.rshi w2, w2, w1 >> 232
    # entry 0 @ buf 16 (wdr 0 byte 16)
    bn.rshi w0, w1, w0 >> 128
    bn.rshi w1, w1, w31 >> 232
    bn.rshi w1, w31, w1 >> 152
    li x16, 3
    ret


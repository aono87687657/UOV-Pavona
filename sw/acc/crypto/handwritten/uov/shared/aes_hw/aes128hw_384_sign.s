/* aes128hw_384_sign: 24 AES-128-CTR blocks in memory and w0-w11.
 * in: x10 = 32-byte readable/aligned key slot (low 16 bytes used).
 *     x11 = 384-byte output, 32-byte aligned; first 32 bytes are IV scratch.
 *     Key bytes must not overlap that scratch; x13 = counter <= 0xffffffe8.
 * out: x13 = start + 24 modulo 2^32; w0-w11 = the stored 384 ciphertext bytes.
 * clob: x6, w12-w15, FG0.
 * wdr: w16-w31 preserved.
 * stack: none (leaf).
 */
.section .text
.balign 4
.global aes128hw_384_sign
aes128hw_384_sign:
    /* dual 0 IV: 12 zero bytes + LE counter at byte 12 in each 128 b lane */
    bn.xor w15, w15, w15
    bn.sd  w15, 0(x11)
    sw     x13, 12(x11)
    addi   x6, x13, 1
    sw     x6, 28(x11)
    bn.ld  w0, 0(x11)
    bn.ld  w12, 0(x10)        /* AES key */

    /* +2 per lane: a dual is two blocks. No lane can carry (counter << 2^32) */
    bn.addi w14, w15, 2
    bn.or   w14, w14, w14 << 128
    bn.rshi w14, w14, w15 >> 160

    bn.add w1, w0, w14
    bn.add w2, w1, w14
    bn.add w3, w2, w14
    bn.add w4, w3, w14
    bn.add w5, w4, w14
    bn.add w6, w5, w14
    bn.add w7, w6, w14
    bn.add w8, w7, w14
    bn.add w9, w8, w14
    bn.add w10, w9, w14
    bn.add w11, w10, w14

    /* round 0: .swap makes the counter field big-endian, as AES-CTR wants */
    bn.aes128.encz.swap w0, w0, w12
    bn.aes128.encz.swap w1, w1, w12
    bn.aes128.encz.swap w2, w2, w12
    bn.aes128.encz.swap w3, w3, w12
    bn.aes128.encz.swap w4, w4, w12
    bn.aes128.encz.swap w5, w5, w12
    bn.aes128.encz.swap w6, w6, w12
    bn.aes128.encz.swap w7, w7, w12
    bn.aes128.encz.swap w8, w8, w12
    bn.aes128.encz.swap w9, w9, w12
    bn.aes128.encz.swap w10, w10, w12
    bn.aes128.encz.swap w11, w11, w12

    bn.aes128.kf w13, w12, 1
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 2
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 3
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 4
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 5
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 6
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 7
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 8
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 9
    bn.aes128.encm w0, w0, w13
    bn.aes128.encm w1, w1, w13
    bn.aes128.encm w2, w2, w13
    bn.aes128.encm w3, w3, w13
    bn.aes128.encm w4, w4, w13
    bn.aes128.encm w5, w5, w13
    bn.aes128.encm w6, w6, w13
    bn.aes128.encm w7, w7, w13
    bn.aes128.encm w8, w8, w13
    bn.aes128.encm w9, w9, w13
    bn.aes128.encm w10, w10, w13
    bn.aes128.encm w11, w11, w13

    bn.aes128.kf w13, w13, 10
    bn.aes128.encf w0, w0, w13
    bn.aes128.encf w1, w1, w13
    bn.aes128.encf w2, w2, w13
    bn.aes128.encf w3, w3, w13
    bn.aes128.encf w4, w4, w13
    bn.aes128.encf w5, w5, w13
    bn.aes128.encf w6, w6, w13
    bn.aes128.encf w7, w7, w13
    bn.aes128.encf w8, w8, w13
    bn.aes128.encf w9, w9, w13
    bn.aes128.encf w10, w10, w13
    bn.aes128.encf w11, w11, w13

    bn.sd  w0, 0(x11)
    bn.sd  w1, 32(x11)
    bn.sd  w2, 64(x11)
    bn.sd  w3, 96(x11)
    bn.sd  w4, 128(x11)
    bn.sd  w5, 160(x11)
    bn.sd  w6, 192(x11)
    bn.sd  w7, 224(x11)
    bn.sd  w8, 256(x11)
    bn.sd  w9, 288(x11)
    bn.sd  w10, 320(x11)
    bn.sd  w11, 352(x11)

    addi x13, x13, 24         /* chain the counter for the next call */
    ret

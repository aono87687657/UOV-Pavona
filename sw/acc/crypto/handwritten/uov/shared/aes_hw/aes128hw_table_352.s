/* aes128table_352, hardware: 22 AES-128-CTR blocks (352 B) with bn.aes128 behind the
 * contract of the T-table wrapper of the same name, for the Round-2 Ip AES-only sign and
 * keygen kernels. The 22-block body is that of dmem32k/verify_stream_uniform/ov-Ip-pkc/aes128hw_352.s.
 * in    : x10 = round-key buffer (bytes 0..15, the key, are read; 4-byte aligned)
 *         x11 = 352 B output buffer, 32-byte aligned (the body stores with bn.sd)
 *         x13 = LE block counter in; out: x13 + 22
 * clob  : x5-x8, x10, x12 (within the wrapper's set); x9 scratch base, x7 saved FLAGS.
 * wdr   : none clobbered: the body uses w0-w10, w14, w15, w18, w30, all saved and
 *         restored here. FLAGS saved and restored (the body's counter adds write FG0).
 * data  : 512 B private scratch (key slot + fifteen wide saves); non-reentrant.
 * stack : none; no nested call.
 */
.section .text
.balign 4
.globl aes128table_352
aes128table_352:
    la x9, aes128hw_table_scratch
    csrrs x7, flags, x0
    bn.sd w0, 32(x9)
    bn.sd w1, 64(x9)
    bn.sd w2, 96(x9)
    bn.sd w3, 128(x9)
    bn.sd w4, 160(x9)
    bn.sd w5, 192(x9)
    bn.sd w6, 224(x9)
    bn.sd w7, 256(x9)
    bn.sd w8, 288(x9)
    bn.sd w9, 320(x9)
    bn.sd w10, 352(x9)
    bn.sd w14, 384(x9)
    bn.sd w15, 416(x9)
    bn.sd w18, 448(x9)
    bn.sd w30, 480(x9)
    lw x5, 0(x10)                   /* the key = round key 0, staged into the aligned slot */
    lw x6, 4(x10)
    lw x8, 8(x10)
    lw x12, 12(x10)
    sw x5, 0(x9)
    sw x6, 4(x9)
    sw x8, 8(x9)
    sw x12, 12(x9)
    sw x0, 16(x9)
    sw x0, 20(x9)
    sw x0, 24(x9)
    sw x0, 28(x9)
    addi x10, x9, 0
    /* dual 0 IV: 12 zero bytes + LE counter at byte 12 in each 128 b lane */
    bn.xor w18, w18, w18
    bn.sd  w18, 0(x11)
    sw     x13, 12(x11)
    addi   x6, x13, 1
    sw     x6, 28(x11)
    bn.ld  w0, 0(x11)
    bn.ld  w30, 0(x10)        /* AES key */

    /* +2 per lane: a dual is two blocks. No lane can carry (counter << 2^32) */
    bn.addi w15, w18, 2
    bn.or   w15, w15, w15 << 128
    bn.rshi w15, w15, w18 >> 160

    bn.add w1, w0, w15
    bn.add w2, w1, w15
    bn.add w3, w2, w15
    bn.add w4, w3, w15
    bn.add w5, w4, w15
    bn.add w6, w5, w15
    bn.add w7, w6, w15
    bn.add w8, w7, w15
    bn.add w9, w8, w15
    bn.add w10, w9, w15

    /* round 0: .swap makes the counter field big-endian, as AES-CTR wants */
    bn.aes128.encz.swap w0, w0, w30
    bn.aes128.encz.swap w1, w1, w30
    bn.aes128.encz.swap w2, w2, w30
    bn.aes128.encz.swap w3, w3, w30
    bn.aes128.encz.swap w4, w4, w30
    bn.aes128.encz.swap w5, w5, w30
    bn.aes128.encz.swap w6, w6, w30
    bn.aes128.encz.swap w7, w7, w30
    bn.aes128.encz.swap w8, w8, w30
    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encz.swap w10, w10, w30

    bn.aes128.kf w14, w30, 1
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 2
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 3
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 4
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 5
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 6
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 7
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 8
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 9
    bn.aes128.encm w0, w0, w14
    bn.aes128.encm w1, w1, w14
    bn.aes128.encm w2, w2, w14
    bn.aes128.encm w3, w3, w14
    bn.aes128.encm w4, w4, w14
    bn.aes128.encm w5, w5, w14
    bn.aes128.encm w6, w6, w14
    bn.aes128.encm w7, w7, w14
    bn.aes128.encm w8, w8, w14
    bn.aes128.encm w9, w9, w14
    bn.aes128.encm w10, w10, w14

    bn.aes128.kf w14, w14, 10
    bn.aes128.encf w0, w0, w14
    bn.aes128.encf w1, w1, w14
    bn.aes128.encf w2, w2, w14
    bn.aes128.encf w3, w3, w14
    bn.aes128.encf w4, w4, w14
    bn.aes128.encf w5, w5, w14
    bn.aes128.encf w6, w6, w14
    bn.aes128.encf w7, w7, w14
    bn.aes128.encf w8, w8, w14
    bn.aes128.encf w9, w9, w14
    bn.aes128.encf w10, w10, w14

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

    addi x13, x13, 22         /* chain the counter for the next call */
    bn.ld w0, 32(x9)
    bn.ld w1, 64(x9)
    bn.ld w2, 96(x9)
    bn.ld w3, 128(x9)
    bn.ld w4, 160(x9)
    bn.ld w5, 192(x9)
    bn.ld w6, 224(x9)
    bn.ld w7, 256(x9)
    bn.ld w8, 288(x9)
    bn.ld w9, 320(x9)
    bn.ld w10, 352(x9)
    bn.ld w14, 384(x9)
    bn.ld w15, 416(x9)
    bn.ld w18, 448(x9)
    bn.ld w30, 480(x9)
    csrrw x0, flags, x7
    ret

.section .data
.balign 32
aes128hw_table_scratch: .zero 512

/* aes128hw_352: AES-128-CTR PRG, 22 blocks = 352 B keystream, bn.aes128.
 * Drop-in for aes128table_352 in the R2 Ip streamed verify: 11 duals, counter
 * +22. Same register plan as the R3 verify leaf, but that is a MEASURED
 * coincidence -- the R2 fold statically touches w10/w15-w19/w30 and only an ISS
 * liveness pass showed they are written before read after the call.
 * Same buffer layout and counter chaining as the T-table leaf.
 * The key is reloaded per call: the caller owns every WDR that survives a call.
 * in    : x10 = 16 B AES key (32 B aligned; only the low 128 b are used)
 *         x11 = 352 B out, 32 B aligned; its first 32 B are the IV scratch
 *         x13 = start block counter (LE)
 * out   : x13 = start + 22
 * clob  : x6 ; w0-w10, w14, w15, w18, w30 ; FG0 (bn.add)
 * stack : none (leaf)
 */
.section .text
.balign 4
.global aes128hw_352
aes128hw_352:
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
    ret

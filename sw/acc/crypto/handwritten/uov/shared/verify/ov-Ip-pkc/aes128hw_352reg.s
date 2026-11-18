/* aes128hw_352reg: AES-128-CTR PRG, 22 blocks = 352 B, bn.aes128, returned
 * IN REGISTERS. Same keystream and counter chaining as aes128hw_352; that
 * one stores to a buffer, this one does not store at all.
 * Duals 0..10 come back in w7 w8 w9 w10 w13 w14 w15 w18 w19 w20 w30, in
 * that order - dual i is keystream bytes [32i, 32i+32).
 * The caller must own those 11 WDRs across the call, and must NOT hold
 * anything in w0-w3.
 * in    : x10 = 16 B AES key (32 B aligned; only the low 128 b are used)
 *         x11 = 32 B scratch, 32 B aligned (IV staging only, not output)
 *         x13 = start block counter (LE)
 * out   : x13 = start + 22 ; duals in the 11 WDRs above
 * clob  : x6 ; w0-w3 ; FG0 (bn.add)
 * stack : none (leaf)
 */
.section .text
.balign 4
.global aes128hw_352reg
aes128hw_352reg:
    /* dual 0 IV: 12 zero bytes + LE counter at byte 12 in each 128 b lane */
    bn.xor w3, w3, w3
    bn.sd  w3, 0(x11)
    sw     x13, 12(x11)
    addi   x6, x13, 1
    sw     x6, 28(x11)
    bn.ld  w7, 0(x11)
    bn.ld  w0, 0(x10)        /* AES key */

    /* +2 per lane: a dual is two blocks. No lane can carry (counter << 2^32) */
    bn.addi w2, w3, 2
    bn.or   w2, w2, w2 << 128
    bn.rshi w2, w2, w3 >> 160

    bn.add w8, w7, w2
    bn.add w9, w8, w2
    bn.add w10, w9, w2
    bn.add w13, w10, w2
    bn.add w14, w13, w2
    bn.add w15, w14, w2
    bn.add w18, w15, w2
    bn.add w19, w18, w2
    bn.add w20, w19, w2
    bn.add w30, w20, w2

    /* round 0: .swap makes the counter field big-endian, as AES-CTR wants */
    bn.aes128.encz.swap w7, w7, w0
    bn.aes128.encz.swap w8, w8, w0
    bn.aes128.encz.swap w9, w9, w0
    bn.aes128.encz.swap w10, w10, w0
    bn.aes128.encz.swap w13, w13, w0
    bn.aes128.encz.swap w14, w14, w0
    bn.aes128.encz.swap w15, w15, w0
    bn.aes128.encz.swap w18, w18, w0
    bn.aes128.encz.swap w19, w19, w0
    bn.aes128.encz.swap w20, w20, w0
    bn.aes128.encz.swap w30, w30, w0

    bn.aes128.kf w1, w0, 1
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 2
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 3
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 4
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 5
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 6
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 7
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 8
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 9
    bn.aes128.encm w7, w7, w1
    bn.aes128.encm w8, w8, w1
    bn.aes128.encm w9, w9, w1
    bn.aes128.encm w10, w10, w1
    bn.aes128.encm w13, w13, w1
    bn.aes128.encm w14, w14, w1
    bn.aes128.encm w15, w15, w1
    bn.aes128.encm w18, w18, w1
    bn.aes128.encm w19, w19, w1
    bn.aes128.encm w20, w20, w1
    bn.aes128.encm w30, w30, w1

    bn.aes128.kf w1, w1, 10
    bn.aes128.encf w7, w7, w1
    bn.aes128.encf w8, w8, w1
    bn.aes128.encf w9, w9, w1
    bn.aes128.encf w10, w10, w1
    bn.aes128.encf w13, w13, w1
    bn.aes128.encf w14, w14, w1
    bn.aes128.encf w15, w15, w1
    bn.aes128.encf w18, w18, w1
    bn.aes128.encf w19, w19, w1
    bn.aes128.encf w20, w20, w1
    bn.aes128.encf w30, w30, w1

    addi x13, x13, 22         /* chain the counter for the next call */
    ret

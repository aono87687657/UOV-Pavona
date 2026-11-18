/* aes128_352 (Ip verify, bngfaes): 11 dual-block AES-128-CTR batch (352B keystream)
 * via bn.aes128 encz.swap/encm/encf with on-the-fly kf key schedule in w28.
 * in    : w27 counter increment, w30 base key, w31 zero
 * in-out: w29 IV base -> advanced past this batch
 * out   : w9-w23 keystream realigned to 44B columns
 * clob  : w8-w23, w28, FG0 (bn.add); no GPR/WSR/CSR writes
 * stack : none (leaf)
 */
.section .text
.balign 4
.global aes128_352
aes128_352:
    /* Prepare 11 IV blocks in w8-w18 */
    bn.mov w8, w29
    bn.add w9, w8, w27
    bn.add w10, w9, w27
    bn.add w11, w10, w27
    bn.add w12, w11, w27
    bn.add w13, w12, w27
    bn.add w14, w13, w27
    bn.add w15, w14, w27
    bn.add w16, w15, w27
    bn.add w17, w16, w27
    bn.add w18, w17, w27
    /* Update IV for next batch */
    bn.add w29, w18, w27

    /* Zero round: byte-swap counters + XOR with base key */
    bn.aes128.encz.swap w8, w8, w30
    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encz.swap w10, w10, w30
    bn.aes128.encz.swap w11, w11, w30
    bn.aes128.encz.swap w12, w12, w30
    bn.aes128.encz.swap w13, w13, w30
    bn.aes128.encz.swap w14, w14, w30
    bn.aes128.encz.swap w15, w15, w30
    bn.aes128.encz.swap w16, w16, w30
    bn.aes128.encz.swap w17, w17, w30
    bn.aes128.encz.swap w18, w18, w30

    /* Rounds 1-9: on-the-fly key schedule in w28 */
    bn.aes128.kf w28, w30, 1
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 2
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 3
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 4
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 5
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 6
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 7
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 8
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 9
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w11, w11, w28
    bn.aes128.encm w12, w12, w28
    bn.aes128.encm w13, w13, w28
    bn.aes128.encm w14, w14, w28
    bn.aes128.encm w15, w15, w28
    bn.aes128.encm w16, w16, w28
    bn.aes128.encm w17, w17, w28
    bn.aes128.encm w18, w18, w28

    bn.aes128.kf w28, w28, 10
    bn.aes128.encf w8, w8, w28
    bn.aes128.encf w9, w9, w28
    bn.aes128.encf w10, w10, w28
    bn.aes128.encf w11, w11, w28
    bn.aes128.encf w12, w12, w28
    bn.aes128.encf w13, w13, w28
    bn.aes128.encf w14, w14, w28
    bn.aes128.encf w15, w15, w28
    bn.aes128.encf w16, w16, w28
    bn.aes128.encf w17, w17, w28
    bn.aes128.encf w18, w18, w28

    /* Repack w8-w18 into 8 column pairs w8-w23 (identical to old code) */
    bn.rshi w23, w31, w18 >> 160
    bn.rshi w22, w18, w17 >> 160

    bn.rshi w21, w17, w31 >> 160
    bn.rshi w21, w31, w21 >> 160
    bn.rshi w20, w17, w16 >> 64

    bn.rshi w19, w16, w15 >> 64
    bn.rshi w19, w31, w19 >> 160
    bn.rshi w18, w15, w14 >> 224

    bn.rshi w17, w14, w31 >> 224
    bn.rshi w17, w31, w17 >> 160
    bn.rshi w16, w14, w13 >> 128

    bn.rshi w15, w13, w31 >> 128
    bn.rshi w15, w31, w15 >> 160
    bn.rshi w14, w13, w12 >> 32

    bn.rshi w13, w12, w11 >> 32
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w11, w10 >> 192

    bn.rshi w11, w10, w31 >> 192
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w10, w9 >> 96

    bn.rshi w9, w9, w31 >> 96
    bn.rshi w9, w31, w9 >> 160

    ret

/* load_p3_45 (Ip3 verify): load 8 packed 45B P3 columns (360B) and realign each
 * to a 32B WDR pair.  360B is not a whole number of WDRs, so the read pointer's
 * alignment cycles 4/12/20/28 and each phase carries its own schedule; bn.ld
 * traps on an unaligned address.  Each phase reads from the 32B floor below its
 * batch and advances the floor by 352/352/352/384.
 * in   : x12 32B-aligned read base, x2 phase 0..3, w31 zero
 * out  : w8-w23, column c in (w8+2c, w9+2c) as 32B + 13B zero-extended
 * clob : w8-w23, w26-w27, x2, x4, x12
 * stack: none (leaf)
 */
.section .text
.balign 4
.global load_p3_45
load_p3_45:
    beq  x2, x0, _lp3_ph0
    li   x4, 1
    beq  x2, x4, _lp3_ph1
    li   x4, 2
    beq  x2, x4, _lp3_ph2
    beq  x0, x0, _lp3_ph3

_lp3_ph0:
    bn.ld w8, 0(x12)
    bn.ld w9, 32(x12)
    bn.ld w10, 64(x12)
    bn.ld w11, 96(x12)
    bn.ld w12, 128(x12)
    bn.ld w13, 160(x12)
    bn.ld w14, 192(x12)
    bn.ld w15, 224(x12)
    bn.ld w16, 256(x12)
    bn.ld w17, 288(x12)
    bn.ld w18, 320(x12)
    bn.ld w19, 352(x12)
    bn.rshi w22, w18, w17 >> 248
    bn.rshi w23, w19, w18 >> 248
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 144
    bn.rshi w21, w18, w17 >> 144
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 40
    bn.rshi w19, w17, w16 >> 40
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w13 >> 192
    bn.rshi w17, w15, w14 >> 192
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w14, w13, w12 >> 88
    bn.rshi w15, w14, w13 >> 88
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w13, w12, w11 >> 240
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w11, w10 >> 240
    bn.rshi w10, w10, w9 >> 136
    bn.ld w26, 64(x12)
    bn.rshi w11, w11, w26 >> 136
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 32
    bn.ld w26, 64(x12)
    bn.rshi w9, w26, w9 >> 32
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    addi x12, x12, 352
    li   x2, 1
    ret

_lp3_ph1:
    bn.ld w8, 0(x12)
    bn.ld w9, 32(x12)
    bn.ld w10, 64(x12)
    bn.ld w11, 96(x12)
    bn.ld w12, 128(x12)
    bn.ld w13, 160(x12)
    bn.ld w14, 192(x12)
    bn.ld w15, 224(x12)
    bn.ld w16, 256(x12)
    bn.ld w17, 288(x12)
    bn.ld w18, 320(x12)
    bn.ld w19, 352(x12)
    bn.rshi w22, w19, w18 >> 56
    bn.rshi w23, w19, w19 >> 56
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 208
    bn.rshi w21, w18, w17 >> 208
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 104
    bn.rshi w19, w17, w16 >> 104
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w14 >> 0
    bn.rshi w17, w16, w15 >> 0
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w14, w13, w12 >> 152
    bn.rshi w15, w31, w13 >> 152
    bn.rshi w12, w12, w11 >> 48
    bn.ld w26, 128(x12)
    bn.rshi w13, w13, w26 >> 48
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w10, w9 >> 200
    bn.ld w26, 64(x12)
    bn.rshi w11, w11, w26 >> 200
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 96
    bn.ld w26, 64(x12)
    bn.rshi w9, w26, w9 >> 96
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    addi x12, x12, 352
    li   x2, 2
    ret

_lp3_ph2:
    bn.ld w8, 0(x12)
    bn.ld w9, 32(x12)
    bn.ld w10, 64(x12)
    bn.ld w11, 96(x12)
    bn.ld w12, 128(x12)
    bn.ld w13, 160(x12)
    bn.ld w14, 192(x12)
    bn.ld w15, 224(x12)
    bn.ld w16, 256(x12)
    bn.ld w17, 288(x12)
    bn.ld w18, 320(x12)
    bn.ld w19, 352(x12)
    bn.rshi w22, w19, w18 >> 120
    bn.rshi w23, w19, w19 >> 120
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w18, w17 >> 16
    bn.rshi w21, w19, w18 >> 16
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 168
    bn.rshi w19, w17, w16 >> 168
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w15, w14 >> 64
    bn.rshi w17, w16, w15 >> 64
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w15, w14, w13 >> 216
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 216
    bn.rshi w12, w12, w11 >> 112
    bn.ld w26, 128(x12)
    bn.rshi w13, w13, w26 >> 112
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w11, w10 >> 8
    bn.ld w26, 128(x12)
    bn.rshi w11, w26, w11 >> 8
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 160
    bn.ld w26, 64(x12)
    bn.rshi w9, w26, w9 >> 160
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    addi x12, x12, 352
    li   x2, 3
    ret

_lp3_ph3:
    bn.ld w8, 0(x12)
    bn.ld w9, 32(x12)
    bn.ld w10, 64(x12)
    bn.ld w11, 96(x12)
    bn.ld w12, 128(x12)
    bn.ld w13, 160(x12)
    bn.ld w14, 192(x12)
    bn.ld w15, 224(x12)
    bn.ld w16, 256(x12)
    bn.ld w17, 288(x12)
    bn.ld w18, 320(x12)
    bn.ld w19, 352(x12)
    bn.ld w20, 384(x12)
    bn.rshi w22, w19, w18 >> 184
    bn.rshi w23, w20, w19 >> 184
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w18, w17 >> 80
    bn.rshi w21, w19, w18 >> 80
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 232
    bn.rshi w19, w17, w16 >> 232
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w15, w14 >> 128
    bn.rshi w17, w16, w15 >> 128
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w14, w14, w13 >> 24
    bn.ld w26, 192(x12)
    bn.rshi w15, w26, w31 >> 128
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w12, w12, w11 >> 176
    bn.ld w26, 128(x12)
    bn.rshi w13, w13, w26 >> 176
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w11, w10 >> 72
    bn.ld w26, 128(x12)
    bn.rshi w11, w26, w11 >> 72
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 224
    bn.ld w26, 64(x12)
    bn.rshi w9, w26, w9 >> 224
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    addi x12, x12, 384
    li   x2, 0
    ret

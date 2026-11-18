/* aes128_360: computed AES-CTR, 12 dual blocks -> eight 45-byte entries.
 * One-shot fork: blkbuf is a .data label exported by the kernel, not a fixed address.
 * in: x2=RK base, x16=phase 0..3; mod0=0x11b, mod1=0.
 * wdr: w27=affine, w28=msb_mask, w29=LE counters C/C+1, w31=0.
 * out: w8-w23=entries (odd WDR zero above byte 12); x16=next phase;
 *      w29 advances 22 blocks on phases 0..2, 24 on phase 3.
 * clob: x24-x27, w8-w23, w26, w30, FG0; w19 loads shiftrow_mask.
 * keep: x2/x6/x30, w0-w7, w24/w25, ACC/ACCH.
 * scratch: blkbuf (kernel-exported .data label), 384 B written before read; needs shiftrow_mask.
 * stack: 0.
 */
.section .text
.balign 4
.global aes128_360
aes128_360:
    li x24, 16                       /* WDR index of the finished dual */
    la x27, shiftrow_mask
    li x26, 19
    bn.lid x26, 0(x27)                /* w19 = shiftrow_mask, constant */
    la x25, blkbuf

    bn.addi w8, w31, 0xff             # fixed ShiftRows rotation masks
    bn.or w8, w8, w8 << 128
    bn.or w8, w31, w8 << 8
    bn.addi w9, w31, 0xff
    bn.or w9, w9, w9 << 32
    bn.or w9, w9, w9 << 128
    bn.or w9, w31, w9 << 16
    bn.addi w10, w31, 0xff
    bn.or w10, w10, w10 << 128
    bn.or w10, w31, w10 << 120

    loopi 12, 167
        addi x26, x2, 0                    # reset rk cursor to &rk[0]
        li x27, 30                        # round 0
        bn.lid x27, 0(x26++)               # rk[0]
        bn.and w15, w29, w19 >> 8         # LE->BE byteswap; byte 0/16 (LE LSB)
        bn.or w16, w31, w15 << 120        # byte 15/31 (BE LSB)
        bn.and w15, w29, w19              # byte 1/17
        bn.or w16, w16, w15 << 104        # byte 14/30
        bn.and w15, w29, w19 << 8         # byte 2/18
        bn.or w16, w16, w15 << 88         # byte 13/29
        bn.and w15, w29, w19 << 16        # byte 3/19 (LE MSB)
        bn.or w16, w16, w15 << 72         # byte 12/28 (BE MSB)
        bn.xor w16, w30, w16              # AddRoundKey 0
        loopi 9, 86
            bn.gfmul.8.vv w12, w16, w16   # rounds 1..9 Substitute: a^254
            bn.gfmul.8.vv w13, w12, w16
            bn.gfmul.8.vv w14, w13, w13
            bn.gfmul.8.vv w14, w14, w14
            bn.gfmul.8.vv w13, w13, w14
            bn.gfmul.8.vv w13, w13, w13
            bn.gfmul.8.vv w13, w13, w13
            bn.gfmul.8.vv w13, w13, w13
            bn.gfmul.8.vv w13, w13, w13
            bn.gfmul.8.vv w13, w13, w14
            bn.gfmul.8.vv w14, w13, w12
            bn.and w13, w14, w28
            bn.xor w12, w14, w13
            bn.rshi w13, w31, w13 >> 7
            bn.rshi w12, w12, w31 >> 255
            bn.xor w13, w12, w13
            bn.and w12, w13, w28
            bn.xor w15, w13, w12
            bn.rshi w12, w31, w12 >> 7
            bn.rshi w15, w15, w31 >> 255
            bn.xor w12, w15, w12
            bn.xor w13, w12, w13
            bn.and w15, w12, w28
            bn.xor w17, w12, w15
            bn.rshi w15, w31, w15 >> 7
            bn.rshi w17, w17, w31 >> 255
            bn.xor w12, w15, w17
            bn.xor w13, w12, w13
            bn.and w15, w12, w28
            bn.xor w17, w12, w15
            bn.rshi w15, w31, w15 >> 7
            bn.rshi w17, w17, w31 >> 255
            bn.xor w12, w15, w17
            bn.xor w13, w12, w13
            bn.xor w14, w14, w13
            bn.xor w14, w14, w27
            bn.and w12, w14, w19          # ShiftRow row 1, w19 = row-1 mask
            bn.xor w14, w12, w14
            bn.and w13, w12, w8
            bn.xor w12, w12, w13
            bn.rshi w12, w31, w12 >> 32
            bn.or w13, w31, w13 << 96
            bn.or w12, w13, w12
            bn.or w14, w12, w14
            bn.or w18, w31, w19 << 8      # ShiftRow row 2, mask = w19 << 8
            bn.and w12, w18, w14
            bn.xor w14, w12, w14
            bn.and w13, w12, w9
            bn.xor w12, w13, w12
            bn.rshi w12, w31, w12 >> 64
            bn.or w13, w31, w13 << 64
            bn.or w12, w13, w12
            bn.or w14, w12, w14
            bn.or w18, w31, w19 << 16     # ShiftRow row 3, mask = w19 << 16
            bn.and w12, w14, w18
            bn.xor w14, w12, w14
            bn.and w13, w12, w10
            bn.xor w12, w13, w12
            bn.rshi w12, w12, w31 >> 224
            bn.rshi w13, w31, w13 >> 96
            bn.or w12, w13, w12
            bn.or w17, w12, w14
            bn.addi w14, w31, 0x02        # MixCol; col_mask = w19 >> 8
            bn.gfmul.8 w12, w17, w14
            bn.xor w16, w12, w17
            bn.and w13, w16, w19 >> 8
            bn.xor w16, w16, w13
            bn.rshi w16, w31, w16 >> 8
            bn.or w16, w16, w13 << 24
            bn.xor w12, w12, w16
            bn.and w13, w17, w19 >> 8
            bn.xor w16, w17, w13
            bn.rshi w16, w31, w16 >> 8
            bn.or w16, w16, w13 << 24
            bn.and w13, w16, w19 >> 8
            bn.xor w16, w16, w13
            bn.rshi w16, w31, w16 >> 8
            bn.or w16, w16, w13 << 24
            bn.xor w12, w12, w16
            bn.and w13, w16, w19 >> 8
            bn.xor w16, w16, w13
            bn.rshi w16, w31, w16 >> 8
            bn.or w16, w16, w13 << 24
            bn.xor w12, w12, w16
            bn.lid x27, 0(x26++)           # rk[i+1]
            bn.xor w16, w12, w30          # AddRoundKey
        bn.gfmul.8.vv w12, w16, w16       # round 10 Substitute: a^254
        bn.gfmul.8.vv w13, w12, w16
        bn.gfmul.8.vv w14, w13, w13
        bn.gfmul.8.vv w14, w14, w14
        bn.gfmul.8.vv w13, w13, w14
        bn.gfmul.8.vv w13, w13, w13
        bn.gfmul.8.vv w13, w13, w13
        bn.gfmul.8.vv w13, w13, w13
        bn.gfmul.8.vv w13, w13, w13
        bn.gfmul.8.vv w13, w13, w14
        bn.gfmul.8.vv w14, w13, w12
        bn.and w13, w14, w28
        bn.xor w12, w14, w13
        bn.rshi w13, w31, w13 >> 7
        bn.rshi w12, w12, w31 >> 255
        bn.xor w13, w12, w13
        bn.and w12, w13, w28
        bn.xor w15, w13, w12
        bn.rshi w12, w31, w12 >> 7
        bn.rshi w15, w15, w31 >> 255
        bn.xor w12, w15, w12
        bn.xor w13, w12, w13
        bn.and w15, w12, w28
        bn.xor w17, w12, w15
        bn.rshi w15, w31, w15 >> 7
        bn.rshi w17, w17, w31 >> 255
        bn.xor w12, w15, w17
        bn.xor w13, w12, w13
        bn.and w15, w12, w28
        bn.xor w17, w12, w15
        bn.rshi w15, w31, w15 >> 7
        bn.rshi w17, w17, w31 >> 255
        bn.xor w12, w15, w17
        bn.xor w13, w12, w13
        bn.xor w14, w14, w13
        bn.xor w14, w14, w27
        bn.and w12, w14, w19              # round 10 ShiftRow row 1
        bn.xor w14, w12, w14
        bn.and w13, w12, w8
        bn.xor w12, w12, w13
        bn.rshi w12, w31, w12 >> 32
        bn.or w13, w31, w13 << 96
        bn.or w12, w13, w12
        bn.or w14, w12, w14
        bn.or w18, w31, w19 << 8          # round 10 ShiftRow row 2
        bn.and w12, w18, w14
        bn.xor w14, w12, w14
        bn.and w13, w12, w9
        bn.xor w12, w13, w12
        bn.rshi w12, w31, w12 >> 64
        bn.or w13, w31, w13 << 64
        bn.or w12, w13, w12
        bn.or w14, w12, w14
        bn.or w18, w31, w19 << 16         # round 10 ShiftRow row 3
        bn.and w12, w14, w18
        bn.xor w14, w12, w14
        bn.and w13, w12, w10
        bn.xor w12, w13, w12
        bn.rshi w12, w12, w31 >> 224
        bn.rshi w13, w31, w13 >> 96
        bn.or w12, w13, w12
        bn.or w17, w12, w14
        bn.lid x27, 0(x26)                 # AddRoundKey 10; cursor at &rk[10]
        bn.xor w16, w17, w30
        bn.addi w12, w31, 0x02            # counter += 2 (LE)
        bn.or w12, w12, w12 << 128
        bn.add w29, w29, w12
    bn.sid x24, 0(x25++)              # spill dual to blkbuf

    /* phases 0-2 encrypt one dual more than they consume; hand it back */
    li x26, 3
    beq x16, x26, a360_keep
    bn.addi w12, w31, 0x02
    bn.or w12, w12, w12 << 128
    bn.sub w29, w29, w12
a360_keep:
    la x25, blkbuf

    /* phase dispatch: x16 = 0..3 in, next phase out */
    beq x16, x0, a360_p0
    addi x16, x16, -1
    beq x16, x0, a360_p1
    addi x16, x16, -1
    beq x16, x0, a360_p2
    li x16, 0                       /* window at buffer byte 24 */
    bn.ld w8, 0(x25)
    bn.ld w9, 32(x25)
    bn.ld w10, 64(x25)
    bn.ld w11, 96(x25)
    bn.ld w12, 128(x25)
    bn.ld w13, 160(x25)
    bn.ld w14, 192(x25)
    bn.ld w15, 224(x25)
    bn.ld w16, 256(x25)
    bn.ld w17, 288(x25)
    bn.ld w18, 320(x25)
    bn.ld w19, 352(x25)
    bn.rshi w22, w19, w18 >> 152
    bn.rshi w23, w31, w19 >> 152
    bn.rshi w20, w18, w17 >> 48
    bn.rshi w21, w19, w18 >> 48
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 200
    bn.rshi w19, w17, w16 >> 200
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w15, w14 >> 96
    bn.rshi w17, w16, w15 >> 96
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w15, w14, w13 >> 248
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 248
    bn.rshi w12, w12, w11 >> 144
    bn.ld w26, 128(x25)
    bn.rshi w13, w13, w26 >> 144
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w11, w10 >> 40
    bn.ld w26, 128(x25)
    bn.rshi w11, w26, w11 >> 40
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 192
    bn.ld w26, 64(x25)
    bn.rshi w9, w26, w9 >> 192
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    ret
a360_p2:
    li x16, 3                       /* window at buffer byte 16 */
    bn.ld w8, 0(x25)
    bn.ld w9, 32(x25)
    bn.ld w10, 64(x25)
    bn.ld w11, 96(x25)
    bn.ld w12, 128(x25)
    bn.ld w13, 160(x25)
    bn.ld w14, 192(x25)
    bn.ld w15, 224(x25)
    bn.ld w16, 256(x25)
    bn.ld w17, 288(x25)
    bn.ld w18, 320(x25)
    bn.ld w19, 352(x25)
    bn.rshi w22, w19, w18 >> 88
    bn.rshi w23, w19, w19 >> 88
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 240
    bn.rshi w21, w18, w17 >> 240
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 136
    bn.rshi w19, w17, w16 >> 136
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w15, w14 >> 32
    bn.rshi w17, w16, w15 >> 32
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w15, w14, w13 >> 184
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w14, w13, w12 >> 184
    bn.rshi w12, w12, w11 >> 80
    bn.ld w26, 128(x25)
    bn.rshi w13, w13, w26 >> 80
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w10, w9 >> 232
    bn.ld w26, 64(x25)
    bn.rshi w11, w11, w26 >> 232
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 128
    bn.ld w26, 64(x25)
    bn.rshi w9, w26, w9 >> 128
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    ret
a360_p1:
    li x16, 2                       /* window at buffer byte 8 */
    bn.ld w8, 0(x25)
    bn.ld w9, 32(x25)
    bn.ld w10, 64(x25)
    bn.ld w11, 96(x25)
    bn.ld w12, 128(x25)
    bn.ld w13, 160(x25)
    bn.ld w14, 192(x25)
    bn.ld w15, 224(x25)
    bn.ld w16, 256(x25)
    bn.ld w17, 288(x25)
    bn.ld w18, 320(x25)
    bn.ld w19, 352(x25)
    bn.rshi w22, w19, w18 >> 24
    bn.rshi w23, w19, w31 >> 128
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 176
    bn.rshi w21, w18, w17 >> 176
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 72
    bn.rshi w19, w17, w16 >> 72
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w13 >> 224
    bn.rshi w17, w15, w14 >> 224
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w14, w13, w12 >> 120
    bn.rshi w15, w14, w13 >> 120
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w12, w12, w11 >> 16
    bn.ld w26, 128(x25)
    bn.rshi w13, w13, w26 >> 16
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w10, w10, w9 >> 168
    bn.ld w26, 64(x25)
    bn.rshi w11, w11, w26 >> 168
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w9, w8 >> 64
    bn.ld w26, 64(x25)
    bn.rshi w9, w26, w9 >> 64
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    ret
a360_p0:
    li x16, 1                       /* window at buffer byte 0 */
    bn.ld w8, 0(x25)
    bn.ld w9, 32(x25)
    bn.ld w10, 64(x25)
    bn.ld w11, 96(x25)
    bn.ld w12, 128(x25)
    bn.ld w13, 160(x25)
    bn.ld w14, 192(x25)
    bn.ld w15, 224(x25)
    bn.ld w16, 256(x25)
    bn.ld w17, 288(x25)
    bn.ld w18, 320(x25)
    bn.ld w19, 352(x25)
    bn.rshi w22, w18, w17 >> 216
    bn.rshi w23, w19, w18 >> 216
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 112
    bn.rshi w21, w18, w17 >> 112
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w16, w15 >> 8
    bn.rshi w19, w17, w16 >> 8
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w13 >> 160
    bn.rshi w17, w15, w14 >> 160
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    bn.rshi w14, w13, w12 >> 56
    bn.rshi w15, w14, w13 >> 56
    bn.rshi w15, w15, w31 >> 104
    bn.rshi w15, w31, w15 >> 152
    bn.rshi w13, w12, w11 >> 208
    bn.rshi w13, w13, w31 >> 104
    bn.rshi w13, w31, w13 >> 152
    bn.rshi w12, w11, w10 >> 208
    bn.rshi w10, w10, w9 >> 104
    bn.ld w26, 64(x25)
    bn.rshi w11, w11, w26 >> 104
    bn.rshi w11, w11, w31 >> 104
    bn.rshi w11, w31, w11 >> 152
    bn.rshi w8, w8, w8 >> 0
    bn.ld w26, 64(x25)
    bn.rshi w9, w26, w9 >> 0
    bn.rshi w9, w9, w31 >> 104
    bn.rshi w9, w31, w9 >> 152
    ret

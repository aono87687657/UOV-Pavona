/* back_substitution (Ip3 45-row, GF(256) upper-tri).
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW: unrolled inner loops + gf256_macc{,_dualvec}_sw helpers
 *   bngfonly    -DGF_INSTRUCTIONS    HW: bn.gfmul.8 with sliding mod1 cursor
 *   bngfaes     -DAES_|GF_           same as bngfonly (no AES used)
 *
 * Public symbol: back_substitution.
 */

.section .text
.balign 4
.global back_substitution

#if defined(GF_INSTRUCTIONS)

/* =============== bngfaes + bngfonly (HW bn.gfmul.8) =============== */
back_substitution:

    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    add x12, x0, x10
    addi x12, x12, 2047
    addi x12, x12, 769
    li x28, 12
    li x29, 1
    li x30, 2
    li x31, 3
    bn.addi w30, w31, 0xff
    bn.rshi w30, w30, w31 >> 160
    bn.lid x30, 0(x11)
    bn.lid x31, 32(x11)

    /* Loop 1: rows 44..33 (bytes 12..1 of w3 region) */
    loopi 12, 13
        bn.lid x0, 0(x12)
        bn.lid x29, 32(x12)
        bn.and w4, w1, w30
        bn.xor w1, w1, w4
        bn.and w4, w3, w30           # extract byte x28 of w3 into w4[x28]
        csrrw x0, mod1, x28          # mod1 = x28 → gfmul reads w4[x28] directly
        bn.gfmul.8 w0, w0, w4        # vxs: w0 *= w4[mod1=x28]
        bn.gfmul.8 w1, w1, w4
        bn.xor w2, w2, w0
        bn.xor w3, w3, w1
        addi x12, x12, -64
        bn.rshi w30, w31, w30 >> 8
        addi x28, x28, -1

    /* Mid-section: row 32 (byte 0 of w3 region) — mod1 must be reset to 0 */
    csrrw x0, mod1, x0
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w30
    bn.xor w1, w1, w4
    bn.and w4, w3, w30
    bn.gfmul.8 w0, w0, w4
    bn.xor w2, w2, w0
    addi x12, x12, -64
    bn.rshi w30, w30, w31 >> 8

    /* Loop 2: rows 31..1 (bytes 31..1 of w2 region) */
    li x28, 31
    loopi 31, 10
        bn.lid x0, 0(x12)
        bn.and w4, w0, w30
        bn.xor w0, w0, w4
        bn.and w4, w2, w30           # extract byte x28 of w2 into w4[x28]
        csrrw x0, mod1, x28          # mod1 = x28
        bn.gfmul.8 w0, w0, w4        # vxs: w0 *= w4[mod1=x28]
        bn.xor w2, w2, w0
        addi x12, x12, -64
        bn.rshi w30, w31, w30 >> 8
        addi x28, x28, -1


    bn.sid x30, 0(x11)
    bn.sid x31, 32(x11)

    csrrw x0, mod1, x0               # reset mod1 = 0 so downstream callers see clean state
ret

#else

/* =============== sw (SW gf256 multiply, unrolled inner loops) =============== */
back_substitution:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31

    /* Load helper constants. */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)              /* w16 = msb_mask */
    bn.addi w17, w31, 0x1b        /* w17 = 0x1b */

    /* Build mask w24 with byte 12 = 0xff. */
    bn.addi w24, w31, 0xff
    bn.rshi w24, w24, w31 >> 160

    /* Compute x12 = x10 + 2816 (last row of matrix). */
    add x12, x0, x10
    addi x12, x12, 2047
    addi x12, x12, 769

    /* Load b into w2, w3 (45 bytes; in 2 WDRs padded). */
    li x30, 2
    li x31, 3
    bn.lid x30, 0(x11)            /* w2 = b[0..31] */
    bn.lid x31, 32(x11)           /* w3 = b[32..63] */

    li x29, 1                      /* GPR holding WDR idx 1 for bn.lid w1 */

    /* Loop 1 iter 0: x28=12, shift=96 (= 8 * 12) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 96
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 1: x28=11, shift=88 (= 8 * 11) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 88
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 2: x28=10, shift=80 (= 8 * 10) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 80
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 3: x28=9, shift=72 (= 8 * 9) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 72
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 4: x28=8, shift=64 (= 8 * 8) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 64
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 5: x28=7, shift=56 (= 8 * 7) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 56
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 6: x28=6, shift=48 (= 8 * 6) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 48
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 7: x28=5, shift=40 (= 8 * 5) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 40
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 8: x28=4, shift=32 (= 8 * 4) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 32
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 9: x28=3, shift=24 (= 8 * 3) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 24
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 10: x28=2, shift=16 (= 8 * 2) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 16
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 1 iter 11: x28=1, shift=8 (= 8 * 1) */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.rshi w19, w31, w3 >> 8
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.xor w2, w2, w20
    bn.xor w3, w3, w30
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Mid section: row 32 (byte 0 of w3). w24 byte 0 = 0xff. */
    bn.lid x0, 0(x12)
    bn.lid x29, 32(x12)
    bn.and w4, w1, w24
    bn.xor w1, w1, w4
    bn.mov w19, w3
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    /* Promote w24 byte 0 -> byte 31 for loop 2. */
    bn.rshi w24, w24, w31 >> 8

    /* Loop 2 iter 0: x28=31, shift=248 (= 8 * 31) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 248
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 1: x28=30, shift=240 (= 8 * 30) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 240
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 2: x28=29, shift=232 (= 8 * 29) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 232
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 3: x28=28, shift=224 (= 8 * 28) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 224
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 4: x28=27, shift=216 (= 8 * 27) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 216
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 5: x28=26, shift=208 (= 8 * 26) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 208
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 6: x28=25, shift=200 (= 8 * 25) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 200
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 7: x28=24, shift=192 (= 8 * 24) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 192
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 8: x28=23, shift=184 (= 8 * 23) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 184
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 9: x28=22, shift=176 (= 8 * 22) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 176
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 10: x28=21, shift=168 (= 8 * 21) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 168
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 11: x28=20, shift=160 (= 8 * 20) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 160
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 12: x28=19, shift=152 (= 8 * 19) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 152
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 13: x28=18, shift=144 (= 8 * 18) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 144
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 14: x28=17, shift=136 (= 8 * 17) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 136
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 15: x28=16, shift=128 (= 8 * 16) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 128
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 16: x28=15, shift=120 (= 8 * 15) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 120
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 17: x28=14, shift=112 (= 8 * 14) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 112
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 18: x28=13, shift=104 (= 8 * 13) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 104
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 19: x28=12, shift=96 (= 8 * 12) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 96
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 20: x28=11, shift=88 (= 8 * 11) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 88
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 21: x28=10, shift=80 (= 8 * 10) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 80
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 22: x28=9, shift=72 (= 8 * 9) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 72
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 23: x28=8, shift=64 (= 8 * 8) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 64
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 24: x28=7, shift=56 (= 8 * 7) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 56
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 25: x28=6, shift=48 (= 8 * 6) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 48
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 26: x28=5, shift=40 (= 8 * 5) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 40
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 27: x28=4, shift=32 (= 8 * 4) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 32
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 28: x28=3, shift=24 (= 8 * 3) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 24
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 29: x28=2, shift=16 (= 8 * 2) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 16
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Loop 2 iter 30: x28=1, shift=8 (= 8 * 1) */
    bn.lid x0, 0(x12)
    bn.and w4, w0, w24
    bn.xor w0, w0, w4
    bn.rshi w19, w31, w2 >> 8
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.xor w2, w2, w20
    addi x12, x12, -64
    bn.rshi w24, w31, w24 >> 8

    /* Store w2, w3 back to b. */
    li x30, 2
    li x31, 3
    bn.sid x30, 0(x11)
    bn.sid x31, 32(x11)

    ret


#endif

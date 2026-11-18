/* ov-Is-verify_backend.s - backend arms for the Is verify stream_uniform outer.
 * cpp picks the arm (same convention as ov-Is-pkc_publicmap.s):
 *   bngfaes  -DAES_INSTRUCTIONS -DGF_INSTRUCTIONS  inline bn.aes128 (kf keys
 *            w8..w17), near-verbatim streamed-Is splice (Is was ALREADY
 *            uniform - Part-S/H never applied; no helper calls).
 *   bngfonly -DGF_INSTRUCTIONS   compute-AES monolith splice (rk in w5..w14,
 *            jal aes128 per dual-block; aes128 clob x5/x6, KeySchedule x23;
 *            x1 saved in x28).
 *   sw       (none)              T-table AES (aes128_col_is) + gf16_mul.
 * The hw arms share ONE backend_verify_p3_rows (bottom of file): the Is P3
 * fold is pure bn.gfmul.4, no AES - identical for both tiers by construction.
 * backend_verify_p1p2: in x10=sig x12=seed; full VxV+VxO from AES-CTR;
 *   spills acc -> ctx 0x20. backend_verify_p3_rows: in x9=row_start
 *   x8=row_count>=1; folds rows from window @0x100; reload/spill acc.
 * clob: everything.
 */
#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)
.section .text
.balign 4

.global backend_verify_p1p2
backend_verify_p1p2:
    bn.xor w31, w31, w31
    bn.wsrw acc, w31
    li   x31, 0x13
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0       /* explicit scalar cursor = 0 */

    li   x5, 28
    bn.lid x5, 0(x12)
    bn.aes128.kf w8,  w28, 1
    bn.aes128.kf w9,  w8,  2
    bn.aes128.kf w10, w9,  3
    bn.aes128.kf w11, w10, 4
    bn.aes128.kf w12, w11, 5
    bn.aes128.kf w13, w12, 6
    bn.aes128.kf w14, w13, 7
    bn.aes128.kf w15, w14, 8
    bn.aes128.kf w16, w15, 9
    bn.aes128.kf w17, w16, 10

    bn.addi w29, w31, 1
    bn.rshi w29, w29, w31 >> 32
    bn.addi w26, w31, 2
    bn.or  w26, w26, w26 << 128
    bn.rshi w26, w26, w31 >> 160

    addi x31, x0, 1
    bn.lid x31++, 0(x10)
    bn.lid x31++, 32(x10)
    bn.lid x31++, 64(x10)

    bn.mov w4, w1
    bn.mov w5, w2
    bn.rshi w5, w5, w31 >> 128
    bn.rshi w5, w31, w5  >> 128
    addi x31, x0, 96
    addi x30, x0, 30
    loopi 96, 21
        bn.gfmul.4 w6, w4, w4
        bn.gfmul.4 w7, w5, w4
        loop x31, 15
            bn.aes128.encz.swap w30, w29, w28
            bn.add w29, w29, w26
            bn.aes128.encm w30, w30, w8
            bn.aes128.encm w30, w30, w9
            bn.aes128.encm w30, w30, w10
            bn.aes128.encm w30, w30, w11
            bn.aes128.encm w30, w30, w12
            bn.aes128.encm w30, w30, w13
            bn.aes128.encm w30, w30, w14
            bn.aes128.encm w30, w30, w15
            bn.aes128.encm w30, w30, w16
            bn.aes128.encf w30, w30, w17
            bn.gfmul.4.acc w0, w30, w6
            bn.rshi w6, w7, w6 >> 4
            bn.rshi w7 , w31, w7 >> 4
        bn.rshi w4, w5, w4 >> 4
        bn.rshi w5, w31, w5 >> 4
        addi x31, x31, -1

    bn.mov w4, w1
    bn.mov w5, w2
    bn.rshi w5, w5, w31 >> 128
    bn.rshi w5, w31, w5  >> 128
    bn.rshi w6, w3, w2 >> 128
    loopi 96, 18
        bn.gfmul.4 w7, w6, w4
        loopi 64, 14
            bn.aes128.encz.swap w30, w29, w28
            bn.add w29, w29, w26
            bn.aes128.encm w30, w30, w8
            bn.aes128.encm w30, w30, w9
            bn.aes128.encm w30, w30, w10
            bn.aes128.encm w30, w30, w11
            bn.aes128.encm w30, w30, w12
            bn.aes128.encm w30, w30, w13
            bn.aes128.encm w30, w30, w14
            bn.aes128.encm w30, w30, w15
            bn.aes128.encm w30, w30, w16
            bn.aes128.encf w30, w30, w17
            bn.gfmul.4.acc w0, w30, w7
            bn.rshi w7, w31, w7 >> 4
        bn.rshi w4, w5, w4 >> 4
        bn.rshi w5, w31, w5 >> 4
    li   x3, 0x20
    bn.sd w0, 0(x3)          /* acc -> ctx */
    ret

#elif defined(GF_INSTRUCTIONS)
/* AES constants the monolith splice la-resolves; shiftrow_mask is also
 * self-loaded by the aes128 helper (hence .global). Canonical values =
 * the ov-Is-pkc test wrappers. */
.section .data
.balign 32
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b
    .zero 20
.balign 32
.global shiftrow_mask
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
.balign 32
.global msb_mask
msb_mask:
    .word 0x80808080,0x80808080,0x80808080,0x80808080
    .word 0x80808080,0x80808080,0x80808080,0x80808080
.balign 32
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363

.section .text
.balign 4

.global backend_verify_p1p2
backend_verify_p1p2:
    add  x28, x0, x1          /* aes128 clob x5/x6, KeySchedule x23 only */
    csrrw x0, mod1, x0
    li   x10, 0x80            /* sig */
    li   x12, 0xE0            /* seed = AES key */
    bn.xor w31, w31, w31
    bn.wsrw acc, w31
    bn.xor w0, w0, w0

    #increment const
    bn.addi w15, w31, 0x2
    bn.or w15, w15, w15 << 128
    bn.rshi w15, w15, w31 >> 160
    #byte swap mask
    bn.addi w30, w31, 0xff
    bn.or w30, w30, w30 << 128
    bn.rshi w30, w30, w31 >> 160


    /*Load AES128 Key from cpk into w28*/
    li x5, 28
    bn.lid x5, 0(x12)
    bn.rshi w28, w28, w31 >> 128
    bn.rshi w28, w31, w28 >> 128

    la x5, rcon
    addi x6, x0, 26
    bn.lid x6, 0(x5)

    la x5, affine_value
    li x6, 23
    bn.lid x6, 0(x5)

    la x5, msb_mask
    li x6, 24
    bn.lid x6, 0(x5)

    /*Initialize IV in w29 for AES128 ctr*/
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 224
    li x5, 5
    li x6, 28
    loopi 10, 2
        jal x1, KeySchedule
        bn.movr x5++, x6
    bn.or w5, w5, w5 << 128
    bn.or w6, w6, w6 << 128
    bn.or w7, w7, w7 << 128
    bn.or w8, w8, w8 << 128
    bn.or w9, w9, w9 << 128
    bn.or w10, w10, w10 << 128
    bn.or w11, w11, w11 << 128
    bn.or w12, w12, w12 << 128
    bn.or w13, w13, w13 << 128
    bn.or w14, w14, w14 << 128

    li x5, 28
    bn.lid x5, 0(x12)
    bn.rshi w28, w28, w31 >> 128
    bn.rshi w28, w31, w28 >> 128
    bn.or w28, w28, w28 << 128

    li x30, 0x13
    csrrw x0,mod0,x30

    /*Preparing Process VxV*/
    /*Load vinegar x0-x95 into w1,w2*/
    addi x31, x0, 1
    bn.lid x31++, 0(x10)  /*w1:x63-x0*/
    bn.lid x31++, 32(x10)
    bn.rshi w2, w2, w31 >> 128
    bn.rshi w2, w31, w2 >> 128 /*w2:x95-x64*/

    li x31, 96

    li x30, 0x13
    loopi 96, 13
        bn.gfmul.4 w3, w1, w1
        bn.gfmul.4 w4, w2, w1
        loop x31, 7
            jal x1, aes128
            bn.add w29, w29, w15
            bn.wsrw acc, w0
            csrrw x0,mod0,x30
            bn.gfmul.4.acc w0, w27, w3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.rshi w1, w2, w1 >> 4
        bn.rshi w2, w31, w2 >> 4
        addi x31, x31, -1

    addi x31, x0, 1
    bn.lid x31++, 0(x10)  /*w1:x63-x0*/
    bn.lid x31++, 32(x10)
    bn.lid x31++, 64(x10)

    bn.rshi w3, w3, w2 >> 128 /*w3:x159-x96*/

    bn.rshi w2, w2, w31 >> 128
    bn.rshi w2, w31, w2 >> 128 /*w2:x95-x64*/


    li x30, 0x13
    loopi 96, 10
        bn.gfmul.4 w4, w3, w1
        loopi 64, 6
            jal x1, aes128
            bn.add w29, w29, w15
            bn.wsrw acc, w0
            csrrw x0,mod0,x30
            bn.gfmul.4.acc w0, w27, w4
            bn.rshi w4, w31, w4 >> 4
        bn.rshi w1, w2, w1 >> 4
        bn.rshi w2, w31, w2 >> 4
    li   x3, 0x20
    bn.sd w0, 0(x3)          /* acc -> ctx */
    add  x1, x0, x28
    ret

#else

/* Software GF arm with software or hardware AES columns.
 * acc in w25 (XOR-accumulate). ABI: backend_verify_* headers.
 * aes128_col_is clob x5-x16/x19-x22/x29-x31 -> x1 saved to DMEM; gf16_mul
 * clob w0,w1,w4,w28-w31 (preserves w2), no GPRs, needs w3 = 0x88.. msb mask.
 */
.section .data
.balign 32
sfk_stack:   .space 256           /* 32 frame + 192 rk + 32 col-buf */
sfk_stack_end:
.balign 32
sfk_msb:
    .word 0x88888888,0x88888888,0x88888888,0x88888888
    .word 0x88888888,0x88888888,0x88888888,0x88888888
sfk_x1:      .word 0

.section .text
.balign 4

.global backend_verify_p1p2
backend_verify_p1p2:
    la   x5, sfk_x1
    sw   x1, 0(x5)            /* helpers clobber x1 */
    la   x2, sfk_stack_end    /* private stack (monolith convention) */
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x10, 0x80            /* sig */
    li   x11, 0x20            /* acc out (frame slot; spilled below anyway) */
    li   x12, 0xE0            /* seed = AES key (cpk[0..15] in the monolith) */
    addi x2, x2, -32
    add  x3, x0, x2
    sw   x10,  0(x3)
    sw   x11,  4(x3)
    sw   x12,  8(x3)
    sw   x13, 12(x3)
    sw   x14, 16(x3)

    bn.xor w31, w31, w31           # zero const
    bn.xor w25, w25, w25            # accumulator = 0

    /* Phase 1: packed AES key schedule, 176 B. */
    addi x2, x2, -192              # 176 B rk + 16 B align pad
    add  x10, x0, x12              # x10 = pk_seed pointer (= cpk[0..15])
    add  x11, x0, x2               # x11 = rk buffer base
    jal  x1, AES_128_keyschedule
    add  x18, x0, x2               #x18 = rk base survivor, set AFTER KS (KS clobbers x12-x18)

    /* Phase 2: CTR + 32 B scratch buf for aes128_col_is (2 AES blocks = 1 col).
     * Frame slot 20(x3) holds scratch base; w13 returns the two blocks.
     * Scratch contents after the call are unspecified.
     */
    addi x13, x0, 0                # AES-CTR LE counter starts at 0
    addi x2, x2, -32
    add  x4, x0, x2
    sw   x4, 20(x3)                # buf base for helper to lw

    /* Phase 3: sig load + v / o window extract */
    li   x31, 5
    lw   x5, 0(x3)                 # x5 = sig base
    bn.lid x31++, 0(x5)            # w5 = bytes [0..31]   = v[0..63]
    bn.lid x31++, 32(x5)           # w6 = v[64..95] || o[0..31]
    bn.lid x31++, 64(x5)           # w7 = o[32..63] || salt
    bn.mov  w23, w5                #v-window lo (full 64 nibbles)
    bn.rshi w26, w7, w6 >> 128     #o-window = {w7[127:0], w6[255:128]} = o[0..63]
    bn.rshi w24, w6, w31 >> 128    #step 1: w6 lo128 to high half of tmp
    bn.rshi w24, w31, w24 >> 128   #step 2: tmp >> 128 to w24 = v[64..95] lo, 0 hi

    /* Phase 4: VxV. 96 rows, row i has 96-i entries; x17 survives both helpers. */
    li x17, 96
    loopi 96, 18
        bn.mov w1, w23
        bn.mov w2, w23                   #scalar = v[i] (low nibble of w2)
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef lo = v[i]·v_window[0..63]
        bn.mov w1, w24
        jal x1, gf16_mul                  #w2 still = v[i] (gf16_mul preserves w2)
        bn.mov w12, w0                   #coef hi = v[i]·v_window[64..95]
        loop x17, 7
            jal x1, aes128_col_is        #w13 = 1 col (32 B), x13 += 2
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w12, w11 >> 4   #advance coef by 1 nibble
            bn.rshi w12, w31, w12 >> 4
        bn.rshi w23, w24, w23 >> 4       #slide v-window 1 nibble v[i] to v[i+1]
        bn.rshi w24, w31, w24 >> 4
        addi x17, x17, -1                #next row has 1 fewer col

    /* Phase 5: VxO setup. reload sig + rebuild windows. */
    li   x31, 5
    lw   x6, 0(x3)
    bn.lid x31++, 0(x6)
    bn.lid x31++, 32(x6)
    bn.lid x31++, 64(x6)
    bn.mov  w23, w5
    bn.rshi w26, w7, w6 >> 128
    bn.rshi w24, w6, w31 >> 128
    bn.rshi w24, w31, w24 >> 128

    /* Phase 5 cont'd: VxO. 96 rows x 64 cols, const inner. */
    loopi 96, 13
        bn.mov w1, w26
        bn.mov w2, w23                   #scalar = v[i]
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef = v[i]·o[0..63]
        loopi 64, 6
            jal x1, aes128_col_is
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w31, w11 >> 4
        bn.rshi w23, w24, w23 >> 4
        bn.rshi w24, w31, w24 >> 4
    li   x5, 0x20
    li   x6, 25
    bn.sid x6, 0(x5)          /* acc (w25) -> ctx */
    la   x5, sfk_x1
    lw   x1, 0(x5)
    ret

.global backend_verify_p3_rows
backend_verify_p3_rows:
    la   x5, sfk_x1
    sw   x1, 0(x5)
    bn.xor w31, w31, w31
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x5, 0x20
    li   x6, 25
    bn.lid x6, 0(x5)          /* w25 = acc <- ctx */
    li   x5, 0x40
    li   x6, 26
    bn.lid x6, 0(x5)          /* w26 = oil (host-aligned to row_start) */
    li   x23, 1               /* bn.lid dest w1: entries are ALIGNED here */
    li   x4, 0x100            /* P3 window */
    li   x7, 64
    sub  x7, x7, x9           /* first row size */
    loop x8, 13
    bn.mov w1, w26
    bn.mov w2, w26            # scalar = O[row] (low nibble)
    jal x1, gf16_mul
    bn.mov w11, w0            # coef = O[row]*o_window
    loop x7, 6
        bn.lid x23, 0(x4)     # w1 = entry (aligned)
        bn.mov w2, w11
        jal x1, gf16_mul
        bn.xor w25, w25, w0
        bn.rshi w11, w31, w11 >> 4
        addi x4, x4, 32
    bn.rshi w26, w31, w26 >> 4
    addi x7, x7, -1
    li   x5, 0x20
    li   x6, 25
    bn.sid x6, 0(x5)          /* acc -> ctx */
    la   x5, sfk_x1
    lw   x1, 0(x5)
    ret

#endif

#if defined(GF_INSTRUCTIONS)
/* shared by both hw arms: P3 fold is pure bn.gfmul.4 (no AES anywhere) */
.global backend_verify_p3_rows
backend_verify_p3_rows:
    li     x31, 0x13
    csrrw  x0, mod0, x31
    csrrw  x0, mod1, x0
    bn.xor w31, w31, w31
    li     x3, 0x20
    bn.ld  w0, 0(x3)          /* acc <- ctx */
    bn.wsrw acc, w0
    li     x7, 64
    sub    x7, x7, x9         /* first row size = o - row_start */
    li     x3, 0x40
    bn.ld  w6, 0(x3)          /* oil (host-aligned to row_start) */
    li     x12, 0x100
    li     x30, 30
    loop x8, 7
    bn.gfmul.4 w5, w6, w6
    loop x7, 3
        bn.lid x30, 0(x12++)
        bn.gfmul.4.acc w0, w30, w5
        bn.rshi w5, w31, w5 >> 4
    bn.rshi w6, w31, w6 >> 4
    addi   x7, x7, -1
    li     x3, 0x20
    bn.sd  w0, 0(x3)          /* acc -> ctx */
    ret
#endif

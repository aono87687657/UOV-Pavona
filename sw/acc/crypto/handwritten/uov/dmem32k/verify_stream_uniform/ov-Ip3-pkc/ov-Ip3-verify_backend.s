/* ov-Ip3-verify_backend.s - backend arms for the Ip3 verify stream_uniform outer.
 * cpp picks the arm (same convention as the R2 rig):
 *   bngfaes   -DAES_INSTRUCTIONS -DGF_INSTRUCTIONS  bn.aes128 CTR + bn.gfmul.8
 *   bngfonly  -DGF_INSTRUCTIONS                     compute-AES + bn.gfmul.8
 *   bnaesonly -DAES_INSTRUCTIONS                    aes128hw_384 + gf256_mul
 *   sw        (none)                                T-table AES + gf256_mul
 * Uniform cursor cadence everywhere (no tuned head/mid/tail), forked from the
 * R2 rig at Ip3 geometry: v=74, o=m=45, 8x45=360B keystream batches from the
 * 384B/12-dual leaves, entries realigned to WDR pairs by the leaf/loader.
 * ABI + schedule: see the backend_verify_* entry headers below.
 */
#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)
.section .text
.balign 4

/* VxV + VxO: full P1/P2 fold from AES-CTR; spills acc to ctx.
 * in: x10 sig, x12 seed (set by the outer). clob: x1,x5-x7,x16,x26,x28-x31,
 * w0-w9,w24-w31, acc/acch, mod0/mod1. stack: none. */
.global backend_verify_p1p2
backend_verify_p1p2:
    add x26, x0, x1           /* helpers clobber x1 */
    bn.xor w31, w31, w31
    bn.xor w0, w0, w0
    bn.xor w1, w1, w1
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    li   x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0       /* explicit scalar cursor = 0 */
    li   x31, 2
    bn.lid x31++, 0(x10)      /*w2:x31-x0*/
    bn.lid x31++, 32(x10)     /*w3:x63-x32*/
    bn.lid x31++, 64(x10)
    bn.rshi w4, w4, w31 >> 80
    bn.rshi w4, w31, w4 >> 176  /*w4:x73-x64*/
    li   x31, 30
    bn.lid x31, 0(x12)        /* AES key from seed */
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128
    bn.addi w29, w31, 1
    bn.rshi w29, w29, w31 >> 32
    bn.addi w27, w31, 2
    bn.or  w27, w27, w27 << 128
    bn.rshi w27, w27, w31 >> 160
    li   x16, 0               /* aes128_360 phase */
    /* ---- VxV: 74 cols, col i folds 74-i entries ---- */
    jal  x1, aes128_360
    li   x6, 0
    li   x7, 74
    li   x28, 8
    li   x29, 9
    li   x30, 8
    loopi 74, 20
    bn.gfmul.8 w5, w2, w2
    bn.gfmul.8 w6, w3, w2
    bn.gfmul.8 w7, w4, w2
    loop x7, 12
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc  w0, w8, w5
        bn.gfmul.8.acch w1, w9, w5
        addi x6, x6, 1
        bne x6, x28, _fkvv
            jal x1, aes128_360
            li x6, 0
            add x30, x0, x28
            _fkvv:bn.rshi w5, w6, w5 >> 8
        bn.rshi w6, w7, w6 >> 8
        bn.rshi w7, w31, w7 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1
    /* ---- VxO: oil window + 74 rows x 45 entries (stream continues) ---- */
    addi x31, x0, 2
    bn.lid x31++, 0(x10)
    bn.lid x31++, 32(x10)
    bn.lid x31++, 64(x10)
    bn.lid x31++, 96(x10)
    bn.rshi w6, w31, w5 >> 80   /* oil high: sig bytes 106..118 */
    bn.rshi w6, w6, w31 >> 104
    bn.rshi w6, w31, w6 >> 152  /* w6 = O[32..44], 13B zero-extended */
    bn.rshi w5, w5, w4 >> 80    /* w5 = O[0..31] = sig bytes 74..105 */
    bn.rshi w4, w4, w31 >> 80
    bn.rshi w4, w31, w4 >> 176  /* w4 = x[64..73] */
    loopi 74, 17
    bn.gfmul.8 w24, w5, w2
    bn.gfmul.8 w25, w6, w2
    loopi 45, 11
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        addi x6, x6, 1
        bne x6, x28, _fkvo
            jal x1, aes128_360
            li x6, 0
            add x30, x0, x28
            _fkvo:bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    /* ---- spill acc ctx ---- */
    li   x3, 0x020
    bn.sd w0, 0(x3)
    bn.sd w1, 32(x3)
    add x1, x0, x26
    ret

/* P3 row windows: reload acc, fold row_count rows, spill.
 * in: x9 row_start, x8 row_count (bounds-checked by the outer).
 * clob: x1-x8,x12,x26,x28-x31, w0-w9,w13-w27,w31, acc/acch, mod0/mod1. */
.global backend_verify_p3_rows
backend_verify_p3_rows:
    add  x26, x0, x1
    li   x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0
    bn.xor w31, w31, w31
    li   x3, 0x20
    bn.ld w0, 0(x3)
    bn.ld w1, 32(x3)
    bn.wsrw acc, w0
    bn.wsrw acch, w1
    li   x3, 0x60
    bn.ld w5, 0(x3)           /* oil, host-shifted to row_start */
    bn.ld w6, 32(x3)
    li   x28, 8
    li   x29, 9
    li   x12, 0x1A0
    li   x7, 45
    sub  x7, x7, x9           /* first row size */
    /* prefetch entries 0..3 (absorbs the 16B prefix); entry e starts at
     * window byte 16+45e, hi halves trimmed to 13B */
    bn.ld w13, 0(x12)
    bn.ld w14, 32(x12)
    bn.ld w15, 64(x12)
    bn.ld w16, 96(x12)
    bn.ld w17, 128(x12)
    bn.ld w18, 160(x12)
    bn.ld w19, 192(x12)
    bn.rshi w22, w18, w17 >> 184
    bn.rshi w23, w19, w18 >> 184
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 80
    bn.rshi w21, w18, w17 >> 80
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w15, w14 >> 232
    bn.rshi w19, w16, w15 >> 232
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w13 >> 128
    bn.rshi w17, w15, w14 >> 128
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    addi x12, x12, 192        /* aligned base of batch 0 (16+4*45 = 192+4) */
    li   x2, 0                /* load_p3_45 phase */
    li   x6, 4
    li   x30, 16
    loop x8, 17
    bn.gfmul.8 w24, w5, w5
    bn.gfmul.8 w25, w6, w5
    loop x7, 11
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        addi x6, x6, 1
        bne x6, x28, _fkp3
            jal x1, load_p3_45
            li x6, 0
            add x30, x0, x28
            _fkp3:bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
    bn.rshi w5, w6, w5 >> 8
    bn.rshi w6, w31, w6 >> 8
    addi x7, x7, -1
    li   x3, 0x20
    bn.sd w0, 0(x3)
    bn.sd w1, 32(x3)
    add x1, x0, x26
    ret

#elif defined(GF_INSTRUCTIONS)
.section .data
.balign 32
rcon:
    .word 0x08040201, 0x80402010, 0x361b
    .zero 26
# shiftrow_mask is referenced by AES_bngf helpers by name; keep original symbol.
.global shiftrow_mask
.balign 32
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
.balign 32
msb_mask:
    .word 0x80808080,0x80808080,0x80808080,0x80808080
    .word 0x80808080,0x80808080,0x80808080,0x80808080
.balign 32
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
.global MixColMat
.balign 32
MixColMat:
    .word 0x03010102, 0x01010203, 0x01020301, 0x02030101
    .zero 16
.balign 32
bfk_rk:      .zero 352            /* forward-pushed rk[0..10], x2 base */
bfk_x1:      .word 0

.section .text
.balign 4

/* clob: x1-x2,x5-x7,x10,x12,x16,x24-x31, w0-w9,w24-w31, acc/acch, mod0/1. */
.global backend_verify_p1p2
backend_verify_p1p2:
    la x5, bfk_x1
    sw x1, 0(x5)              /* aes128_360_bngf clobbers x24-x27: x1 -> DMEM */
    li x10, 0xE0              /* sig */
    li x12, 0x180             /* seed = AES key (cpk[0..15]) */
    bn.xor w31, w31, w31
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    bn.xor w0, w0, w0
    bn.xor w1, w1, w1

    li x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0
    li x31, 2
    bn.lid x31++, 0(x10)  /*w2:x31-x0*/
    bn.lid x31++, 32(x10) /*w3:x63-x32*/
    bn.lid x31++, 64(x10)
    bn.rshi w4, w4, w31 >> 80
    bn.rshi w4, w31, w4 >> 176 /*w4:x73-x64*/

    #Load AES128 Key From CPK
    li x31, 30
    bn.lid x31, 0(x12)
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128

    # w29 = LE-at-start dual counter (aes128_360_bngf byte-swaps and
    # self-increments +22/+22/+22/+24 across phases): blk0 ctr = 0 at byte 0,
    # blk1 ctr = 1 at byte 16, zero nonce
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 128

    la x30, msb_mask
    li x31, 28
    bn.lid x31, 0(x30)   /* w28 = msb_mask, preserved by the helpers */

    la x30, affine_value
    li x31, 27
    bn.lid x31, 0(x30)   /* w27 = affine_value, preserved */

    la x30, rcon
    li x31, 26
    bn.lid x31, 0(x30)   /* w26 = rcon carrier; dead after the schedule */
    la   x2, bfk_rk           /* rk base: aes128_360_bngf reads via x2 */
    addi x6, x2, 0            /* forward-push cursor */
    li x30, 30

    bn.or w30, w30, w30 << 128
    bn.sid x30, 0(x6++)
    bn.rshi w30, w31, w30 >> 128

    loopi 10, 4
        jal x1, KeySchedule
        bn.or w30, w30, w30 << 128
        bn.sid x30, 0(x6++)
        bn.rshi w30, w31, w30 >> 128
    li x16, 0                 /* aes128_360_bngf phase */
    jal x1, aes128_360
    li x6, 0
    li x7, 74
    li x28, 8
    li x29, 9
    li x30, 8
    li x31, 8

    loopi 74, 21
        bn.gfmul.8 w5, w2, w2
        bn.gfmul.8 w6, w3, w2
        bn.gfmul.8 w7, w4, w2
        loop x7, 13
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w8, w5
            bn.gfmul.8.acch w1, w9, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            addi x6, x6, 1
            bne x6, x31, vvskip_expand_key
                jal x1, aes128_360
                li x6, 0
                add x30, x0, x28
            vvskip_expand_key: NOP
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1

    /*Preparing Process VxO*/
    addi x31, x0, 2
    bn.lid x31++, 0(x10)  /*w2:x31-x0*/
    bn.lid x31++, 32(x10) /*w3:x63-x32*/
    bn.lid x31++, 64(x10) /*w4:x73-x64 + O[0..21]*/
    bn.lid x31++, 96(x10) /*w5:O[22..44] + salt head*/

    bn.rshi w6, w31, w5 >> 80   /* oil high: sig bytes 106..118 */
    bn.rshi w6, w6, w31 >> 104
    bn.rshi w6, w31, w6 >> 152  /* w6 = O[32..44] */
    bn.rshi w5, w5, w4 >> 80    /* w5 = O[0..31] */
    bn.rshi w4, w4, w31 >> 80
    bn.rshi w4, w31, w4 >> 176  /* w4 = x[64..73] */
    li x31, 8
    /* coefs in w24/w25: the leaf spills its duals precisely so these survive
     * a mid-row refill (w7/w8 would collide with the keystream pair) */
    loopi 74, 18
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        loopi 45, 12
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w8, w24
            bn.gfmul.8.acch w1, w9, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            addi x6, x6, 1
            bne x6, x31, voskip_expand_key
                jal x1, aes128_360
                li x6, 0
                add x30, x0, x28
            voskip_expand_key:
                NOP
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    /* ---- spill acc ctx ---- */
    li   x3, 0x020
    bn.sd w0, 0(x3)
    bn.sd w1, 32(x3)
    la   x5, bfk_x1
    lw   x1, 0(x5)
    ret

.global backend_verify_p3_rows
backend_verify_p3_rows:
    add  x26, x0, x1          /* load_p3_45 clobbers x2/x4/x12; x26 free here */
    li   x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0
    bn.xor w31, w31, w31
    li   x3, 0x20
    bn.ld w0, 0(x3)
    bn.ld w1, 32(x3)
    bn.wsrw acc, w0
    bn.wsrw acch, w1
    li   x3, 0x60
    bn.ld w5, 0(x3)           /* oil, host-shifted to row_start */
    bn.ld w6, 32(x3)
    li   x28, 8
    li   x29, 9
    li   x12, 0x1A0
    li   x7, 45
    sub  x7, x7, x9           /* first row size */
    bn.ld w13, 0(x12)
    bn.ld w14, 32(x12)
    bn.ld w15, 64(x12)
    bn.ld w16, 96(x12)
    bn.ld w17, 128(x12)
    bn.ld w18, 160(x12)
    bn.ld w19, 192(x12)
    bn.rshi w22, w18, w17 >> 184
    bn.rshi w23, w19, w18 >> 184
    bn.rshi w23, w23, w31 >> 104
    bn.rshi w23, w31, w23 >> 152
    bn.rshi w20, w17, w16 >> 80
    bn.rshi w21, w18, w17 >> 80
    bn.rshi w21, w21, w31 >> 104
    bn.rshi w21, w31, w21 >> 152
    bn.rshi w18, w15, w14 >> 232
    bn.rshi w19, w16, w15 >> 232
    bn.rshi w19, w19, w31 >> 104
    bn.rshi w19, w31, w19 >> 152
    bn.rshi w16, w14, w13 >> 128
    bn.rshi w17, w15, w14 >> 128
    bn.rshi w17, w17, w31 >> 104
    bn.rshi w17, w31, w17 >> 152
    addi x12, x12, 192
    li   x2, 0                /* load_p3_45 phase */
    li   x6, 4
    li   x30, 16
    li   x31, 8
    loop x8, 18
    bn.gfmul.8 w2, w5, w5
    bn.gfmul.8 w3, w6, w5
    loop x7, 12
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc w0, w8, w2
        bn.gfmul.8.acch w1, w9, w2
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w31, w3 >> 8
        addi x6, x6, 1
        bne x6, x31, _bfkp3
            jal x1, load_p3_45
            li x6, 0
            add x30, x0, x28
            _bfkp3: NOP
    bn.rshi w5, w6, w5 >> 8
    bn.rshi w6, w31, w6 >> 8
    addi x7, x7, -1
    li   x3, 0x20
    bn.sd w0, 0(x3)
    bn.sd w1, 32(x3)
    add  x1, x0, x26
    ret

#else

/* ------------------------------ sw arm ------------------------------
 * Fold bodies lifted verbatim from the R3 streamed gfsw kernel (which itself
 * forked the R2 uniform sw arm); only the entry/exit ABI differs. T-table AES
 * (or aes128hw_384 under -DAES_INSTRUCTIONS) + gf256_mul dual folds; acc in
 * w21/w22, spilled to ctx at 0x20/0x40.
 * MAX-WINDOW ABI: the outer reserves msgwin to winend; the private stack is
 * ACC-only scratch above the bus window, written before read, never host-read.
 */
.section .data
.balign 32
vfk_upper13: .word 0xffffffff, 0xffffffff, 0xffffffff
             .byte 0xff
             .zero 19
.balign 32
vfk_msb:     .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
             .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
vfk_x1:      .word 0

/* x2 descends from vfk_stack_end; ACC-private, above the 31,744 B bus window */
.set vfk_stack,     31744
.set vfk_stack_end, 32352   /* 32 frame + 192 rk (sw only) + 384 buf */

.section .text
.balign 4

.global backend_verify_p1p2
backend_verify_p1p2:
    la x5, vfk_x1
    sw x1, 0(x5)              /* helpers clobber x1 */
    la x2, vfk_stack_end      /* private 608B stack (monolith convention) */
    la x5, vfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask (gf256_mul precondition) */
    la x5, vfk_upper13
    li x6, 29
    bn.lid x6, 0(x5)          /* w29 = upper12B_mask (col-hi12) */
    li x10, 0xE0              /* sig */
    li x11, 0x20             /* acc-out (unused; p1p2 spills to 0x20/0x40) */
    li x12, 0x180            /* seed = AES key (cpk[0..15] in the monolith) */
    li x13, 0
    li x14, 0
    addi x2, x2, -32
    add x3, x0, x2
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    sw x14, 16(x2)

    bn.xor w31, w31, w31
    bn.xor w21, w21, w21
    bn.xor w22, w22, w22
    bn.xor w20, w20, w20

    bn.wsrw acc, w31

#ifdef AES_INSTRUCTIONS
    add x18, x0, x12            # x18 = AES key survivor; bn.aes128 expands per call
#else
    addi x2, x2, -192            # 176 B rk + 16 B pad (keeps stack 32-aligned for P1 below)

    #AES key schedule: pk_seed (cpk[0..15]) to 176-byte round-key buffer
    add x10, x0, x12            # x10 = pk_seed pointer (= cpk pointer)
    add x11, x0, x2            # x11 = rkb base
    jal x1, AES_128_keyschedule
    add x18, x0, x2             #x18 = rkb survivor, set AFTER KS, KS clobbers x18
#endif

    #AES-CTR counter init; threads through the 384-B leaf calls via x13
    addi x13, x0, 0

    # preserve 384 bytes for P1 expansion (12 duals)
    addi x2, x2, -384
    add x4, x0, x2 # x4 point for P1 tmp space for 384 bytes
    sw x4, 20(x3)   # store 384 bytes starting adddress
    li x31, 23
    lw x25, 0(x3)
    # VxV,  Only load V part first
    bn.lid x31++, 0(x25)            # w23 = sig[0..31]   = v[0..31]
    bn.lid x31++, 32(x25)           # w24 = sig[32..63]  = v[32..63]
    bn.lid x31++, 64(x25)           # w25 = sig[64..95]  (only v[64..67] valid)
    bn.rshi w25, w25, w31 >> 80     # trim w25 to 10 valid vinegar bytes
    bn.rshi w25, w31, w25 >> 176

    li x17, 0                   # col countdown (relocated from x25 to free contiguous block)
    li x26, 74                  # row size
    li x23, 7                   # WDR idx 7 (was x23)
    li x24, 8                   # WDR idx 8 (was x24)
    li x25, 9                   # WDR idx 9 (was x25; now part of x23-x24-x25 contiguous block)
    addi x10, x10, -320
    #setup first batch of VxV Elements
    jal x1, gen_newVxV_element
    VxV_p0_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -2          # net +22 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col1
        jal x1, gen_newVxV_element
        VxV_p0_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 104
        bn.rshi w8, w31, w8 >> 104
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col2
        jal x1, gen_newVxV_element
        VxV_p0_col2:
        bn.lid x23, 64(x4)
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 208
        bn.rshi w8, w9, w8 >> 208
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col3
        jal x1, gen_newVxV_element
        VxV_p0_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 56
        bn.rshi w8, w31, w8 >> 56
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col4
        jal x1, gen_newVxV_element
        VxV_p0_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 160
        bn.rshi w8, w9, w8 >> 160
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col5
        jal x1, gen_newVxV_element
        VxV_p0_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 8
        bn.rshi w8, w31, w8 >> 8
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col6
        jal x1, gen_newVxV_element
        VxV_p0_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.rshi w7, w8, w7 >> 112
        bn.rshi w8, w31, w8 >> 112
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_col7
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_p0_col7:
        bn.lid x23, 288(x4)
        bn.lid x24, 320(x4)
        bn.lid x25, 352(x4)
        bn.rshi w7, w8, w7 >> 216
        bn.rshi w8, w9, w8 >> 216
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_head
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_p1_head
    VxV_p1_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -1          # net +23 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.rshi w7, w8, w7 >> 64
        bn.rshi w8, w31, w8 >> 64
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col1
        jal x1, gen_newVxV_element
        VxV_p1_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.lid x25, 96(x4)
        bn.rshi w7, w8, w7 >> 168
        bn.rshi w8, w9, w8 >> 168
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col2
        jal x1, gen_newVxV_element
        VxV_p1_col2:
        bn.lid x23, 96(x4)
        bn.lid x24, 128(x4)
        bn.rshi w7, w8, w7 >> 16
        bn.rshi w8, w31, w8 >> 16
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col3
        jal x1, gen_newVxV_element
        VxV_p1_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 120
        bn.rshi w8, w31, w8 >> 120
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col4
        jal x1, gen_newVxV_element
        VxV_p1_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 224
        bn.rshi w8, w9, w8 >> 224
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col5
        jal x1, gen_newVxV_element
        VxV_p1_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 72
        bn.rshi w8, w31, w8 >> 72
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col6
        jal x1, gen_newVxV_element
        VxV_p1_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.lid x25, 320(x4)
        bn.rshi w7, w8, w7 >> 176
        bn.rshi w8, w9, w8 >> 176
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p1_col7
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_p1_col7:
        bn.lid x23, 320(x4)
        bn.lid x24, 352(x4)
        bn.rshi w7, w8, w7 >> 24
        bn.rshi w8, w31, w8 >> 24
        bn.and w8, w8, w29
        bn.mov w2, w26
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_p0_head
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_p0_head
    VxV_END:    #start VxO init continue from VxV end of VxVcol2
    li x31, 23                  #x23..x27 still hold prior state, x28..x31 clobbered by aes128table_352 not used here
    lw x5, 0(x3)                #reload sig ptr
    li x17, 0                   # current VxO elements
    li x26, 74                  # V elements remaining; x26=0 marks P2 done
    # VxO, load all sig = V(68B) || O(44B) || salt (16B), need V[0..67] + O[0..43]
    bn.lid x31++, 0(x5)         #w23 V[0..31]
    bn.lid x31++, 32(x5)        #w24 V[32..63]
    bn.lid x31++, 64(x5)        #w25 V[64..67] + O[0..27]
    bn.lid x31++, 96(x5)        #w26 O[28..43] + 16B junk
    bn.rshi w27, w31, w26 >> 80 #w27 = O[32..44] = sig[106..118]
    bn.and w27, w27, w29        #  mask to 13B, wipe salt junk
    bn.rshi w26, w26, w25 >> 80 # w26 = O[0..31] = sig[74..105]
    bn.and w25, w25, w29 >> 24  # w25 = V[64..73] low 10B, rest 0
    jal x1, gen_newVxO_element  # row 0 coefs in w11/w12, v slid for row 1
    beq x0, x0, VxO_p0_col7   # continue mid-batch: entry 2775 is col 7
    VxO_p0_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -2          # net +22 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col1
        beq x0, x26, VxO_END
        jal x1, gen_newVxO_element
        VxO_p0_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 104
        bn.rshi w8, w31, w8 >> 104
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col2
        jal x1, gen_newVxO_element
        VxO_p0_col2:
        bn.lid x23, 64(x4)
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 208
        bn.rshi w8, w9, w8 >> 208
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col3
        jal x1, gen_newVxO_element
        VxO_p0_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 56
        bn.rshi w8, w31, w8 >> 56
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col4
        jal x1, gen_newVxO_element
        VxO_p0_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 160
        bn.rshi w8, w9, w8 >> 160
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col5
        jal x1, gen_newVxO_element
        VxO_p0_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 8
        bn.rshi w8, w31, w8 >> 8
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col6
        jal x1, gen_newVxO_element
        VxO_p0_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.rshi w7, w8, w7 >> 112
        bn.rshi w8, w31, w8 >> 112
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_col7
        jal x1, gen_newVxO_element
        VxO_p0_col7:
        bn.lid x23, 288(x4)
        bn.lid x24, 320(x4)
        bn.lid x25, 352(x4)
        bn.rshi w7, w8, w7 >> 216
        bn.rshi w8, w9, w8 >> 216
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_head
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_p1_head
    VxO_p1_head:
        lw x4, 20(x3)
        add x10, x0, x18              #rk base / AES key survivor
        lw  x11, 20(x3)               # 384-B batch buffer
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_384
#else
        jal x1, aes128table_384
#endif
        addi x13, x13, -1          # net +23 blocks
        lw x4, 20(x3)
        bn.lid x23, 0(x4)
        bn.lid x24, 32(x4)
        bn.rshi w7, w8, w7 >> 64
        bn.rshi w8, w31, w8 >> 64
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col1
        beq x0, x26, VxO_END
        jal x1, gen_newVxO_element
        VxO_p1_col1:
        bn.lid x23, 32(x4)
        bn.lid x24, 64(x4)
        bn.lid x25, 96(x4)
        bn.rshi w7, w8, w7 >> 168
        bn.rshi w8, w9, w8 >> 168
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col2
        jal x1, gen_newVxO_element
        VxO_p1_col2:
        bn.lid x23, 96(x4)
        bn.lid x24, 128(x4)
        bn.rshi w7, w8, w7 >> 16
        bn.rshi w8, w31, w8 >> 16
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col3
        jal x1, gen_newVxO_element
        VxO_p1_col3:
        bn.lid x23, 128(x4)
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 120
        bn.rshi w8, w31, w8 >> 120
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col4
        jal x1, gen_newVxO_element
        VxO_p1_col4:
        bn.lid x23, 160(x4)
        bn.lid x24, 192(x4)
        bn.lid x25, 224(x4)
        bn.rshi w7, w8, w7 >> 224
        bn.rshi w8, w9, w8 >> 224
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col5
        jal x1, gen_newVxO_element
        VxO_p1_col5:
        bn.lid x23, 224(x4)
        bn.lid x24, 256(x4)
        bn.rshi w7, w8, w7 >> 72
        bn.rshi w8, w31, w8 >> 72
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col6
        jal x1, gen_newVxO_element
        VxO_p1_col6:
        bn.lid x23, 256(x4)
        bn.lid x24, 288(x4)
        bn.lid x25, 320(x4)
        bn.rshi w7, w8, w7 >> 176
        bn.rshi w8, w9, w8 >> 176
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p1_col7
        jal x1, gen_newVxO_element
        VxO_p1_col7:
        bn.lid x23, 320(x4)
        bn.lid x24, 352(x4)
        bn.rshi w7, w8, w7 >> 24
        bn.rshi w8, w31, w8 >> 24
        bn.and w8, w8, w29
        bn.mov w2, w11
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w11, w12, w11 >> 8
        bn.rshi w12, w31, w12 >> 8
        addi x17, x17, -1
        bne x17, x0, VxO_p0_head
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_p0_head
    VxO_END:    # start P3 init
    /* acc (w21/w22) complete after VxO; spill to ctx */
    li x5, 0x20
    bn.sd w21, 0(x5)
    li x5, 0x40
    bn.sd w22, 0(x5)
    la   x5, vfk_x1
    lw   x1, 0(x5)
    ret

.global backend_verify_p3_rows
backend_verify_p3_rows:
    la x5, vfk_x1
    sw x1, 0(x5)
    la x2, vfk_stack_end
    la x5, vfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask */
    la x5, vfk_upper13
    li x6, 30
    bn.lid x6, 0(x5)          /* w30 = 12B mask for the fold hi half */
    bn.xor w31, w31, w31
    li x5, 0x20
    bn.ld w21, 0(x5)          /* acc lo <- ctx */
    li x5, 0x40
    bn.ld w22, 0(x5)          /* acc hi */
    li x5, 0x60
    bn.ld w26, 0(x5)          /* oil[0..31] (host-shifted: byte0 = O[row_start]) */
    li x5, 0x80
    bn.ld w27, 0(x5)          /* oil[32..43] (junk above ok) */
    li x4, 0x1A0             /* P3 window (16B prefix + packed entries) */
    li x26, 45
    sub x26, x26, x9         /* geometry rows: 45 - row_start */
    /* x8 = row_count (from outer) is the independent terminator */
    jal x1, gen_newP3_element  /* row-0 coefs w28/w29, x17 = 45-row_start */
    P3_p0_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 128
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w8 >> 128
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 232
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 232
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 80
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 80
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 184
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w12 >> 184
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col4:
        bn.mov w2, w28
        bn.rshi w1, w14, w13 >> 32
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 32
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 136
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 136
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 240
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 240
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p0_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 88
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 88
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p1_head
    P3_p1_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 384
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 192
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w9, w8 >> 192
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col1:
        bn.mov w2, w28
        bn.rshi w1, w10, w9 >> 40
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w10 >> 40
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 144
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 144
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 248
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w13, w12 >> 248
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col4:
        bn.mov w2, w28
        bn.rshi w1, w14, w13 >> 96
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w14 >> 96
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 200
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w16, w15 >> 200
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col6:
        bn.mov w2, w28
        bn.rshi w1, w18, w16 >> 48
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w18 >> 48
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p1_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p1_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 152
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 152
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p2_head
    P3_p2_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
        bn.mov w2, w28
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w8, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 104
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w9 >> 104
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col2:
        bn.mov w2, w28
        bn.rshi w1, w10, w9 >> 208
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w11, w10 >> 208
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 56
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 56
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col4:
        bn.mov w2, w28
        bn.rshi w1, w13, w12 >> 160
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w14, w13 >> 160
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 8
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 8
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 112
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w16 >> 112
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p2_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p2_col7:
        bn.mov w2, w28
        bn.rshi w1, w18, w16 >> 216
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w19, w18 >> 216
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p3_head
    P3_p3_head:
        li x6, 7
        bn.lid x6++, 0(x4)
        bn.lid x6++, 32(x4)
        bn.lid x6++, 64(x4)
        bn.lid x6++, 96(x4)
        bn.lid x6++, 128(x4)
        bn.lid x6++, 160(x4)
        bn.lid x6++, 192(x4)
        bn.lid x6++, 224(x4)
        bn.lid x6++, 256(x4)
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)
        bn.lid x6++, 352(x4)
        addi x4, x4, 352
        bn.mov w2, w28
        bn.rshi w1, w8, w7 >> 64
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w8 >> 64
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col1:
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 168
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 168
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col2:
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 16
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 16
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col3:
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 120
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 120
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col4:
        bn.mov w2, w28
        bn.rshi w1, w13, w12 >> 224
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w14, w13 >> 224
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col5:
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 72
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 72
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col6:
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 176
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 176
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p3_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_p3_col7:
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 24
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 24
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_p0_head
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_p0_head
    P3_done:
    li x5, 0x20
    bn.sd w21, 0(x5)          /* acc lo -> ctx */
    li x5, 0x40
    bn.sd w22, 0(x5)
    la   x5, vfk_x1
    lw   x1, 0(x5)
    ret

/* ---- internal helpers from the backend sw arm (ret-terminated, jal x1) ---- */
# gen_newVxV_element: prep one VxV row coefs (upper-tri, row size = V-i)
# in:  w23..w25 V window, byte 0 = v[i]
#      x26 = row size for current row (= V-i), caller gates so x26 != 0 here
# out: w26 = v[i]*v[i..i+31], w27 = v[i]*v[i+32..i+63], w28 = v[i]*v[i+64..i+95]
#      x17 = x26 (row size for col countdown)
#      v slid 1B (byte 0 = v[i+1]), x26-- (next row size = V-(i+1))
gen_newVxV_element:
    bn.mov w1, w23
    bn.mov w2, w23
    jal x1, gf256_mul
    bn.mov w26, w0                       # 32 coefs v[i]*v[i..i+31]
    bn.mov w1, w24
    jal x1, gf256_mul
    bn.mov w27, w0                       # 32 coefs v[i]*v[i+32..i+63]
    bn.mov w1, w25
    jal x1, gf256_mul
    bn.mov w28, w0                       # tail v[i]*v[i+64..i+95] (bytes past V[67] = junk)
    add x17, x0, x26                     # row size = V-i (shrinks per row)
    beq x26, x0, gen_newVxV_element_ret  #x26=0 skip slide
    bn.rshi w23, w24, w23 >> 8
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8           # v window v[i] to v[i+1]
    addi x26, x26, -1
gen_newVxV_element_ret:
    ret


# gen_newVxO_element: prep one VxO row coefs
# in:  w23..w25 V window, byte 0 = v[i]
#      w26 = O[0..31], w27 = O[32..43] low 12B
#      x26 = rows left, caller gates so x26 != 0 here
# out: w11 = v[i]*O[0..31], w12 = v[i]*O[32..43] low 12B
#      x17 = 44, v slid 1B (byte 0 = v[i+1]), x26--
gen_newVxO_element:
    bn.mov w2, w23
    bn.mov w1, w26
    jal x1, gf256_mul
    bn.mov w11, w0                       # 32 coefs v[i]*O[0..31]
    bn.mov w1, w27
    jal x1, gf256_mul
    bn.mov w12, w0                       # 12 valid coefs v[i]*O[32..43]
    li x17, 45                           # row size const for VxO (vs V-i in VxV)
    beq x26, x0, gen_newVxO_element_ret  #x26=0 skip slide
    bn.rshi w23, w24, w23 >> 8
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8           # v window v[i] to v[i+1]
    addi x26, x26, -1
gen_newVxO_element_ret:
    ret


# gen_newP3_element: prep one P3 row coefs (oil x oil upper-tri)
# in:  w26 = O[i..i+31], w27 = O[i+32..i+43] low 12B (junk above)
#      x26 = rows-left BEFORE this row (= 44-i; caller gates so x26 != 0 here)
# out: w28 = O[i]*O[i..i+31]              (32B; first 44-i meaningful)
#      w29 = O[i]*O[i+32..i+43] low 12B   (first max(0,12-i) meaningful)
#      x17 = row size for col countdown (= 44-i)
#      O window slid 1B (byte 0 = O[i+1]); x26 decremented
gen_newP3_element:
    bn.mov w2, w26                       # scalar = O[i] (low byte)
    bn.mov w1, w26
    jal x1, gf256_mul
    bn.mov w28, w0                       # 32 coefs O[i]*O[i..i+31]
    bn.mov w1, w27
    jal x1, gf256_mul
    bn.mov w29, w0                       # 12 valid coefs O[i]*O[i+32..i+43]
    add x17, x0, x26                     # row size = 44-i (shrinks per row)
    beq x26, x0, gen_newP3_element_ret   #x26=0 skip slide
    bn.rshi w26, w27, w26 >> 8
    bn.rshi w27, w31, w27 >> 8           # O window O[i] to O[i+1]
    addi x26, x26, -1
gen_newP3_element_ret:
    ret

#endif

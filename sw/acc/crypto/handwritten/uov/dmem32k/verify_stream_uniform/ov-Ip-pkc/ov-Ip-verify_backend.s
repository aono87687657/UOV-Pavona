/* ov-Ip-verify_backend.s - backend arms for the Ip verify stream_uniform outer.
 * cpp picks the arm (same convention as ov-Ip-pkc_publicmap.s):
 *   bngfaes   -DAES_INSTRUCTIONS -DGF_INSTRUCTIONS  bn.aes128 CTR + bn.gfmul.8
 *   bngfonly  -DGF_INSTRUCTIONS                     compute-AES + bn.gfmul.8
 *   bnaesonly -DAES_INSTRUCTIONS                    aes128hw_352 + gf256_mul
 *   sw        (none)                                T-table AES + gf256_mul
 * The last two share the sw arm body: the GF engine picks the arm, the AES leaf
 * is an inner ifdef, so the pair prices AES with the GF path held fixed.
 * Uniform cursor cadence everywhere (no tuned head/mid/tail): the fixed
 * bngfaes arm = 193,960 cyc, +25.2% vs the shipping TUNED streamed (154,873)
 * (ISS, case 0, both re-measured 2026-08-01)
 * - the fixed uniform geometry deliberately drops the bngfaes-only Part-S/H
 * tuning so arm ratios isolate the backend, not per-tier effort.
 * ABI + schedule: see the backend_verify_* entry headers.
 */
#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)
.section .text
.balign 4

/* VxV + VxO: full P1/P2 fold from AES-CTR; spills acc to ctx. */
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
    bn.rshi w4, w4, w31 >> 32
    bn.rshi w4, w31, w4 >> 224  /*w4:x67-x64*/
    li   x31, 30
    bn.lid x31, 0(x12)        /* AES key from seed */
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128
    bn.addi w29, w31, 1
    bn.rshi w29, w29, w31 >> 32
    bn.addi w27, w31, 2
    bn.or  w27, w27, w27 << 128
    bn.rshi w27, w27, w31 >> 160
    /* ---- VxV: 68 cols, col i folds 68-i entries ---- */
    jal  x1, aes128_352
    li   x6, 0
    li   x7, 68
    li   x28, 8
    li   x29, 9
    li   x30, 8
    loopi 68, 20
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
            jal x1, aes128_352
            li x6, 0
            add x30, x0, x28
            _fkvv:bn.rshi w5, w6, w5 >> 8
        bn.rshi w6, w7, w6 >> 8
        bn.rshi w7, w31, w7 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1
    /* ---- VxO: oil window + 68 rows x 44 entries (stream continues) ---- */
    addi x31, x0, 2
    bn.lid x31++, 0(x10)
    bn.lid x31++, 32(x10)
    bn.lid x31++, 64(x10)
    bn.lid x31++, 96(x10)
    bn.rshi w5, w5, w31 >> 128
    bn.rshi w5, w31, w5 >> 128
    bn.rshi w6, w31, w5 >> 32
    bn.rshi w5, w5, w4 >> 32
    bn.rshi w4, w4, w31 >> 32
    bn.rshi w4, w31, w4 >> 224
    loopi 68, 17
    bn.gfmul.8 w24, w5, w2
    bn.gfmul.8 w25, w6, w2
    loopi 44, 11
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        addi x6, x6, 1
        bne x6, x28, _fkvo
            jal x1, aes128_352
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

/* P3 row windows: reload acc, fold row_count rows, spill. */
.global backend_verify_p3_rows
backend_verify_p3_rows:
    add x26, x0, x1
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
    li   x12, 0x180
    li   x7, 44
    sub  x7, x7, x9           /* first row size */
    li   x30, 13
    loopi 6, 2
        bn.lid x30++, 0(x12)
        addi x12, x12, 32
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
            jal x1, load_p3
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
# shiftrow_mask is referenced by AES_bngf/aes128_352.s by name; keep original symbol.
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

.global backend_verify_p1p2
backend_verify_p1p2:
    la x5, bfk_x1
    sw x1, 0(x5)              /* aes128_352 clobbers x24-x27: x1 -> DMEM */
    li x10, 0xE0              /* sig */
    li x12, 0x160             /* seed = AES key (cpk[0..15] in the monolith) */
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
    bn.rshi w4, w4, w31 >> 32
    bn.rshi w4, w31, w4 >> 224 /*w4:x67-x64*/

    #Load AES128 Key From CPK
    li x31, 30
    bn.lid x31, 0(x12)
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128

    # w29 = IV in LE-at-start staging form, NOT spec position
    # counter NOT at upper 32b of each block (= spec BE-at-end);
    # held at low 32b instead so +=2 increment is one bn.add
    # byte 0 = c0_lo (=0), byte 16 = c1_lo (=0x01)
    # aes128_352 byte-swap LE-at-start -> BE-at-end before encrypt
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 128

    la x30, msb_mask
    li x31, 28
    bn.lid x31, 0(x30)   /* loads msb_mask into w28 */

    la x30, affine_value
    li x31, 27
    bn.lid x31, 0(x30)   /* loads affine_value into w27 */

    la x30, rcon
    li x31, 26
    bn.lid x31, 0(x30)
    la   x2, bfk_rk           /* rk base: aes128_352 reads via x2 */
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
    jal x1, aes128_352
    li x6, 0
    li x7, 68
    li x28, 9
    li x29, 10
    li x30, 9
    li x31, 8

    loopi 68, 21
        bn.gfmul.8 w5, w2, w2
        bn.gfmul.8 w6, w3, w2
        bn.gfmul.8 w7, w4, w2
        loop x7, 13
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w9, w5
            bn.gfmul.8.acch w1, w10, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            addi x6, x6, 1
            bne x6, x31, vvskip_expand_key
                jal x1, aes128_352
                li x6, 0
                add x30, x0, x28
            vvskip_expand_key: NOP
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1

    /*Preparing Process VxO*/
    addi x31, x0, 2
    bn.lid x31++, 0(x10)  /*w2:x31-x0*/# 32
    bn.lid x31++, 32(x10) /*w3:x63-x32*/ #32
    bn.lid x31++, 64(x10) /*w4:x95-x64*/ #28 + 4
    bn.lid x31++, 96(x10) /*w5:(salt)||x111-x96*/ #16

    bn.rshi w5, w5, w31 >> 128
    bn.rshi w5, w31, w5 >> 128
    bn.rshi w6, w31, w5 >> 32
    bn.rshi w5, w5, w4 >> 32
    bn.rshi w4, w4, w31 >> 32
    bn.rshi w4, w31, w4 >> 224
    li x31, 8
    loopi 68, 18
        bn.gfmul.8 w7, w5, w2
        bn.gfmul.8 w8, w6, w2
        loopi 44, 12
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w9, w7
            bn.gfmul.8.acch w1, w10, w7
            bn.rshi w7, w8, w7 >> 8
            bn.rshi w8, w31, w8 >> 8
            addi x6, x6, 1
            bne x6, x31, voskip_expand_key
                jal x1, aes128_352
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
    add  x26, x0, x1          /* load_p3 is GPR-clean; x26 free here */
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
    li   x28, 9
    li   x29, 10
    li   x12, 0x180
    li   x7, 44
    sub  x7, x7, x9           /* first row size */
    li x30, 13
    loopi 6, 2
        bn.lid x30++, 0(x12)
        addi x12, x12, 32

    bn.rshi w24, w31, w18 >> 160
    bn.rshi w23, w18, w17 >> 160

    bn.rshi w22, w17, w31 >> 160
    bn.rshi w22, w31, w22 >> 160
    bn.rshi w21, w17, w16 >> 64

    bn.rshi w20, w16, w15 >> 64
    bn.rshi w20, w31, w20 >> 160
    bn.rshi w19, w15, w14 >> 224

    bn.rshi w18, w14, w31 >> 224
    bn.rshi w18, w31, w18 >> 160
    bn.rshi w17, w14, w13 >> 128
    li   x6, 4
    li   x30, 17
    li   x31, 8
    loop x8, 18
    bn.gfmul.8 w2, w5, w5
    bn.gfmul.8 w3, w6, w5
    loop x7, 12
        bn.movr x28, x30++
        bn.movr x29, x30++
        bn.gfmul.8.acc w0, w9, w2
        bn.gfmul.8.acch w1, w10, w2
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w31, w3 >> 8
        addi x6, x6, 1
        bne x6, x31, _bfkp3
            jal x1, load_p3
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
 * Monolith-publicmap splice (T-table AES + gf256_mul dual folds); acc in
 * plain WDRs w21/w22. No gfmul/aes128; gf256_mul is the repo sw-tier
 * helper (bn.mulv.l x0x1b reduce). ABI + phase split: backend_verify_* headers.
 * MAX-WINDOW ABI: the outer reserves the host window to 0x58e0 (<=504
 * packed P3 entries per UPDATE, the caprows maximum); this arm's private
 * .data links after that.
 * A host schedule writing a larger single window is OUT OF CONTRACT.
 */
.section .data
.balign 32
vfk_stack:   .zero 576            /* 32 frame + 192 rk + 352 P1 tmp */
vfk_stack_end:
.balign 32
vfk_upper12: .word 0xffffffff, 0xffffffff, 0xffffffff
             .zero 20
.balign 32
vfk_msb:     .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
             .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
vfk_x1:      .word 0

.section .text
.balign 4

.global backend_verify_p1p2
backend_verify_p1p2:
    la x5, vfk_x1
    sw x1, 0(x5)              /* helpers clobber x1 */
    la x2, vfk_stack_end      /* private 576B stack (monolith convention) */
    la x5, vfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask (gf256_mul precondition) */
    la x5, vfk_upper12
    li x6, 29
    bn.lid x6, 0(x5)          /* w29 = upper12B_mask (col-hi12) */
    li x10, 0xE0              /* sig */
    li x11, 0x20             /* acc-out (unused; p1p2 spills to 0x20/0x40) */
    li x12, 0x160            /* seed = AES key (cpk[0..15] in the monolith) */
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

    #AES-CTR counter init; threads through the AES leaf via x13
    addi x13, x0, 0

    # preserve 352 bytes for P1 expansion
    addi x2, x2, -352
    add x4, x0, x2 # x4 point for P1 tmp space for 352 bytes
    sw x4, 20(x3)   # store 352 bytes starting adddress
    li x31, 23
    lw x25, 0(x3)
    # VxV,  Only load V part first
    bn.lid x31++, 0(x25)            # w23 = sig[0..31]   = v[0..31]
    bn.lid x31++, 32(x25)           # w24 = sig[32..63]  = v[32..63]
    bn.lid x31++, 64(x25)           # w25 = sig[64..95]  (only v[64..67] valid)
    bn.rshi w25, w25, w31 >> 32     # trim w25 to 4 valid vinegar bytes (low 4B)
    bn.rshi w25, w31, w25 >> 224

    li x17, 0                   # col countdown (relocated from x25 to free contiguous block)
    li x26, 68                  # row size
    li x23, 7                   # WDR idx 7 (was x23)
    li x24, 8                   # WDR idx 8 (was x24)
    li x25, 9                   # WDR idx 9 (was x25; now part of x23-x24-x25 contiguous block)
    addi x10, x10, -320
    #setup first batch of VxV Elements
    jal x1, gen_newVxV_element
    VxV_mul_loop:
        lw x4, 20(x3)
        # AES-CTR expand 22 blocks (352 B) into P1 buffer; counter chains via x13
        add x10, x0, x18              #rk base / AES key survivor from setup
        lw  x11, 20(x3)               # P1 buffer base from frame slot 20
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_352
#else
        jal x1, aes128table_352
#endif
        lw x4, 20(x3)                    #col 0
        bn.lid x23, 0(x4)                #  col_lo32 directly
        bn.lid x24, 32(x4)               #
        bn.and w8, w8, w29               # col_hi12 = KS1 & mask12
        bn.mov w2, w26                  # coef = byte 0 of v·v[i]
        bn.mov w1, w7
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.mov w1, w8
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w26, w27, w26 >> 8      # advance coef buffer
        bn.rshi w27, w28, w27 >> 8
        bn.rshi w28, w31, w28 >> 8
        addi x17, x17, -1
        bne x17, x0, VxV_col1
        jal x1, gen_newVxV_element
        VxV_col1:
        bn.lid x23, 32(x4)              #col 1
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 96        # col_lo32 in-place
        bn.rshi w8, w31, w8 >> 96       # col_hi12 candidate
        bn.and w8, w8, w29              # mask to 12B
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
        bne x17, x0, VxV_col2
        beq x0, x26, VxV_END
        jal x1, gen_newVxV_element
        VxV_col2:
        bn.lid x23, 64(x4)               # col 2
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 192       # col_lo32 = KS2[24..31]||KS3[0..23]
        bn.rshi w8, w9, w8 >> 192       # col_hi12 candidate
        bn.and w8, w8, w29              # mask
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
        bne x17, x0, VxV_col3
        jal x1, gen_newVxV_element
        VxV_col3:
        bn.lid x23, 128(x4)             #col 3
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 32
        bn.rshi w8, w31, w8 >> 32
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
        bne x17, x0, VxV_col4
        jal x1, gen_newVxV_element
        VxV_col4:
        bn.lid x23, 160(x4)             #col 4
        bn.lid x24, 192(x4)
        bn.rshi w7, w8, w7 >> 128
        bn.rshi w8, w31, w8 >> 128
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
        bne x17, x0, VxV_col5
        jal x1, gen_newVxV_element
        VxV_col5:
        bn.lid x23, 192(x4)           #col 5
        bn.lid x24, 224(x4)
        bn.lid x25, 256(x4)
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
        bne x17, x0, VxV_col6
        jal x1, gen_newVxV_element
        VxV_col6:
        bn.lid x23, 256(x4)          #col 6
        bn.lid x24, 288(x4)
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
        bne x17, x0, VxV_col7
        jal x1, gen_newVxV_element
        VxV_col7:
        bn.lid x23, 288(x4)         #col 7
        bn.lid x24, 320(x4)
        bn.rshi w7, w8, w7 >> 160       # col_lo32
        bn.rshi w8, w31, w8 >> 160      # col_hi12 w31 top zero high no mask
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
        bne x17, x0, VxV_mul_loop
        jal x1, gen_newVxV_element
        beq x0, x0, VxV_mul_loop
    VxV_END:    #start VxO init continue from VxV end of VxVcol2
    li x31, 23                  #x23..x27 still hold prior state, x28..x31 clobbered by aes128table_352 not used here
    lw x5, 0(x3)                #reload sig ptr
    li x17, 0                   # current VxO elements
    li x26, 68                  # V elements remaining; x26=0 marks P2 done
    # VxO, load all sig = V(68B) || O(44B) || salt (16B), need V[0..67] + O[0..43]
    bn.lid x31++, 0(x5)         #w23 V[0..31]
    bn.lid x31++, 32(x5)        #w24 V[32..63]
    bn.lid x31++, 64(x5)        #w25 V[64..67] + O[0..27]
    bn.lid x31++, 96(x5)        #w26 O[28..43] + 16B junk
    bn.and w27, w29, w26 >> 32  #w27 = O[32..43] low 12B, mask12 wipe junk
    bn.rshi w26, w26, w25 >> 32 # w26 = O[0..31] = w25[4..31] || w26[0..3]
    bn.and w25, w25, w29 >> 64  # w25 = V[64..67] low 4B, rest 0
    jal x1, gen_newVxO_element  # row 0 coefs in w11/w12, v slid for row 1
    beq x0, x0,  VxO_col2       # last VxV batch col2..col7 = first 6 P2 entries
    VxO_mul_loop:
        lw x4, 20(x3)
        # AES-CTR expand 22 blocks (352 B) into P1 buffer; counter chains via x13
        add x10, x0, x18              #rk base / AES key survivor from setup
        lw  x11, 20(x3)               # P1 buffer base from frame slot 20
#ifdef AES_INSTRUCTIONS
        jal x1, aes128hw_352
#else
        jal x1, aes128table_352
#endif
        lw x4, 20(x3)                    #col 0
        bn.lid x23, 0(x4)                #  col_lo32 directly
        bn.lid x24, 32(x4)               #
        bn.and w8, w8, w29               # col_hi12 = KS1 & mask12
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
        bne x17, x0, VxO_col1
        jal x1, gen_newVxO_element
        VxO_col1:
        bn.lid x23, 32(x4)              #col 1
        bn.lid x24, 64(x4)
        bn.rshi w7, w8, w7 >> 96        # col_lo32 in-place
        bn.rshi w8, w31, w8 >> 96       # col_hi12 candidate
        bn.and w8, w8, w29              # mask to 12B
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
        # gate order: row 67 = 44 entries so x26=0 stays across many col1
        # visits. bne x17 first so beq fires only when x17=0 AND x26=0
        bne x17, x0, VxO_col2     # row not done, continue
        beq x0, x26, VxO_END      # row done, no more rows, exit
        jal x1, gen_newVxO_element  # row done, prep next row
        VxO_col2:
        bn.lid x23, 64(x4)               # col 2
        bn.lid x24, 96(x4)
        bn.lid x25, 128(x4)
        bn.rshi w7, w8, w7 >> 192       # col_lo32 = KS2[24..31]||KS3[0..23]
        bn.rshi w8, w9, w8 >> 192       # col_hi12 candidate
        bn.and w8, w8, w29              # mask
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
        bne x17, x0, VxO_col3
        jal x1, gen_newVxO_element
        VxO_col3:
        bn.lid x23, 128(x4)             #col 3
        bn.lid x24, 160(x4)
        bn.rshi w7, w8, w7 >> 32
        bn.rshi w8, w31, w8 >> 32
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
        bne x17, x0, VxO_col4
        jal x1, gen_newVxO_element
        VxO_col4:
        bn.lid x23, 160(x4)             #col 4
        bn.lid x24, 192(x4)
        bn.rshi w7, w8, w7 >> 128
        bn.rshi w8, w31, w8 >> 128
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
        bne x17, x0, VxO_col5
        jal x1, gen_newVxO_element
        VxO_col5:
        bn.lid x23, 192(x4)           #col 5
        bn.lid x24, 224(x4)
        bn.lid x25, 256(x4)
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
        bne x17, x0, VxO_col6
        jal x1, gen_newVxO_element
        VxO_col6:
        bn.lid x23, 256(x4)          #col 6
        bn.lid x24, 288(x4)
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
        bne x17, x0, VxO_col7
        jal x1, gen_newVxO_element
        VxO_col7:
        bn.lid x23, 288(x4)         #col 7
        bn.lid x24, 320(x4)
        bn.rshi w7, w8, w7 >> 160       # col_lo32
        bn.rshi w8, w31, w8 >> 160      # col_hi12 w31 top zero high no mask
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
        bne x17, x0, VxO_mul_loop
        jal x1, gen_newVxO_element
        beq x0, x0, VxO_mul_loop
    VxO_END:    # start P3 init
    /* acc (w21/w22) complete after VxO; spill to ctx */
    li x5, 0x20
    bn.sd w21, 0(x5)
    li x5, 0x40
    bn.sd w22, 0(x5)
    la x5, vfk_x1
    lw x1, 0(x5)
    ret

.global backend_verify_p3_rows
backend_verify_p3_rows:
    la x5, vfk_x1
    sw x1, 0(x5)
    la x2, vfk_stack_end
    la x5, vfk_msb
    li x6, 17
    bn.lid x6, 0(x5)          /* w17 = msb_mask */
    la x5, vfk_upper12
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
    li x4, 0x180             /* P3 window (16B prefix + packed entries) */
    li x26, 44
    sub x26, x26, x9         /* geometry rows: 44 - row_start */
    /* x8 = row_count (from outer) is the independent terminator */
    jal x1, gen_newP3_element  /* row-0 coefs w28/w29, x17 = 44-row_start */
    P3_outer_loop:
        #load 12 aligned WDRs cpk[352N..352N+383] into w7..w16,w18,w19
        li x6, 7
        bn.lid x6++, 0(x4)          #w7
        bn.lid x6++, 32(x4)         #w8
        bn.lid x6++, 64(x4)         #w9
        bn.lid x6++, 96(x4)         #w10
        bn.lid x6++, 128(x4)        #w11
        bn.lid x6++, 160(x4)        #w12
        bn.lid x6++, 192(x4)        #w13
        bn.lid x6++, 224(x4)        #w14
        bn.lid x6++, 256(x4)        #w15
        bn.lid x6, 288(x4)          # w16 (skip w17 = msb mask)
        li x6, 18
        bn.lid x6++, 320(x4)        #w18
        bn.lid x6, 352(x4)          #w19
        addi x4, x4, 352
        P3_col0:                  #entry 0 bytes [16..59]
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
        bne x17, x0, P3_col1
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col1:                  #entry 1 bytes [60..103]
        bn.mov w2, w28
        bn.rshi w1, w9, w8 >> 224
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w10, w9 >> 224
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col2
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col2:                  #entry 2 bytes [104..147]
        bn.mov w2, w28
        bn.rshi w1, w11, w10 >> 64
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w11 >> 64
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col3
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col3:                  #entry 3 bytes [148..191]
        bn.mov w2, w28
        bn.rshi w1, w12, w11 >> 160
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w12 >> 160
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col4
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col4:                  #entry 4 bytes [192..235]
        bn.mov w2, w28
        bn.mov w1, w13
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.and w1, w14, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col5
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col5:                  #entry 5 bytes [236..279]
        bn.mov w2, w28
        bn.rshi w1, w15, w14 >> 96
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w15 >> 96
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col6
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col6:                  #entry 6 bytes [280..323]
        bn.mov w2, w28
        bn.rshi w1, w16, w15 >> 192
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w18, w16 >> 192
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_col7
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        P3_col7:                  #entry 7 bytes [324..367]
        bn.mov w2, w28
        bn.rshi w1, w19, w18 >> 32
        jal x1, gf256_mul
        bn.xor w21, w21, w0
        bn.rshi w1, w31, w19 >> 32
        bn.and w1, w1, w30
        jal x1, gf256_mul
        bn.xor w22, w22, w0
        bn.rshi w28, w29, w28 >> 8
        bn.rshi w29, w31, w29 >> 8
        addi x17, x17, -1
        bne x17, x0, P3_outer_loop
        addi x8, x8, -1        # one requested row done
        beq x8, x0, P3_done    # all row_count rows folded
        jal x1, gen_newP3_element
        beq x0, x0, P3_outer_loop
    P3_done:
    li x5, 0x20
    bn.sd w21, 0(x5)          /* acc lo -> ctx */
    li x5, 0x40
    bn.sd w22, 0(x5)
    la x5, vfk_x1
    lw x1, 0(x5)
    ret

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
    li x17, 44                           # row size const for VxO (vs V-i in VxV)
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

/* ov-Ip3-keygen_stream_gfsw.s - streamed UOV-Ip3 keygen, software-GF arms.
 * Streamed UOV-Ip3 keygen (v=74, o=45, WJ=5), software-GF arms:
 *   -DAES_INSTRUCTIONS: aesonly (HW AES via expand_360_table/aes128hw_384_sign)
 *   (none):             sw (T-table AES; INIT derives rkbuf via AES_128_keyschedule)
 *   phase 0 INIT  : expandsk(sk_seed@0x20) -> pk_seed@0x40 + padded O ctx [+ rkbuf]
 *   phase 1 WINDOW(arg0=col_start, arg1=1<=col_count<=5): slice[k][j] =
 *           sum_i O[i][k]*B[i][col_start+j], B = P1*O+P2 restreamed.
 * WINDOW requires a prior INIT (pk_seed stored zero-extended to 32 B).
 * Fixed slice: entry (k,j) at slice + k*320 + j*64 (45B valid + 19B pad).
 * P2 stream: g = 2775 + 45*row + col; b=g>>3, slot=g&7; x13 = floor(45*b/2),
 * x16 = b&1 (expand_360_table grid). 9 windows of 5. No mod0/mod1 use;
 * mod1 pinned 0 on every phase exit. clob: everything (phase app, no caller).
 * stack: INIT expandsk frame via p1buf (4,352B); WINDOW x2 = swstack_end
 * (expand_360_table 448B frame). Whole map bus-visible, < 31,744 B.
 */
.section .data
.balign 32
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
slice:     .zero 14400
slice_end:
o_aligned: .zero 4320
p1buf:     .zero 5120
group_buf: .zero 1280
frame:     .zero 32
#ifndef AES_INSTRUCTIONS
rkbuf:     .zero 192
#endif
swstack:   .zero 448
swstack_end:
p2buf:     .zero 1024

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _WINDOW
    jal  x0, _bad_args

/* ============================ INIT ============================ */
_INIT:
    bn.xor w31, w31, w31
    la x2, group_buf          /* p1buf_end; expandsk frame grows down */
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid, high zero) */
#ifndef AES_INSTRUCTIONS
    /* SW AES key schedule once: pk_seed -> rkbuf (DMEM persists).
     * Clobbers x5-x8, x12-x18, x29-x31 -> runs BEFORE the O-copy setup;
     * x2 (expandsk frame, O source) is preserved. */
    la x10, pk_seed
    la x11, rkbuf
    jal x1, AES_128_keyschedule
#endif
    addi x12, x2, 32
    la x11, o_aligned
    li x6, 0
    loopi 135, 2
        bn.lid x6, 0(x12++)
        bn.sid x6, 0(x11++)
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x8, 4(x0)              /* col_start */
    lw x5, 8(x0)              /* col_count (x18 = key/RK survivor) */
    sw x8, 4(x3)
    beq x5, x0, _bad_args
    or   x30, x8, x5          /* pre-gate cs|cc < 64: the signed-trick */
    srli x30, x30, 6          /* checks below wrap on huge inputs */
    bne  x30, x0, _bad_args
    addi x30, x5, -6     /* col_count <= 5 */
    srli x30, x30, 31
    beq  x30, x0, _bad_args
    li   x30, 44           /* col_start <= 44 */
    sub  x30, x30, x8
    srli x30, x30, 31
    bne  x30, x0, _bad_args
    add  x30, x8, x5
    li   x29, 45             /* col_start + col_count <= 45 */
    sub  x29, x29, x30
    srli x29, x29, 31
    bne  x29, x0, _bad_args
    bn.xor w31, w31, w31
    la x6, o_aligned
    sw x6, 0(x3)              /* true O base (fold) */
    slli x7, x8, 6
    slli x30, x8, 5
    add  x7, x7, x30          /* col_start*96 */
    add  x6, x6, x7
    sw x6, 16(x3)             /* window O base (col walk via setup) */
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    la x2, swstack_end        /* expand_360_table descends 448 from here */
#ifdef AES_INSTRUCTIONS
    la x18, pk_seed           /* raw 16-B AES key; leaf restores x10 from x18 */
#else
    la x18, rkbuf             /* RK base; leaf restores x10 from x18 */
#endif
    /* macc consts (persist: expand_360_table preserves w16..w31) */
    li x9, 16
    la x14, msb_mask
    bn.lid x9, 0(x14)         /* w16 = 0x80 per byte */
    bn.addi w17, w31, 0x1b    /* w17.0 = reduction constant */
    /* WDR-index GPR constants */
    li x23, 6
    li x26, 3
    li x27, 4
    li x28, 5
    /* zero the FULL 5-wide slice (fixed-320 layout, all windows) */
    la x10, slice
    li x8, 450
    loop x8, 1
        bn.sd w31, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 18, 363
    jal x1, phase4_row_setup
    add x20, x0, x8
    li x24, 7
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_0
    jal x1, expand_batch
_bskip_0:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_0
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_0:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_1
    jal x1, expand_batch
_bskip_1:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 320
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_1
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_1:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_2
    jal x1, expand_batch
_bskip_2:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 640
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_2
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_2:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_3
    jal x1, expand_batch
_bskip_3:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 960
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_3
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_3:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -4
    li x30, 96
    li x29, 320
    li x19, 20
    li x17, 30
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    lw x22, 0(x3)
    add x22, x22, x21
    loop x5, 49
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 320(x12)
      addi x8, x8, 1
      bn.lid x8, 352(x12)
      addi x8, x8, 1
      bn.lid x8, 640(x12)
      addi x8, x8, 1
      bn.lid x8, 672(x12)
      addi x8, x8, 1
      bn.lid x8, 960(x12)
      addi x8, x8, 1
      bn.lid x8, 992(x12)
      add x4, x0, x22
      add x10, x0, x11
      loopi 45, 28
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        bn.ld w14, 0(x24)
        bn.lid x19, 0(x10)
        bn.lid x17, 32(x10)
        bn.mov w0, w2
        bn.mov w1, w3
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w4
        bn.mov w1, w5
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w6
        bn.mov w1, w7
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w8
        bn.mov w1, w9
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.sd w20, 0(x10)
        bn.sd w30, 32(x10)
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    /* ---- tail: rows 72,73 (2-MAC fold; slack bytes 74/75 unused) ---- */
    jal x1, phase4_row_setup
    add x20, x0, x8
    li x24, 7
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_T0
    jal x1, expand_batch
_bskip_T0:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_T0
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_T0:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    andi x16, x30, 1
    slli x29, x30, 5
    slli x8,  x30, 3
    add  x29, x29, x8
    slli x8,  x30, 2
    add  x29, x29, x8
    add  x29, x29, x30
    srli x13, x29, 1
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x5
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_T1
    jal x1, expand_batch
_bskip_T1:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 320
    loop x5, 29
        add x14, x0, x4
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_T1
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_T1:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    addi x7, x7, 1
    addi x21, x7, -2
    li x30, 96
    li x29, 320
    li x19, 20
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    lw x22, 0(x3)
    add x22, x22, x21
    loop x5, 31
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 320(x12)
      addi x8, x8, 1
      bn.lid x8, 352(x12)
      add x4, x0, x22
      add x10, x0, x11
      loopi 45, 18
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        bn.ld w14, 0(x24)
        bn.lid x19, 0(x10)
        bn.lid x17, 32(x10)
        bn.mov w0, w2
        bn.mov w1, w3
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w4
        bn.mov w1, w5
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.sd w20, 0(x10)
        bn.sd w30, 32(x10)
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

_bad_args:
    csrrw x0, mod1, x0
    li x6, -2
    sw x6, 12(x0)
    ecall

/* expand_batch: 8 x 45B entries -> 8 x 64B slots at x11. x18 = key/RK
 * base (expand_360_table clobbers x10; x13/x16 chain across calls). */
expand_batch:
    add x10, x0, x18
    jal x1, expand_360_table
    bn.sd w0, 0(x11)
    bn.sd w1, 32(x11)
    bn.sd w2, 64(x11)
    bn.sd w3, 96(x11)
    bn.sd w4, 128(x11)
    bn.sd w5, 160(x11)
    bn.sd w6, 192(x11)
    bn.sd w7, 224(x11)
    bn.sd w8, 256(x11)
    bn.sd w9, 288(x11)
    bn.sd w10, 320(x11)
    bn.sd w11, 352(x11)
    bn.sd w12, 384(x11)
    bn.sd w13, 416(x11)
    bn.sd w14, 448(x11)
    bn.sd w15, 480(x11)
    addi x11, x11, 512
    ret

/* phase4_row_setup: P1 re-expand for row x7 (x13 grid ctr, x16 phase) */
phase4_row_setup:
    srli x29, x9, 3                    /* b = t_r / 8 */
    andi x15, x9, 7                    /* slot = t_r % 8 */
    andi x16, x29, 1                   /* phase = b & 1 */
    slli x30, x29, 5
    slli x8,  x29, 3
    add  x30, x30, x8
    slli x8,  x29, 2
    add  x30, x30, x8
    add  x30, x30, x29                 /* 45b */
    srli x13, x30, 1                   /* AES block counter */
    lw   x11, 20(x3)                   /* reset P1 buf write ptr */
    slli x29, x15, 6                   /* adjusted P1 read ptr BEFORE the */
    add  x29, x29, x11                 /* expands: expand_360_table (sw arm) */
    add  x4, x0, x29                   /* clobbers x15 (AES_128_encrypt); kept in x4 */
    li   x8, 74
    sub  x8, x8, x7                    /* elements = 74-r */
    add  x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3                     /* num batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    li   x8, 74
    sub  x8, x8, x7                    /* x8 = 74-r */
    ret

/* ov-Ip3-keygen_min_sw.s - one-shot UOV-Ip3 keygen, software-GF
 * arms, minimal DMEM (60,832B bus-visible aesonly, 65,120B sw). WJ=1: 45
 * windows re-expand P1 (more cycles, less DMEM); accumulator is the packed
 * 45B cpk payload, GPR word-written with masked head/tail words.
 *   -DAES_INSTRUCTIONS: aesonly (HW AES via expand_360_table/aes128hw_384_sign)
 *   (none):             sw (T-table AES; INIT derives rkbuf once)
 * Host contract: write sk_seed, EXECUTE, read cpk 46,591B + csk.
 * Fold per window col c: k >= c plain (masked) copies to the row-c segment;
 * k < c XOR-RMW slot(k,c). First touch each run = plain -> re-EXECUTE
 * without reload is clean.
 * Frame ext: +4 col_start | +32 wc | +36 seg_c | +40 c.
 * mod1 = 0 on exit. clob: everything (app, no caller).
 * stack: INIT expandsk frame inside p1buf (4,352B); WINDOW x2 = swstack_end
 * (expand_360_table 448B frame).
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid, high zero) */
cpk:       .zero 16           /* 32B-aligned; prefix copied at the end */
cpk_payload: .zero 46575      /* 1,035 x 45B packed upper-tri, GPR-written */
           .zero 8            /* over-read guard past cpk; stays zero */
.balign 32
slice:     .zero 2880         /* 45 rows x 64B: one column per window */
slice_end:
o_aligned: .zero 4320
p1buf:     .zero 5120
group_buf: .zero 256          /* 4 rows x 64B */
frame:     .zero 64
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
    /* window loop: runtime-init state in the frame extension */
    la   x3, frame
    sw   x0, 36(x3)           /* seg_c */
    sw   x0, 40(x3)           /* c = next col_start */
_wloop:
    la   x3, frame
    lw   x8, 40(x3)           /* col_start = c */
    li   x5, 1                /* 45 exact windows (WJ=1) */
    sw   x8, 4(x3)
    sw   x5, 32(x3)           /* wc: fold reads this */
    /* falls into the WINDOW body (post-validation) */
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
    li x31, 31
    li x23, 6
    li x24, 7
    li x25, 8
    li x6,  9
    li x26, 3
    li x27, 4
    li x28, 5
    /* zero the FULL 5-wide slice (fixed-320 layout, all windows) */
    la x10, slice
    li x8, 90
    loop x8, 1
        bn.sid x31, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 18, 374
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
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    bne x8, x0, _bskip_1
    jal x1, expand_batch
_bskip_1:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 64
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    bne x8, x0, _bskip_2
    jal x1, expand_batch
_bskip_2:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 128
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    bne x8, x0, _bskip_3
    jal x1, expand_batch
_bskip_3:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 192
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -4
    li x30, 96
    li x29, 64
    li x19, 20
    li x17, 30
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    loop x5, 51
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 64(x12)
      addi x8, x8, 1
      bn.lid x8, 96(x12)
      addi x8, x8, 1
      bn.lid x8, 128(x12)
      addi x8, x8, 1
      bn.lid x8, 160(x12)
      addi x8, x8, 1
      bn.lid x8, 192(x12)
      addi x8, x8, 1
      bn.lid x8, 224(x12)
      lw x4, 0(x3)
      add x4, x4, x21
      add x10, x0, x11
      loopi 45, 29
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
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
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    bne x8, x0, _bskip_T1
    jal x1, expand_batch
_bskip_T1:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 64
    loop x5, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -2
    li x30, 96
    li x29, 64
    li x19, 20
    li x17, 30
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    loop x5, 33
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 64(x12)
      addi x8, x8, 1
      bn.lid x8, 96(x12)
      lw x4, 0(x3)
      add x4, x4, x21
      add x10, x0, x11
      loopi 45, 19
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
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
    jal x0, _fold

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
    sw   x29, 28(x3)                   /* clobbers x15 (AES_128_encrypt) */
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
    lw   x12, 16(x3)                   /* window O col walk base */
    ret

/* One window = one column c. Fold it into the packed payload:
 * slot(k,c) = payload + seg_k + 45(c-k), seg_k = 45(45k - k(k-1)/2). */
_fold:
    la   x3, frame
    lw   x14, 40(x3)          /* c = this window's column */
    lw   x15, 36(x3)          /* seg_c = payload offset of row-c segment */
    la   x20, slice
    la   x12, cpk_payload
    slli x11, x14, 5
    slli x7,  x14, 3
    add  x11, x11, x7
    slli x7,  x14, 2
    add  x11, x11, x7
    add  x11, x11, x14        /* 45c */
    beq  x14, x0, _fold_ge    /* c = 0: nothing above the diagonal */
    /* k < c: XOR slot(k,c); walk from payload+45c with stride 45(44-k),
     * shrinking 45; source row k at slice + 64k. */
    add  x22, x12, x11        /* slot(0,c) */
    add  x24, x20, x0         /* slice row 0 */
    li   x9, 1980             /* 45*44 */
    li   x16, 0               /* XOR mode */
    loop x14, 4
        jal  x1, _slot_write  /* consumes 48B of the source row */
        addi x24, x24, 16     /* -> next row (64B stride) */
        add  x22, x22, x9
        addi x9, x9, -45
_fold_ge:
    /* k >= c: plain (masked) copies into the row-c segment, 45B each;
     * source rows c..44 at slice + 64k. */
    add  x22, x12, x15        /* payload + seg_c */
    slli x7, x14, 6
    add  x24, x20, x7         /* slice + 64c */
    li   x13, 45
    sub  x13, x13, x14        /* 45 - c entries */
    li   x16, -1              /* plain mode */
    loop x13, 3
        jal  x1, _slot_write
        addi x22, x22, 45
        addi x24, x24, 16
    /* seg_{c+1} = seg_c + 45(45-c); c += 1 */
    li   x7, 2025
    sub  x7, x7, x11
    add  x15, x15, x7
    addi x14, x14, 1
    sw   x14, 40(x3)
    sw   x15, 36(x3)
    li   x6, 45
    bne  x14, x6, _wloop
    /* cpk = pk_seed(16B) || packed payload (already in place) */
    la   x10, pk_seed
    la   x11, cpk
    lw   x12, 0(x10)
    sw   x12, 0(x11)
    lw   x12, 4(x10)
    sw   x12, 4(x11)
    lw   x12, 8(x10)
    sw   x12, 8(x11)
    lw   x12, 12(x10)
    sw   x12, 12(x11)
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    ecall

/* Write one 45B entry. in: x22 = dst byte address (any alignment), x24 = src
 * (4B-aligned, 48B readable), x16 = -1 plain / 0 XOR. out: x24 += 48.
 * clob: x10, x17, x19, x21, x23, x25-x30. 12 dst words: head (mask ~0 << 8a),
 * 10 full, tail (mask ~0 >> (24-8a)); v_i = u_{i-1} >> (32-8a) | u_i << 8a,
 * the >>32 case split as >>(31-8a) >>1. d ^= ((d & mode) ^ v) & mask:
 * mode -1 replaces the owned bytes, mode 0 XORs them; neighbours' bytes in
 * the shared head/tail words are never touched. */
_slot_write:
    andi x17, x22, 3
    slli x17, x17, 3          /* s = 8a */
    li   x19, 31
    sub  x19, x19, x17        /* 31 - s */
    andi x10, x22, -4         /* aligned write cursor */
    li   x21, -1
    sll  x21, x21, x17        /* head mask */
    li   x23, 24
    sub  x23, x23, x17
    li   x25, -1
    srl  x25, x25, x23        /* tail mask */
    lw   x27, 0(x24)          /* u0 */
    sll  x28, x27, x17        /* v0 (no carry-in) */
    lw   x29, 0(x10)
    and  x30, x29, x16
    xor  x30, x30, x28
    and  x30, x30, x21
    xor  x29, x29, x30
    sw   x29, 0(x10)
    addi x10, x10, 4
    addi x24, x24, 4
    add  x26, x27, x0         /* prev = u0 */
    loopi 10, 13
        lw   x27, 0(x24)
        srl  x28, x26, x19
        srli x28, x28, 1
        sll  x30, x27, x17
        or   x28, x28, x30    /* v_i */
        lw   x29, 0(x10)
        and  x30, x29, x16
        xor  x30, x30, x28
        xor  x29, x29, x30
        sw   x29, 0(x10)
        addi x10, x10, 4
        addi x24, x24, 4
        add  x26, x27, x0
    lw   x27, 0(x24)          /* u11: byte 44 + pad (masked) */
    srl  x28, x26, x19
    srli x28, x28, 1
    sll  x30, x27, x17
    or   x28, x28, x30
    lw   x29, 0(x10)
    and  x30, x29, x16
    xor  x30, x30, x28
    and  x30, x30, x25
    xor  x29, x29, x30
    sw   x29, 0(x10)
    addi x24, x24, 4
    ret

/* host interface for C (ACC_DECLARE_SYMBOL_ADDR): seed in, csk == seed, cpk out */
.globl sk_seed
.globl csk
.globl cpk

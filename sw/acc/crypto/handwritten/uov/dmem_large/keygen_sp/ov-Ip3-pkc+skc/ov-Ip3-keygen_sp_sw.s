/* ov-Ip3-keygen_sp_sw.s - one-shot UOV-Ip3 keygen, single pass over P1,
 * software GF (gf256 sw dots); the AES leaf decides the arm: expand_360_table
 * over the T-table (sw) or over aes128hw_384_sign (bnaesonly, -DAES_INSTRUCTIONS).
 * Every P1 row is expanded once and folded into all 45 oil columns; the P3
 * accumulator is the upper triangle in 64B cells (tri), packed in place into
 * the 45B cpk slots at the end through the masked slot writer. Host contract
 * as _min: write sk_seed, EXECUTE, read cpk 46,591B + csk. Bodies from
 * ov-Ip3-keygen_min_sw.s; stage 2 visits (k, c) in _min's order with
 * T column c resident, cell = tri(min(k,c), max(k,c)). Guard bytes after cpk
 * are re-zeroed after the pack (tri overlays them). mod1 = 0 on exit.
 * clob: everything (app, no caller). stack: INIT expandsk frame inside p1buf
 * (4,352B); the run uses x2 = swstack_end (expand_360_table 448B frame).
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid, high zero) */
cpk:       .zero 16           /* 32B-aligned; prefix copied at the end */
cpk_payload: .zero 80         /* 1,035 x 45B slots, packed in place at the end; the slots
                               * continue inside tri (payload ends at tri + 46,495) */
tri:       .zero 66240        /* 1,035 x 64B upper-tri cells, cell(a,b) at 64*(45a - a(a-1)/2 + b - a) */
tri_end:
o_aligned: .zero 4320
p1buf:     .zero 5120         /* also the expandsk frame in INIT (4,352B below group_buf) */
group_buf: .zero 2880         /* T rows of the current group, 45 x 64B per row */
group_row1: .zero 2880
group_row2: .zero 2880
group_row3: .zero 2880
frame:     .zero 64
#ifndef AES_INSTRUCTIONS
rkbuf:     .zero 192          /* T-table round keys, scheduled once in INIT */
#endif
swstack:   .zero 448          /* expand_360_table frame */
swstack_end:
p2buf:     .zero 3584         /* one P2 row: up to 7 batches of 8 entries; stage-2 scratch word */

.section .text.start
.balign 4
.global main
main:
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
    /* one-time setup (the _min window loop body, run once): col_start 0, 45 cols */
    la   x3, frame
    li   x8, 0
    sw   x8, 4(x3)            /* col_start */
    li   x5, 45
    sw   x5, 32(x3)           /* wc */
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
    /* zero the 66,240B triangle once (x31 = 31 set above) */
    la x10, tri
    li x8, 2070
    loop x8, 1
        bn.sid x31, 0(x10++)
    li x9, 0
    li x7, 0
    /* ---- 18 groups of 4 rows, rows 0..71 ---- */
    loopi 18, 398
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row1
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row2
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row3
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
    /* stage 2: T column c (4 rows, w2..) against O column k (word at row r0, one
     * byte per row via rshi), cell tri(min(k,c), max(k,c)) */
    addi x21, x7, -4
    li   x30, 96
    li   x19, 20
    li   x17, 30
    lw   x24, 24(x3)          /* p2buf: scratch word for the O bytes (dead between rows) */
    la   x12, group_buf
    la   x10, tri
    li   x20, 0
    loop x5, 82
      bn.ld w2, 0(x12)
      bn.ld w3, 32(x12)
      bn.ld w4, 2880(x12)
      bn.ld w5, 2912(x12)
      bn.ld w6, 5760(x12)
      bn.ld w7, 5792(x12)
      bn.ld w8, 8640(x12)
      bn.ld w9, 8672(x12)
      lw   x4, 0(x3)
      add  x4, x4, x21          /* O column 0, row r0 */
      li   x29, 2816            /* 64 x 44: cell(k,c) -> cell(k+1,c) for k = 0 */
      beq  x20, x0, _sp2_G_d       /* c = 0: nothing above the diagonal */
      loop x20, 30
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
        add  x10, x10, x29
        addi x29, x29, -64
_sp2_G_d:
      li   x8, 45
      sub  x8, x8, x20          /* k = c .. 44, contiguous cells */
      loop x8, 29
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
        addi x10, x10, 64
      addi x20, x20, 1
      addi x12, x12, 64
      la   x10, tri
      slli x8, x20, 6
      add  x10, x10, x8         /* cell(0, c+1) */
    nop
    /* ---- tail: rows 72, 73 (2-row group) ---- */
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 52
    srli x8, x8, 3            /* (off2 + 45 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row1
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
    /* stage 2: T column c (2 rows, w2..) against O column k (word at row r0, one
     * byte per row via rshi), cell tri(min(k,c), max(k,c)) */
    addi x21, x7, -2
    li   x30, 96
    li   x19, 20
    li   x17, 30
    lw   x24, 24(x3)          /* p2buf: scratch word for the O bytes (dead between rows) */
    la   x12, group_buf
    la   x10, tri
    li   x20, 0
    loop x5, 58
      bn.ld w2, 0(x12)
      bn.ld w3, 32(x12)
      bn.ld w4, 2880(x12)
      bn.ld w5, 2912(x12)
      lw   x4, 0(x3)
      add  x4, x4, x21          /* O column 0, row r0 */
      li   x29, 2816            /* 64 x 44: cell(k,c) -> cell(k+1,c) for k = 0 */
      beq  x20, x0, _sp2_T_d       /* c = 0: nothing above the diagonal */
      loop x20, 20
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
        add  x10, x10, x29
        addi x29, x29, -64
_sp2_T_d:
      li   x8, 45
      sub  x8, x8, x20          /* k = c .. 44, contiguous cells */
      loop x8, 19
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
        addi x10, x10, 64
      addi x20, x20, 1
      addi x12, x12, 64
      la   x10, tri
      slli x8, x20, 6
      add  x10, x10, x8         /* cell(0, c+1) */
    csrrw x0, mod1, x0
_pack:
    /* tri cells (64B stride) -> packed 45B slots through the masked writer, front to
     * back, in place (a slot's words end below its own cell for every s) */
    la   x24, tri
    la   x22, cpk_payload
    li   x16, -1              /* plain mode */
    li   x8, 1035
    loop x8, 3
        jal  x1, _slot_write  /* x24 += 48 */
        addi x22, x22, 45
        addi x24, x24, 16
    /* guard: 8B after the payload (offset 46,655, alignment 3) back to zero */
    lw   x9, -3(x22)
    li   x10, 0xffffff        /* keep the slot's last three bytes of that word */
    and  x9, x9, x10
    sw   x9, -3(x22)
    sw   x0, 1(x22)
    sw   x0, 5(x22)
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

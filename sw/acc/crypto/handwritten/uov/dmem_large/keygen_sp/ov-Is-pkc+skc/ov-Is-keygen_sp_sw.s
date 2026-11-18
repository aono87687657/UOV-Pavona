/* ov-Is-keygen_sp_sw.s - one-shot UOV-Is keygen (GF(16)), single pass over
 * P1, software GF (gf16_macc_sw dots); the AES leaf decides the arm: T-table
 * (sw, the 4 KiB table from the AES_table library) or aes128_mem (bnaesonly).
 * Every P1 row is expanded once and folded into all 64 oil columns (32 column
 * pairs); the packed 32B-slot payload is the P3 accumulator itself, zeroed once
 * per run, no slice, no fold. Host contract as _min: write sk_seed, EXECUTE,
 * read cpk 66,576B + csk. Bodies from ov-Is-keygen_min_sw.s. Stage 2:
 * per column c the four T rows (w2/w6/w7/w9) against O column pairs (k, k+1);
 * w20 is preloaded from the destination slot of each half, slot(min(k,c),
 * max(k,c)) then slot(min(k+1,c), max(k+1,c)): below c the slots step 32(63-k),
 * at/above c they step 32, an odd c has one straddling pair ending on the
 * diagonal. mod1 = 0 on exit. clob: everything (app, no caller).
 * stack: INIT overlays the payload end (expandsk 3,104B); run: frame + swframe.
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid) */
           .zero 16           /* payload must land 32B-aligned */
cpk:       .zero 16           /* pk_seed prefix (written at the end) */
cpk_payload: .zero 66560      /* 2,080 x 32B packed upper-tri = the accumulator; INIT's
                               * expandsk frame overlays its top 3,104B */
cpk_payload_end:
o_ctx:     .zero 3072
p1buf:     .zero 3072
group_buf: .zero 2048         /* T rows of the current 4-row group, 64 x 32B per row */
group_row1: .zero 2048
group_row2: .zero 2048
group_row3: .zero 2048
rkbuf:     .zero 192          /* AES round keys, scheduled once in INIT */
ivb:       .zero 32
frame:     .zero 64
swframe:   .zero 32           /* aes128_dual_table frame */
swframe_end:

.section .text.start
.balign 4
.global main
main:
_INIT:
    la x2, cpk_payload_end    /* expandsk overlays the payload end (3,104B), dead until zeroed */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3104; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid) */
    /* SW AES key schedule once: pk_seed -> rkbuf (DMEM persists).
     * Clobbers x5-x8, x11-x18, x29-x31 -> runs BEFORE the O copy. */
    la x10, pk_seed
    la x11, rkbuf
    jal x1, AES_128_keyschedule
    addi x4, x2, 32           /* raw O (3,072B) -> ctx */
    la x5, o_ctx
    li x6, 96
    li x17, 0
    loop x6, 2
        bn.lid x17, 0(x4++)
        bn.sid x17, 0(x5++)

    /* window loop: runtime-init state in the frame extension */
    la   x3, frame
    sw   x0, 36(x3)           /* seg_c */
    sw   x0, 40(x3)           /* c = next col_start */
    /* one-time setup (the _min window loop body, run once): col_start 0, 64 cols */
    la   x3, frame
    li   x5, 0
    li   x18, 64
    sw   x5, 4(x3)            /* col_start */
    sw   x18, 32(x3)          /* wc: the rows load their pair count from here */
    bn.xor w31, w31, w31
    la x6, o_ctx
    sw x6, 0(x3)              /* true O base (fold) */
    slli x4, x5, 5
    slli x7, x5, 4
    add  x4, x4, x7           /* col_start*48 */
    add  x6, x6, x4
    sw x6, 8(x3)              /* window O base */
    la x6, p1buf
    sw x6, 12(x3)             /* P1 row buffer */
    la x18, rkbuf             /* x18 = RK base, required by dual_table */
    la x2, swframe_end        /* dual_table pushes its 32B frame here */
    /* gf16_macc_sw mask: w16 = 0x88.. per nibble (monolith recipe) */
    bn.addi w16, w31, 0x88
    bn.rshi w15, w16, w31 >> 248
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 240
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 224
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 192
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 128
    bn.or   w16, w16, w15
    /* IV increment (+2 per dual-block) + P1 IV [1|0] parked in w0 */
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    bn.addi w0, w31, 1
    bn.rshi w0, w0, w31 >> 32
    /* WDR-index GPR constants (all in dual_table preserve set) */
    li x31, 31
    li x17, 2                 /* w2 = dual_table output */
    li x23, 6
    li x25, 8
    li x26, 3
    li x27, 4
    li x28, 5
    /* zero the 2,080-slot accumulator once (x31 = 31 set above) */
    la x10, cpk_payload
    li x4, 2080
    loop x4, 1
        bn.sid x31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    /* ---- 24 groups of 4 rows ---- */
    loopi 24, 618
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    li   x31, 31
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, group_buf
    lw x19, 32(x3)
    srli x19, x19, 1
    loop x19, 69
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_0
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_0:
        li x8, 96
        sub x8, x8, x7
        loop x8, 7
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_0
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_0:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    li   x31, 31
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, group_row1
    lw x19, 32(x3)
    srli x19, x19, 1
    loop x19, 69
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_1
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_1:
        li x8, 96
        sub x8, x8, x7
        loop x8, 7
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_1
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_1:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    li   x31, 31
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, group_row2
    lw x19, 32(x3)
    srli x19, x19, 1
    loop x19, 69
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_2
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_2:
        li x8, 96
        sub x8, x8, x7
        loop x8, 7
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_2
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_2:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x9, 12(x3)
    sw x7, 28(x3)
    loop x30, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    lw x7, 28(x3)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    slli x4, x7, 7
    lw   x5, 4(x3)
    slli x6, x5, 1
    add  x4, x4, x6
    li   x5, 9312
    add  x4, x4, x5
    la   x5, ivb
    li   x31, 31
    bn.sid x31, 0(x5)
    sw   x4, 0(x5)
    li   x6, 14
    bn.lid x6, 0(x5)
    bn.addi w15, w14, 1
    bn.rshi w18, w14, w31 >> 160
    bn.rshi w15, w15, w31 >> 32
    bn.or  w18, w18, w15
    lw x12, 8(x3)
    la x10, group_row3
    lw x19, 32(x3)
    srli x19, x19, 1
    loop x19, 69
        lw x9, 12(x3)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nsa_3
        loop x7, 3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
_nsa_3:
        li x8, 96
        sub x8, x8, x7
        loop x8, 7
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        beq x7, x0, _nsb_3
        loop x7, 2
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
_nsb_3:
        li x8, 96
        sub x8, x8, x7
        loop x8, 6
            bn.lid x23, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        sw x10, 20(x3)
        sw x12, 24(x3)
        sw x7,  28(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        lw x7,  28(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    addi x7, x7, 1
    addi x30, x30, -1
    /* stage 2: T column c (rows r0..r0+3 in w2/w6/w7/w9) against O column pairs
     * (k, k+1); w20 is preloaded from each half's destination slot in the payload */
    bn.mov w21, w0            /* park the P1 IV (the helper clobbers w0/w18/w19) */
    addi x21, x7, -4
    srli x20, x21, 1
    andi x20, x20, 2
    slli x20, x20, 3          /* nibble shift of rows r0..r0+3 inside the O word */
    la   x24, ivb
    la   x13, group_buf
    la   x11, cpk_payload     /* slot(0, c) */
    lw   x5, 32(x3)           /* 64 columns */
    li   x22, 0               /* c */
    loop x5, 167
      bn.ld w2, 0(x13)
      bn.ld w6, 2048(x13)
      bn.ld w7, 4096(x13)
      bn.ld w9, 6144(x13)
      lw   x4, 0(x3)
      srli x8, x21, 1
      andi x8, x8, -4
      add  x4, x4, x8         /* O column 0, the word holding rows r0..r0+3 */
      add  x10, x0, x11       /* d1 = slot(0, c) */
      li   x29, 2016          /* 32 x 63: slot(k,c) -> slot(k+1,c) at k = 0 */
      srli x14, x22, 1        /* pairs fully below c */
      beq  x14, x0, _pI
      loop x14, 49
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        bn.ld w20, 0(x10)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        add  x9, x10, x29         /* d2 = slot(k+1, c) */
        bn.ld w20, 0(x9)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x9)
        addi x4, x4, 96
        addi x29, x29, -32
        add  x10, x9, x29     /* next d1 = d2 + 32(63 - (k+1)) */
        addi x29, x29, -32
_pI:
      andi x14, x22, 1
      beq  x14, x0, _pII
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        bn.ld w20, 0(x10)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        add  x9, x10, x29         /* d2 = slot(c, c), the diagonal */
        bn.ld w20, 0(x9)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x9)
      addi x4, x4, 96
      addi x10, x9, 32        /* next d1 = slot(c, c+1) */
_pII:
      addi x14, x22, 1
      srli x14, x14, 1
      li   x15, 32
      sub  x14, x15, x14      /* pairs at/above c (0 only for c = 63) */
      beq  x14, x0, _pIII
      loop x14, 47
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        bn.ld w20, 0(x10)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)         /* w14 = O[r0..r0+3][k] nibbles */
        addi x9, x10, 32          /* d2 = slot(c, k+1) */
        bn.ld w20, 0(x9)
        bn.mov w0, w2
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w6
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w7
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.rshi w14, w31, w14 >> 4
        bn.mov w0, w9
        bn.mov w19, w14
        jal x1, gf16_macc_sw
        bn.sd w20, 0(x9)
        addi x4, x4, 96
        addi x10, x9, 32
_pIII:
      addi x22, x22, 1
      addi x13, x13, 32
      addi x11, x11, 32       /* slot(0, c+1) */
    bn.mov w0, w21
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    nop
    /* cpk = pk_seed(16B) || payload (already packed in place) */
    la   x5, pk_seed
    la   x6, cpk
    lw   x7, 0(x5)
    sw   x7, 0(x6)
    lw   x7, 4(x5)
    sw   x7, 4(x6)
    lw   x7, 8(x5)
    sw   x7, 8(x6)
    lw   x7, 12(x5)
    sw   x7, 12(x6)
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    ecall

/* host interface for C (ACC_DECLARE_SYMBOL_ADDR): seed in, csk == seed, cpk out */
.globl sk_seed
.globl csk
.globl cpk

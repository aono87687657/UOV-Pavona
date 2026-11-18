/* ov-Is-keygen_min_sw.s - one-shot UOV-Is keygen, sw tier, minimal
 * DMEM. WJ=2: 32 windows re-expand P1 (more cycles, less DMEM); T-table AES
 * + gf16_macc_sw dots; the 4 KiB table comes from the AES_table library
 * (the aesonly build links the hardware AES leaf instead).
 * Host contract: write sk_seed, EXECUTE, read cpk 66,576B + csk.
 * Fold-scatter into the packed 32B-entry upper-tri accumulator in place;
 * pk_seed prefix at the end. First touch each run = plain store ->
 * re-EXECUTE clean. Frame ext: +4 col_start | +32 wc | +36 seg_c | +40 c.
 * mod1 = 0 on exit. clob: everything (app, no caller).
 * stack: INIT overlays slice (expandsk 3,104B); WINDOW frame + swframe.
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid) */
           .zero 16           /* payload must land 32B-aligned */
cpk:       .zero 16           /* pk_seed prefix (written at the end) */
cpk_payload: .zero 66560      /* 2,080 x 32B packed upper-tri accumulator */
slice:     .zero 4096
slice_end:
o_ctx:     .zero 3072
p1buf:     .zero 3072
gbuf01:    .zero 128
rkbuf:     .zero 192
gbuf23:    .zero 128
ivb:       .zero 32
frame:     .zero 64
swframe:   .zero 32
swframe_end:

.section .text.start
.balign 4
.global main
main:
_INIT:
    la x2, slice_end          /* expandsk overlays the slice (3,104B) */
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
_wloop:
    la   x3, frame
    lw   x5, 40(x3)           /* col_start = c (stays even) */
    li   x18, 2               /* 64 % 2 == 0: 32 exact windows, no short one */
    sw   x5, 4(x3)
    sw   x18, 32(x3)          /* wc: body reloads + fold read this */
    /* falls into the spliced WINDOW body (post-validation) */
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
    /* zero the FULL slice */
    la x10, slice
    li x4, 128
    loop x4, 1
        bn.sid x31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    loopi 24, 520
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
    la x10, gbuf01
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
    la x10, gbuf01
    addi x10, x10, 64
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
    la x10, gbuf23
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
    la x10, gbuf23
    addi x10, x10, 64
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
    bn.mov w21, w0
    addi x21, x7, -4
    srli x20, x21, 1
    andi x20, x20, 2
    slli x20, x20, 3
    la x24, ivb
    la x13, gbuf01
    la x14, gbuf23
    la x11, slice
    lw x5, 32(x3)
    loop x5, 67
      li x8, 2
      bn.lid x8, 0(x13)
      li x8, 6
      bn.lid x8, 64(x13)
      li x8, 7
      bn.lid x8, 0(x14)
      li x8, 9
      bn.lid x8, 64(x14)
      lw x4, 0(x3)
      srli x8, x21, 1
      andi x8, x8, -4
      add x4, x4, x8
      add x10, x0, x11
      loopi 32, 50
        lw x8, 0(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        li x8, 20
        bn.lid x8, 0(x10)
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
        li x8, 20
        bn.sid x8, 0(x10)
        lw x8, 48(x4)
        srl x8, x8, x20
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        li x8, 20
        bn.lid x8, 64(x10)
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
        li x8, 20
        bn.sid x8, 64(x10)
        addi x4, x4, 96
        addi x10, x10, 128
      addi x11, x11, 32
      addi x13, x13, 32
      addi x14, x14, 32
    bn.mov w0, w21
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    jal  x0, _fold


/* ---- fold-scatter: slice window cols -> packed upper-tri accumulator ---- */
_fold:
    la   x3, frame
    lw   x14, 40(x3)          /* c = global col (cols strictly ascend) */
    lw   x15, 36(x3)          /* seg_c = payload offset of row-c segment */
    lw   x18, 32(x3)          /* col_count */
    la   x20, slice
    la   x21, cpk_payload
    li   x8, 0                /* WDR idx: w0 slice entry, w2 slot */
    li   x16, 2
_fold_j:
    beq  x14, x0, _fold_ge    /* c = 0: nothing above the diagonal */
    /* k < c: XOR into slot(k,c). Walk from slot(0,c) = payload + 32c;
     * stride 63*32 shrinking 32/step (row segments shorten). */
    slli x22, x14, 5
    add  x22, x21, x22
    add  x24, x20, x0
    li   x23, 2016
    loop x14, 7
        bn.lid x8, 0(x24)
        bn.lid x16, 0(x22)
        bn.xor w2, w2, w0
        bn.sid x16, 0(x22)
        addi x24, x24, 64
        add  x22, x22, x23
        addi x23, x23, -32
_fold_ge:
    /* k >= c: plain store to slot(c,k) - contiguous row-c segment */
    add  x22, x21, x15
    li   x25, 64
    sub  x25, x25, x14
    slli x26, x14, 6
    add  x24, x20, x26        /* slice + c*64 (this col) */
    loop x25, 4
        bn.lid x8, 0(x24)
        bn.sid x8, 0(x22)
        addi x24, x24, 64
        addi x22, x22, 32
    /* seg_{c+1} = seg_c + 32*(64-c); advance col */
    slli x26, x14, 5
    li   x27, 2048
    sub  x27, x27, x26
    add  x15, x15, x27
    addi x14, x14, 1
    addi x20, x20, 32
    addi x18, x18, -1
    bne  x18, x0, _fold_j
    sw   x14, 40(x3)          /* c == next col_start */
    sw   x15, 36(x3)
    li   x6, 64
    bne  x14, x6, _wloop
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

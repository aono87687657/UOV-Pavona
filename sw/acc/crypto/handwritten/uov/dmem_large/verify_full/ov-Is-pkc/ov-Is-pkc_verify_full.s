/* ov-Is-pkc_verify_full.s - one-shot UOV-Is verify (GF16, v=96, o=m=64,
 * sig 96B), whole cpk resident: host writes cpk (66,576B at 16 mod 32, so the
 * P3 entries after the 16B seed are 32B aligned), msg_len, msg, sig; ONE
 * EXECUTE; reads result: 0 accept, -1 reject, -2 msg_len > 1,024, -5 while
 * running. Bodies are the streamed kernel's INIT (KMAC target + P1/P2 -> acc),
 * UPDATE (P3 fold, one pass over all 64 rows) and FINAL, in that order; the
 * seed is copied from the cpk prefix and the oil vector from sig[48..79] by
 * the kernel. The P3 pass reads exactly the key: no padding.
 * Map: hdr@0 acc@0x20 oil@0x40 target@0x60 sig@0x80 seed@0xE0 msg@0x100
 * cpk@0x510 (bngfonly: AES consts after it).
 * clob: everything (app, no caller). stack: none (round keys stay in w5-w14
 * in the bngfonly INIT); call depth 1.
 */
#if defined(AES_INSTRUCTIONS) && !defined(GF_INSTRUCTIONS)
#error "gfhw source: -DAES_INSTRUCTIONS alone still builds the FULL bngfaes kernel (GF_INSTRUCTIONS is inert here), so a _bnaesonly target aimed at this file reports bngfaes cycles under a software-GF name. Build ov-Is-pkc_verify_full_sw.s for that tier."
#endif
.section .data
.balign 32
hdr:       .zero 32              /* 0x000: +4 msg_len (host), +12 result (kernel) */
accctx:    .zero 32              /* 0x020 acc, INIT -> P3 pass -> FINAL */
oil:       .zero 32              /* 0x040 sig[48..79], written by INIT's tail */
target:    .zero 32              /* 0x060 KMAC digest, INIT -> FINAL */
sig:       .zero 96              /* 0x080: 96B sig (host) */
seed:      .zero 32              /* 0x0E0: cpk[0:16] zero-extended, written at entry */
msg:       .zero 1024            /* 0x100: 32B granules, zero tail */
           .zero 16              /* 0x500: puts the P3 entries on 32B */
cpk:       .zero 16              /* 0x510: 66,576B key = 16B seed + P3 */
cpk_p3:    .zero 66560           /* 0x520: 2,080 entries of 32B */
#ifndef AES_INSTRUCTIONS
/* bngfonly: AES constants, referenced by name by the INIT and AES_bngf. */
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
#endif

.section .text.start
.balign 4
.global main
main:
    li   x3, 0x00
    li   x6, -5
    sw   x6, 12(x3)           /* result = running */
    lw   x14, 4(x3)           /* msg_len */
    srli x5, x14, 15          /* wrap-safe: len >= 2^15 first */
    bne  x5, x0, _len_bad
    li   x5, 1024
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _len_bad     /* len > 1,024 */
    /* seed := cpk[0:16], zero-extended to the 32B word the bodies read */
    la   x10, cpk
    li   x12, 0x0E0
    lw   x5, 0(x10)
    sw   x5, 0(x12)
    lw   x5, 4(x10)
    sw   x5, 4(x12)
    lw   x5, 8(x10)
    sw   x5, 8(x12)
    lw   x5, 12(x10)
    sw   x5, 12(x12)
    sw   x0, 16(x12)
    sw   x0, 20(x12)
    sw   x0, 24(x12)
    sw   x0, 28(x12)
    jal  x0, _INIT
_len_bad:
    li   x6, -2
    jal  x0, _done

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)          /* msg_len */
    li   x10, 0x080          /* sig */
    li   x12, 0x0E0          /* seed */
    li   x13, 0x100          /* msg */

    bn.xor w31, w31, w31
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5

    bn.ld w1, 64(x10)         /* salt */
    bn.rshi w1, w31, w1 >> 128

    beq  x14, x0, _msg_zero
    srli x5, x14, 5
    andi x6, x14, 0x1f
    beq  x5, x0, _msg_short
    loop x5, 27
        bn.lid x0, 0(x13++)
        bn.wsrw kmac_msg, w0
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    beq  x6, x0, _msg_zero
_msg_short:
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x13++)
    bn.wsrw kmac_msg, w0
_msg_zero:
    li   x5, 16
    csrrw x0, kmac_partial_write, x5
    bn.wsrw kmac_msg, w1

#ifdef AES_INSTRUCTIONS
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

#else /* bngfonly: compute-AES engine, from ov-Is-verify_backend.s bngf arm */
    csrrw x0, mod1, x0
    li   x10, 0x80            /* sig */
    li   x12, 0xE0            /* seed = AES key */
    bn.xor w31, w31, w31
    bn.wsrw acc, w31
    bn.xor w0, w0, w0

    /* counter increment const */
    bn.addi w15, w31, 0x2
    bn.or w15, w15, w15 << 128
    bn.rshi w15, w15, w31 >> 160
    /* byte swap mask */
    bn.addi w30, w31, 0xff
    bn.or w30, w30, w30 << 128
    bn.rshi w30, w30, w31 >> 160

    /* AES key from seed into w28 */
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

    /* IV in w29 for AES128-CTR */
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 224
    li x5, 5
    li x6, 28
    loopi 10, 2
        jal x1, KeySchedule
        bn.movr x5++, x6      /* rk WDR-resident: w5..w14 */
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

    /* VxV: vinegar x0-x95 into w1,w2 */
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
            bn.wsrw acc, w0   /* aes128 clobbers WSR acc: re-arm from w0 */
            csrrw x0,mod0,x30 /* aes128 leaves mod0=0x11b: re-pin GF16 */
            bn.gfmul.4.acc w0, w27, w3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.rshi w1, w2, w1 >> 4
        bn.rshi w2, w31, w2 >> 4
        addi x31, x31, -1

    /* VxO */
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
#endif

    bn.wsrr w8, 0xA
    li   x3, 0x60
    bn.sd w8, 0(x3)          /* target */
    li   x3, 0x20
    bn.sd w0, 0(x3)          /* acc -> P3 pass */
    /* oil := sig[48..79], the 64 oil nibbles the P3 body reads */
    li   x3, 0x080
    bn.ld w5, 32(x3)          /* sig 32..63 */
    bn.ld w6, 64(x3)          /* sig 64..95 */
    bn.rshi w5, w6, w5 >> 128 /* bytes 48..79 */
    li   x3, 0x040
    bn.sd w5, 0(x3)

/* ---------------- P3 pass: the UPDATE body, rows 0..63 in one go ---------------- */
    li   x3, 0x00
    li   x7, 0                /* row_start */
    li   x8, 64               /* row_count */
    li     x9, 0x20
    bn.ld  w0, 0(x9)          /* acc_in */

    li     x9, 64
    sub    x7, x9, x7         /* first_row_size = o - row_start */

    li     x31, 0x13
    csrrw  x0, mod0, x31
    csrrw  x0, mod1, x0
    bn.xor w31, w31, w31
    bn.wsrw acc, w0

    li     x9, 0x40
    bn.ld  w6, 0(x9)          /* oil (aligned to row_start) */
    la     x12, cpk_p3        /* resident P3: 2,080 aligned 32B entries */
    li     x30, 30
    loop   x8, 7
        bn.gfmul.4 w5, w6, w6
        loop x7, 3
            bn.lid x30, 0(x12++)
            bn.gfmul.4.acc w0, w30, w5
            bn.rshi w5, w31, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi   x7, x7, -1

    li     x9, 0x20
    bn.sd  w0, 0(x9)          /* acc_out */

/* ============================ FINAL ============================ */
    li   x3, 0x20
    bn.ld w0, 0(x3)          /* acc */
    li   x3, 0x60
    bn.ld w8, 0(x3)          /* target */
    bn.cmp w0, w8, FG0
    csrrs x5, 0x7c0, x0
    srli x5, x5, 3
    andi x5, x5, 1           /* Z flag: 1 if acc == target */
    li   x3, 0x00
    beq  x5, x0, _F_fail
    li   x6, 0
    jal  x0, _done
_F_fail:
    li   x6, -1
_done:
    li   x3, 0x000
    sw   x6, 12(x3)           /* result: 0 accept, -1 reject, -2 bad msg_len */
    csrrw x0, mod1, x0
    ecall

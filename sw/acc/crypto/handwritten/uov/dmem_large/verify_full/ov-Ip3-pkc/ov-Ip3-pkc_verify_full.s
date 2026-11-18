/* ov-Ip3-pkc_verify_full.s - one-shot UOV-Ip3 verify (R3: v=74, o=m=45,
 * sig 135B), whole cpk resident: host writes cpk (46,591B + 225B zero padding
 * the P3 loader over-reads), msg_len, msg, sig (135B in a 160B zero-tailed
 * slot); ONE EXECUTE; reads result: 0 accept, -1 reject, -2 msg_len > 1,024,
 * -5 while running. Bodies are the streamed kernel's INIT (KMAC target +
 * P1/P2 -> acc), UPDATE (P3 fold, one pass over all 45 rows) and FINAL, in
 * that order; the seed is copied from the cpk prefix and the oil vector from
 * sig[74..118] by the kernel, so no host window, oil or ctrl traffic remains.
 * Map: hdr@0 acc@0x20 oil@0x60 target@0xA0 sig@0xE0 seed@0x180 msg@0x1A0
 * cpk@0x5A0 (bngfonly: AES consts, rkbuf, blkbuf after it).
 * clob: everything (app, no caller). stack: none (x2 = rkbuf base in the
 * bngfonly INIT, load_p3_45 phase in the P3 pass); call depth 1.
 */
#if defined(AES_INSTRUCTIONS) && !defined(GF_INSTRUCTIONS)
#error "gfhw source: -DAES_INSTRUCTIONS alone still builds the FULL bngfaes kernel (GF_INSTRUCTIONS is inert here), so an _aesonly target aimed at this file reports bngfaes cycles under a software-GF name. Build _gfsw.s for that tier."
#endif
.section .data
.balign 32
hdr:       .zero 32              /* 0x000: +4 msg_len (host), +12 result (kernel) */
accctx:    .zero 64              /* 0x020 acc lo/hi, INIT -> P3 pass -> FINAL */
oil:       .zero 64              /* 0x060 sig[74..118] zero-padded, written by INIT's tail */
target:    .zero 64              /* 0x0A0 KMAC digest, INIT -> FINAL */
sig:       .zero 160             /* 0x0E0: 135B sig + zero tail (host writes 160 B) */
seed:      .zero 32              /* 0x180: cpk[0:16] zero-extended, written at entry */
msg:       .zero 1024            /* 0x1A0: 32B granules, zero tail */
cpk:       .zero 46816           /* 0x5A0: 46,591B key + 225B readable padding */
#ifndef AES_INSTRUCTIONS
/* bngfonly: AES constants (aes128_360_bngf / KeySchedule reference them by
 * name), forward-pushed round keys and the leaf's staging buffer, all in the
 * image (the streamed kernel keeps the last two above its bus window). */
.balign 32
rcon:
    .word 0x08040201, 0x80402010, 0x361b
    .zero 26
/* shiftrow_mask is la-resolved by AES_bngf/aes128_352.s; keep the symbol. */
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
.balign 32
rkbuf:     .zero 352             /* rk[0..10] forward-pushed, x2 base */
.global blkbuf
blkbuf:    .zero 384             /* aes128_360_bngf staging (leaf resolves the symbol) */
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
    li   x12, 0x180
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
    lw   x14, 4(x3)           /* msg_len */
    li   x10, 0x0E0          /* sig */
    li   x12, 0x180          /* seed */
    li   x13, 0x1A0          /* msg */

    /* ---------------- KMAC SHAKE256 over (msg || salt) ---------------- */
    bn.xor w31, w31, w31
    bn.xor w1, w1, w1
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5
    bn.ld w1, 96(x10)         /* sig bytes 96..127 */
    bn.ld w2, 128(x10)        /* sig bytes 128..159 (135-B sig: 128..134 live) */
    bn.rshi w1, w2, w1 >> 184 /* salt = bytes 119..134 */
    bn.rshi w1, w1, w31 >> 128
    bn.rshi w1, w31, w1 >> 128
    beq  x14, x0, _ipi_msg_zero
    srli x5, x14, 5
    andi x6, x14, 0x1f
    beq  x5, x0, _ipi_msg_short
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
    beq  x6, x0, _ipi_msg_zero
_ipi_msg_short:
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x13++)
    bn.wsrw kmac_msg, w0
_ipi_msg_zero:
    li   x5, 16
    csrrw x0, kmac_partial_write, x5
    bn.wsrw kmac_msg, w1

#ifdef AES_INSTRUCTIONS
    /* ---------------- publicmap setup (from ov-Ip-pkc_publicmap.s) ------------- */
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

#else /* bngfonly: compute-AES prologue; keys -> rkbuf, blocks
        spilled to blkbuf by aes128_360_bngf (same w8..w23 outputs) */
    li x10, 0xE0              /* sig */
    li x12, 0x180             /* seed = AES key */
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

    li x31, 30
    bn.lid x31, 0(x12)        /* AES key from seed */
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128

    /* w29 = LE-at-start dual counter (aes128_360 byte-swaps): blk0 ctr at
     * byte 0 = 0, blk1 at byte 16 = 1, zero nonce; helper self-increments */
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 128

    la x30, msb_mask
    li x31, 28
    bn.lid x31, 0(x30)        /* w28 = msb_mask, preserved by the helpers */
    la x30, affine_value
    li x31, 27
    bn.lid x31, 0(x30)        /* w27 = affine_value, preserved */
    la x30, rcon
    li x31, 26
    bn.lid x31, 0(x30)        /* w26 = rcon carrier; dead after the schedule */
    la   x2, rkbuf            /* rk base: aes128_360 reads via x2 */
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
#endif

    /* ---------------- VxV (P1) (from ov-Ip-pkc_publicmap.s) ------------------- */
    li   x16, 0               /* expansion phase: reset GPRs are URND on RTL */
    jal  x1, aes128_360
    li   x6, 0
    li   x7, 74
    li   x28, 8
    li   x29, 9
    li   x30, 8
    li x5, 0
    loopi 67, 85
        # scalar prep (per column, unchanged)
        bn.gfmul.8 w5, w2, w2
        bn.gfmul.8 w6, w3, w2
        bn.gfmul.8 w7, w4, w2
        # runtime split: h=(8-off)&7, rem=L-h, nb=rem>>3, t=rem&7
        li x31, 8
        sub x8, x31, x5
        andi x8, x8, 7
        sub x31, x7, x8
        srli x9, x31, 3
        andi x11, x31, 7
        beq x8, x0, ipi_vv_skip_head
        loop x8, 12
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc  w0, w8, w5
            bn.gfmul.8.acch w1, w9, w5
            addi x6, x6, 1
            bne x6, x28, ipi_vv_h_skip
                jal x1, aes128_360
                li x6, 0
                add x30, x0, x28
                ipi_vv_h_skip:bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
        ipi_vv_skip_head:
        beq x9, x0, ipi_vv_skip_mid
        loop x9, 41
            bn.gfmul.8.acc  w0, w8, w5
            bn.gfmul.8.acch w1, w9, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w10, w5
            bn.gfmul.8.acch w1, w11, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w12, w5
            bn.gfmul.8.acch w1, w13, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w14, w5
            bn.gfmul.8.acch w1, w15, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w16, w5
            bn.gfmul.8.acch w1, w17, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w18, w5
            bn.gfmul.8.acch w1, w19, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w20, w5
            bn.gfmul.8.acch w1, w21, w5
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
            bn.gfmul.8.acc  w0, w22, w5
            bn.gfmul.8.acch w1, w23, w5
            jal x1, aes128_360
            bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
        ipi_vv_skip_mid:
        beq x11, x0, ipi_vv_skip_tail
        loop x11, 12
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc  w0, w8, w5
            bn.gfmul.8.acch w1, w9, w5
            addi x6, x6, 1
            bne x6, x28, ipi_vv_t_skip
                jal x1, aes128_360
                li x6, 0
                add x30, x0, x28
                ipi_vv_t_skip:bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
        ipi_vv_skip_tail:
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        addi x7, x7, -1
        add x5, x0, x11
    /* columns 61..67 (L=7..1 < 8): original pure-cursor body */
    loopi 7, 20
        bn.gfmul.8 w5, w2, w2
        bn.gfmul.8 w6, w3, w2
        bn.gfmul.8 w7, w4, w2
        loop x7, 12
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc  w0, w8, w5
            bn.gfmul.8.acch w1, w9, w5
            addi x6, x6, 1
            bne x6, x28, ipi_vvskip
                jal x1, aes128_360
                li x6, 0
                add x30, x0, x28
                ipi_vvskip:bn.rshi w5, w6, w5 >> 8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1

    /* ---------------- VxO (P2) (from ov-Ip-pkc_publicmap.s) ------------------ */
    addi x31, x0, 2
    bn.lid x31++, 0(x10)
    bn.lid x31++, 32(x10)
    bn.lid x31++, 64(x10)
    bn.lid x31++, 96(x10)
    bn.rshi w6, w31, w5 >> 80   /* oil high: sig bytes 106..118 */
    bn.rshi w6, w6, w31 >> 104
    bn.rshi w6, w31, w6 >> 152
    bn.rshi w5, w5, w4 >> 80    /* oil low: sig bytes 74..105 */
    bn.rshi w4, w4, w31 >> 80   /* vinegar tail: bytes 64..73 */
    bn.rshi w4, w31, w4 >> 176
    loopi 9, 1525
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
        bn.gfmul.8 w24, w5, w2
        bn.gfmul.8 w25, w6, w2
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w22, w24
        bn.gfmul.8.acch w1, w23, w24
        jal x1, aes128_360
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w8, w24
        bn.gfmul.8.acch w1, w9, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w10, w24
        bn.gfmul.8.acch w1, w11, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w12, w24
        bn.gfmul.8.acch w1, w13, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w14, w24
        bn.gfmul.8.acch w1, w15, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w16, w24
        bn.gfmul.8.acch w1, w17, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w18, w24
        bn.gfmul.8.acch w1, w19, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.gfmul.8.acc  w0, w20, w24
        bn.gfmul.8.acch w1, w21, w24
        bn.rshi w24, w25, w24 >> 8
        bn.rshi w25, w31, w25 >> 8
        bn.rshi w2, w3, w2 >> 8
        bn.rshi w3, w4, w3 >> 8
        bn.rshi w4, w31, w4 >> 8
    /* rows 72..73: 74 = 9x8 + 2 */
    bn.gfmul.8 w24, w5, w2
    bn.gfmul.8 w25, w6, w2
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    bn.gfmul.8 w24, w5, w2
    bn.gfmul.8 w25, w6, w2
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w10, w24
    bn.gfmul.8.acch w1, w11, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w12, w24
    bn.gfmul.8.acch w1, w13, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w14, w24
    bn.gfmul.8.acch w1, w15, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w16, w24
    bn.gfmul.8.acch w1, w17, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w18, w24
    bn.gfmul.8.acch w1, w19, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w20, w24
    bn.gfmul.8.acch w1, w21, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w22, w24
    bn.gfmul.8.acch w1, w23, w24
    jal x1, aes128_360
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.gfmul.8.acc  w0, w8, w24
    bn.gfmul.8.acch w1, w9, w24
    bn.rshi w24, w25, w24 >> 8
    bn.rshi w25, w31, w25 >> 8
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8


    /* ---------------- read 44B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 104
    bn.rshi w14, w31, w14 >> 152
    li   x3, 0x0A0
    bn.sd w13, 0(x3)         /* target lo */
    bn.sd w14, 32(x3)        /* target hi */

    /* ---- spill acc (oil is NOT ctx: host rewrites 0x60 per UPDATE) ---- */
    li   x3, 0x020
    bn.sd w0, 0(x3)          /* acc lo */
    bn.sd w1, 32(x3)         /* acc hi */
    /* oil := sig[74..118] zero-padded to 64B: what the host wrote per window */
    li   x3, 0x0E0
    bn.ld w5, 64(x3)          /* sig 64..95 */
    bn.ld w6, 96(x3)          /* sig 96..127 */
    bn.ld w7, 128(x3)         /* sig 128..159 (zero tail) */
    bn.rshi w5, w6, w5 >> 80  /* bytes 74..105 */
    bn.rshi w6, w7, w6 >> 80  /* bytes 106..137 */
    bn.rshi w6, w6, w31 >> 104
    bn.rshi w6, w31, w6 >> 152 /* keep 13 bytes: 106..118 */
    li   x3, 0x060
    bn.sd w5, 0(x3)
    bn.sd w6, 32(x3)

/* ---------------- P3 pass: the UPDATE body, rows 0..44 in one go ---------------- */
    li   x3, 0x00
    li   x9, 0                /* row_start */
    li   x8, 45               /* row_count */
    li   x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0
    bn.xor w31, w31, w31

    li   x3, 0x20
    bn.ld w0, 0(x3)           /* acc_lo */
    bn.ld w1, 32(x3)          /* acc_hi */
    bn.wsrw acc, w0
    bn.wsrw acch, w1

    li   x3, 0x60
    bn.ld w5, 0(x3)           /* oil o_{row_start}.. */
    bn.ld w6, 32(x3)          /* oil high.. */

    li   x28, 8
    li   x29, 9
    la   x12, cpk             /* resident cpk: 16B prefix + 1,035 entries + padding */

    li   x7, 45
    sub  x7, x7, x9           /* first_row_size = o - row_start */

    /* ---- prefetch (absorbs 16B prefix) ---- */
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
    addi x12, x12, 192        /* aligned base of batch 0 */
    li   x2, 0                /* load_p3_45 phase */

    /* ---- main loop over row_count rows (no tail) ---- */
    li   x6, 4
    li   x30, 16
    loop x8, 87
        bn.gfmul.8 w24, w5, w5
        bn.gfmul.8 w25, w6, w5
        /* runtime L>=8 routing: (L & ~7)==0  <=>  L<8 -> pure */
        andi x5, x7, -8
        beq x5, x0, ipw_oxo_pure
        /* hybrid: off=x6, h=(8-off)&7, nb=(L-h)>>3, t=(L-h)&7 */
        li x15, 8
        sub x10, x15, x6
        andi x10, x10, 7
        sub x14, x7, x10
        srli x11, x14, 3
        andi x13, x14, 7
        beq x10, x0, ipw_oxo_sh
        loop x10, 11
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w8, w24
            bn.gfmul.8.acch w1, w9, w24
            addi x6, x6, 1
            bne x6, x28, ipw_oxo_h
                jal x1, load_p3_45
                li x6, 0
                add x30, x0, x28
                ipw_oxo_h:bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
        ipw_oxo_sh:
        beq x11, x0, ipw_oxo_sm
        loop x11, 33
            bn.gfmul.8.acc w0, w8, w24
            bn.gfmul.8.acch w1, w9, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w10, w24
            bn.gfmul.8.acch w1, w11, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w12, w24
            bn.gfmul.8.acch w1, w13, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w14, w24
            bn.gfmul.8.acch w1, w15, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w16, w24
            bn.gfmul.8.acch w1, w17, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w18, w24
            bn.gfmul.8.acch w1, w19, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w20, w24
            bn.gfmul.8.acch w1, w21, w24
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
            bn.gfmul.8.acc w0, w22, w24
            bn.gfmul.8.acch w1, w23, w24
            jal x1, load_p3_45
            bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
        ipw_oxo_sm:
        beq x13, x0, ipw_oxo_st
        loop x13, 11
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w8, w24
            bn.gfmul.8.acch w1, w9, w24
            addi x6, x6, 1
            bne x6, x28, ipw_oxo_t
                jal x1, load_p3_45
                li x6, 0
                add x30, x0, x28
                ipw_oxo_t:bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
        ipw_oxo_st:
        beq x0, x0, ipw_oxo_done
        ipw_oxo_pure:
        loop x7, 11
            bn.movr x28, x30++
            bn.movr x29, x30++
            bn.gfmul.8.acc w0, w8, w24
            bn.gfmul.8.acch w1, w9, w24
            addi x6, x6, 1
            bne x6, x28, ipw_ooskip
                jal x1, load_p3_45
                li x6, 0
                add x30, x0, x28
                ipw_ooskip:bn.rshi w24, w25, w24 >> 8
            bn.rshi w25, w31, w25 >> 8
        ipw_oxo_done:
        bn.rshi w5, w6, w5 >> 8
        bn.rshi w6, w31, w6 >> 8
        addi x7, x7, -1

_ipw_done:
    li   x3, 0x20
    bn.sd w0, 0(x3)           /* acc_lo */
    bn.sd w1, 32(x3)          /* acc_hi */

/* ============================ FINAL ============================ */
    li   x3, 0x020
    bn.ld w0, 0(x3)          /* acc_lo */
    li   x3, 0x040
    bn.ld w1, 0(x3)          /* acc_hi */
    li   x3, 0x0A0
    bn.ld w13, 0(x3)         /* target_lo */
    li   x3, 0x0C0
    bn.ld w14, 0(x3)         /* target_hi */
    bn.cmp w0, w13, FG0
    bn.cmp w1, w14, FG1
    csrrs x5, 0x7c0, x0
    csrrs x6, 0x7c1, x0
    and  x5, x5, x6
    srli x5, x5, 3
    andi x5, x5, 1
    li   x3, 0x000
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

/* UOV-Ip streamed verify: ONE app, phase-dispatch, DMEM-persistent.
 * phase 0 INIT (KMAC target + P1/P2 -> dual acc), 1 UPDATE (fold P3 window),
 * 2 FINAL (dual-acc compare -> ctrl.status). ctx {acc64,target64} in DMEM;
 * oil@0x60 is a per-UPDATE host input, rewritten each window so byte 0 = o[row_start].
 * Layout: ctrl@0 acc@0x20 oil@0x60 target@0xA0 sig@0xE0 seed@0x160 msg/window@0x180.
 * aes128_352 + load_p3 linked from ../ov-Ip-pkc/AES_bngfaes (bngfaes tier helpers).
 * clob: everything (phase app, no caller).
 * stack: none (x2 unused); call depth 1 - x1 into aes128_352/load_p3, both leaves.
 */
#if defined(AES_INSTRUCTIONS) && !defined(GF_INSTRUCTIONS)
#error "gfhw source: -DAES_INSTRUCTIONS alone still builds the FULL bngfaes kernel (GF_INSTRUCTIONS is inert here), so an _aesonly target aimed at this file reports bngfaes cycles under a software-GF name. Build _gfsw.s for that tier."
#endif
#ifndef AES_INSTRUCTIONS
/* bngfonly arm data. The bngfaes arm addresses the host map absolutely and
 * carries no .data; here the same map is named so the AES constants land
 * above the window and the ELF exports the bound. */
.section .data
.balign 32
ctrl:      .zero 32              /* 0x000 phase, arg0, arg1, status */
accctx:    .zero 64              /* 0x020 acc lo/hi ctx */
oil:       .zero 64              /* 0x060 host-rewritten per UPDATE */
target:    .zero 64              /* 0x0A0 ctx */
sig:       .zero 128             /* 0x0E0 */
seed:      .zero 32              /* 0x160 */
/* msg / P3-window overlay. Sized to the MAX UPDATE read end incl. load_p3
 * refill overshoot (63 refills, 192 + 63*352 = 22,368 B) - same bound as the
 * stream_uniform outer, not the host's 13/31 split. */
.global msgwin
msgwin:    .zero 22368           /* 0x180 .. 0x58e0 */
.global winend
winend:
/* Largest row_count per row_start that still fits msgwin, refill overshoot
 * included. UPDATE rejects rc > caprows[rs] with -2: past winend the row
 * loop would fold this table and the AES constants into the accumulator and
 * return a wrong verdict instead of an error. */
caprows:
    .word 13, 13, 14, 14, 15, 16, 16, 17
    .word 18, 19, 21, 22, 25, 31, 30, 29
    .word 28, 27, 26, 25, 24, 23, 22, 21
    .word 20, 19, 18, 17, 16, 15, 14, 13
    .word 12, 11, 10, 9, 8, 7, 6, 5
    .word 4, 3, 2, 1
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
.global MixColMat
.balign 32
MixColMat:
    .word 0x03010102, 0x01010203, 0x01020301, 0x02030101
    .zero 16
/* ACC-private scratch above the 31,744 B bus window: an address, no load
 * image; never host-read and rk-pushed before read, which makes it legal. */
.set rkbuf, 31744                /* 352 B, rk[0..10] forward-pushed, x2 base */
#endif

.section .text.start
.balign 4
.global main
main:
    li   x3, 0x00
    lw   x4, 0(x3)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _UPDATE
    li   x5, 2
    beq  x4, x5, _FINAL
    li   x6, -2              /* invalid phase -> error status */
    sw   x6, 12(x3)
    ecall

_FINAL:
#ifndef AES_INSTRUCTIONS
    /* acc/target come up as loader-written .data zeros, so FINAL before INIT
     * would compare 0 == 0 and ACCEPT. Sentinel, set by INIT. */
    lw   x5, 16(x0)
    li   x6, 0x517
    bne  x5, x6, _ipf_noinit
#endif
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
    sw   x6, 12(x3)          /* status = 0 (accept) */
    ecall
_F_fail:
    li   x6, -1
    sw   x6, 12(x3)          /* status = -1 (reject) */
    ecall

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)           /* msg_len */
#ifndef AES_INSTRUCTIONS
    sw   x0, 16(x3)           /* invalidate init_done up-front (stale-guard) */
    /* Early, wrap-safe msg bound: the sign-bit test alone wraps on huge
     * lengths AFTER the absorb has already walked DMEM. len >= 2^15 first. */
    srli x5, x14, 15
    bne  x5, x0, _ipi_bf_msgbad
    li   x5, 22368            /* msg past this would sit under the constants */
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _ipi_bf_msgbad
#endif
    li   x10, 0x0E0          /* sig */
    li   x12, 0x160          /* seed */
    li   x13, 0x180          /* msg */

    /* ---------------- KMAC SHAKE256 over (msg || salt) ---------------- */
    bn.xor w31, w31, w31
    bn.xor w1, w1, w1
    addi x5, x14, 16
    slli x5, x5, 5
    ori  x5, x5, 0xA
    csrrw x0, kmac_cfg, x5
    bn.ld w1, 96(x10)         /* salt: 32B from sig+96; upper 128b = bytes 112..127 */
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

    /* ---------------- VxV (P1) (from ov-Ip-pkc_publicmap.s) ------------------- */
    jal  x1, aes128_352
    li   x6, 0
    li   x7, 68
    li   x28, 8
    li   x29, 9
    li   x30, 8
    li x5, 0
    loopi 61, 85
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
                jal x1, aes128_352
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
            jal x1, aes128_352
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
                jal x1, aes128_352
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
                jal x1, aes128_352
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
    bn.rshi w5, w5, w31 >> 128
    bn.rshi w5, w31, w5 >> 128
    bn.rshi w6, w31, w5 >> 32
    bn.rshi w5, w5, w4 >> 32
    bn.rshi w4, w4, w31 >> 32
    bn.rshi w4, w31, w4 >> 224
    loopi 34, 373
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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
        jal x1, aes128_352
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

#else /* bngfonly: compute-AES engine, from ov-Ip-verify_backend.s bngf arm */
    li x10, 0xE0              /* sig */
    li x12, 0x160             /* seed = AES key */
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

    li x31, 30
    bn.lid x31, 0(x12)        /* AES key from seed */
    bn.rshi w30, w30, w31 >> 128
    bn.rshi w30, w31, w30 >> 128

    /* w29 = IV in LE-at-start staging form (aes128_352 byte-swaps to
     * BE-at-end): counters at low 32b of each half so +=2 is one bn.add;
     * byte 0 = 0 (block 0), byte 16 = 1 (block 1), zero nonce */
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
    bn.lid x31, 0(x30)        /* w26 = rcon carrier, 8 bits per round */
    la   x2, rkbuf            /* rk base: aes128_352 reads via x2 */
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

    /* ---------------- VxV (P1) ---------------- */
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
            bne x6, x31, _ipi_bf_vv_skip
                jal x1, aes128_352
                li x6, 0
                add x30, x0, x28
            _ipi_bf_vv_skip: NOP
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    addi x7, x7, -1

    /* ---------------- VxO (P2) ---------------- */
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
            bne x6, x31, _ipi_bf_vo_skip
                jal x1, aes128_352
                li x6, 0
                add x30, x0, x28
            _ipi_bf_vo_skip:
                NOP
    bn.rshi w2, w3, w2 >> 8
    bn.rshi w3, w4, w3 >> 8
    bn.rshi w4, w31, w4 >> 8
    li   x5, 0x517
    sw   x5, 16(x0)           /* init_done: FINAL/UPDATE reject -3 without it */
#endif

    /* ---------------- read 44B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 96
    bn.rshi w14, w31, w14 >> 160
    li   x3, 0x0A0
    bn.sd w13, 0(x3)         /* target lo */
    bn.sd w14, 32(x3)        /* target hi */

    /* ---- spill acc (oil is NOT ctx: host rewrites 0x60 per UPDATE) ---- */
    li   x3, 0x020
    bn.sd w0, 0(x3)          /* acc lo */
    bn.sd w1, 32(x3)         /* acc hi */
    ecall

/* ============================ UPDATE ============================ */
_UPDATE:
    li   x3, 0x00
    lw   x9, 4(x3)            /* row_start */
    lw   x8, 8(x3)            /* row_count */
#ifndef AES_INSTRUCTIONS
    lw   x5, 16(x3)
    li   x6, 0x517
    bne  x5, x6, _ipw_noinit  /* UPDATE before a completed INIT */
    /* Capacity gate (bngfonly carries .data above winend): an admissible-
     * looking oversized window would fold caprows and the AES constants into
     * the accumulator - wrong verdict, nothing corrupted. Wrap-safe: bound
     * both args below 64 before any sign-bit trick. Gate BEFORE the zero-row
     * skip so bad shapes reject even with rc=0. */
    or   x5, x9, x8
    srli x5, x5, 6
    bne  x5, x0, _ipw_bad     /* row_start or row_count >= 64 */
    li   x5, 43
    sub  x5, x5, x9
    srli x5, x5, 31
    bne  x5, x0, _ipw_bad     /* row_start > 43 */
    add  x5, x9, x8
    li   x6, 44
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _ipw_bad     /* row_start + row_count > 44 */
    slli x6, x9, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _ipw_bad     /* row_count > caprows[row_start] */
#endif
    beq  x8, x0, _ipw_skip    /* zero-row window -> no-op before any ctx touch */

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
    li   x12, 0x180           /* window (16B prefix + entries) */

    li   x7, 44
    sub  x7, x7, x9           /* first_row_size = o - row_start */

    /* ---- prefetch (absorbs 16B prefix) ---- */
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
                jal x1, load_p3
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
            jal x1, load_p3
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
                jal x1, load_p3
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
                jal x1, load_p3
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
_ipw_skip:
    ecall

#ifndef AES_INSTRUCTIONS
_ipw_bad:
    csrrw x0, mod1, x0
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* bad UPDATE args */
    ecall
_ipi_bf_msgbad:
    csrrw x0, mod1, x0
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* msg would overrun the window */
    ecall
_ipf_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* FINAL before a completed INIT */
    ecall
_ipw_noinit:
    csrrw x0, mod1, x0
    li   x6, -3
    sw   x6, 12(x0)           /* UPDATE before a completed INIT */
    ecall
#endif

/* UOV-Is streamed verify: ONE app, phase-dispatch, DMEM-persistent.
 * Host loads this once, then EXECUTEs: phase=INIT, phase=UPDATE x K (P3 windows),
 * phase=FINAL. ctx {acc,target} lives in DMEM across all runs; oil@0x40 is a
 * per-UPDATE host input, rewritten each window so nibble 0 = o[row_start].
 *
 *   phase 0 INIT  : KMAC(msg||salt)->target; P1/P2 -> acc
 *   phase 1 UPDATE: fold one row-aligned P3 window into acc
 *   phase 2 FINAL : compare acc vs target -> ctrl.status (0 accept / -1 reject)
 *
 * Shared DMEM layout:
 *   0x000 ctrl {phase@0, arg0@4, arg1@8, status@12}
 *   0x020 acc 32B | 0x040 oil 32B | 0x060 target 32B
 *   0x080 sig 96B | 0x0E0 seed 32B | 0x100 msg/p3_window
 * Each phase block is self-contained and ends in ecall; no register state
 * crosses phases (only DMEM ctx does).
 * clob: everything (phase app, no caller).
 * stack: none (x2 unused); leaf app, no jal.
 */
#if defined(AES_INSTRUCTIONS) && !defined(GF_INSTRUCTIONS)
#error "gfhw source: -DAES_INSTRUCTIONS alone still builds the FULL bngfaes kernel (GF_INSTRUCTIONS is inert here), so an _aesonly target aimed at this file reports bngfaes cycles under a software-GF name. Build _gfsw.s for that tier."
#endif
#ifndef AES_INSTRUCTIONS
/* bngfonly arm data. The bngfaes arm addresses the host map absolutely and
 * carries no .data; here the same map is named so the AES constants land
 * above the window and the ELF exports the bound. Round keys stay
 * WDR-resident (w5-w14), so no scratch is needed. */
.section .data
.balign 32
ctrl:      .zero 32              /* 0x000 phase, arg0, arg1, status */
accctx:    .zero 32              /* 0x020 acc ctx */
oil:       .zero 32              /* 0x040 host-rewritten per UPDATE */
target:    .zero 32              /* 0x060 ctx */
sig:       .zero 96              /* 0x080 */
seed:      .zero 32              /* 0x0E0 */
.global msgwin
msgwin:    .zero 30720           /* 0x100 .. 0x7900: msg (INIT) / P3 window */
.global winend
winend:
/* Largest row_count per row_start that still fits msgwin (960 entries; Is
 * UPDATE loads one 32 B entry at a time, no refill overshoot). UPDATE
 * rejects rc > caprows[rs] with -2: past winend the row loop would fold
 * this table and the AES constants into the accumulator and return a wrong
 * verdict instead of an error. */
caprows:
    .word 17, 17, 17, 18, 18, 19, 19, 20
    .word 20, 21, 22, 22, 23, 24, 25, 26
    .word 27, 29, 30, 33, 36, 43, 42, 41
    .word 40, 39, 38, 37, 36, 35, 34, 33
    .word 32, 31, 30, 29, 28, 27, 26, 25
    .word 24, 23, 22, 21, 20, 19, 18, 17
    .word 16, 15, 14, 13, 12, 11, 10, 9
    .word 8, 7, 6, 5, 4, 3, 2, 1
/* AES constants; shiftrow_mask is la-resolved by AES_bngf/aes128.s. */
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
    bne  x5, x6, _isf_noinit
#endif
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
    sw   x6, 12(x3)          /* status = 0 (accept) */
    ecall
_F_fail:
    li   x6, -1
    sw   x6, 12(x3)          /* status = -1 (reject) */
    ecall

/* ============================ INIT ============================ */
_INIT:
    li   x3, 0x00
    lw   x14, 4(x3)          /* msg_len */
#ifndef AES_INSTRUCTIONS
    sw   x0, 16(x3)           /* invalidate init_done up-front (stale-guard) */
    /* Early, wrap-safe msg bound: the sign-bit test alone wraps on huge
     * lengths AFTER the absorb has already walked DMEM. len >= 2^15 first. */
    srli x5, x14, 15
    bne  x5, x0, _isi_bf_msgbad
    li   x5, 30720            /* msg past this would sit under the constants */
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _isi_bf_msgbad
#endif
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
    li   x5, 0x517
    sw   x5, 16(x0)           /* init_done: FINAL/UPDATE reject -3 without it */
#endif

    bn.wsrr w8, 0xA
    li   x3, 0x60
    bn.sd w8, 0(x3)          /* target */
    li   x3, 0x20
    bn.sd w0, 0(x3)          /* acc (oil is NOT ctx: host rewrites 0x40 per UPDATE) */
    ecall

/* ============================ UPDATE ============================ */
_UPDATE:
    li     x3, 0x00
    lw     x7, 4(x3)          /* row_start */
    lw     x8, 8(x3)          /* row_count */

#ifndef AES_INSTRUCTIONS
    lw   x5, 16(x3)
    li   x6, 0x517
    bne  x5, x6, _isw_noinit  /* UPDATE before a completed INIT */
    /* Capacity gate (bngfonly carries .data above winend): an oversized
     * window would fold caprows and the AES constants into the accumulator -
     * wrong verdict, nothing corrupted. Wrap-safe: bound both args below 64
     * before any sign-bit trick. */
    or   x5, x7, x8
    srli x5, x5, 6
    bne  x5, x0, _isw_bad     /* row_start or row_count >= 64 */
    li   x5, 63
    sub  x5, x5, x7
    srli x5, x5, 31
    bne  x5, x0, _isw_bad     /* row_start > 63 */
    add  x5, x7, x8
    li   x6, 64
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _isw_bad     /* row_start + row_count > 64 */
    slli x6, x7, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _isw_bad     /* row_count > caprows[row_start] */
#endif

    li     x9, 0x20
    bn.ld  w0, 0(x9)          /* acc_in */
    beq    x8, x0, _U_store

    li     x9, 64
    sub    x7, x9, x7         /* first_row_size = o - row_start */

    li     x31, 0x13
    csrrw  x0, mod0, x31
    csrrw  x0, mod1, x0
    bn.xor w31, w31, w31
    bn.wsrw acc, w0

    li     x9, 0x40
    bn.ld  w6, 0(x9)          /* oil (aligned to row_start) */
    li     x12, 0x100
    li     x30, 30
    loop   x8, 7
        bn.gfmul.4 w5, w6, w6
        loop x7, 3
            bn.lid x30, 0(x12++)
            bn.gfmul.4.acc w0, w30, w5
            bn.rshi w5, w31, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi   x7, x7, -1

_U_store:
    li     x9, 0x20
    bn.sd  w0, 0(x9)          /* acc_out */
    ecall

#ifndef AES_INSTRUCTIONS
_isw_bad:
    csrrw x0, mod1, x0
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* bad UPDATE args */
    ecall
_isi_bf_msgbad:
    csrrw x0, mod1, x0
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* msg would overrun the window */
    ecall
_isf_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* FINAL before a completed INIT */
    ecall
_isw_noinit:
    csrrw x0, mod1, x0
    li   x6, -3
    sw   x6, 12(x0)           /* UPDATE before a completed INIT */
    ecall
#endif

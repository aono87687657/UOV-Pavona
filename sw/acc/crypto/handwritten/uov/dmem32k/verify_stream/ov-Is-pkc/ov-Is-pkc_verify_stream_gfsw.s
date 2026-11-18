/* Streamed UOV-Is verify: software GF with software or hardware AES columns.
 * Host contract = ov-Is-pkc_verify_streamed_gfhw.s; window cap = 22,496 B.
 * aes128_col_is returns two blocks in w13; acc = w25, spilled to 0x20.
 * INIT rejects msg_len > 22,496; UPDATE rejects bad/oversized windows: status -2.
 * clob: everything. stack: 256 B in the ACC-private scratch (x2 descends).
 */
#ifdef GF_INSTRUCTIONS
#error "gfsw source: GF is always software here, so -DGF_INSTRUCTIONS is never correct on it -- a _bngfonly target aimed at this file reports swonly cycles under a hardware-GF name. Build _gfhw.s for that tier."
#endif
.section .data
.balign 32
ctrl:      .zero 32              /* 0x000 phase, arg0, arg1, status */
accctx:    .zero 32              /* 0x020 acc ctx */
oil:       .zero 32              /* 0x040 host-rewritten per UPDATE */
target:    .zero 32              /* 0x060 ctx */
sig:       .zero 96              /* 0x080 */
seed:      .zero 32              /* 0x0E0 */
.global msgwin
msgwin:    .zero 22496           /* 0x100 .. 0x58e0: msg (INIT) / P3 window */
.global winend
winend:
/* Largest row_count per row_start that fits the 703-entry window. */
caprows:
    .word 12, 12, 12, 12, 13, 13, 13, 13
    .word 14, 14, 14, 15, 15, 16, 16, 17
    .word 17, 18, 19, 19, 20, 21, 22, 23
    .word 25, 27, 29, 37, 36, 35, 34, 33
    .word 32, 31, 30, 29, 28, 27, 26, 25
    .word 24, 23, 22, 21, 20, 19, 18, 17
    .word 16, 15, 14, 13, 12, 11, 10, 9
    .word 8, 7, 6, 5, 4, 3, 2, 1
/* gf16_mul msb mask (loaded to w3) */
.balign 32
sfk_msb:
    .word 0x88888888,0x88888888,0x88888888,0x88888888
    .word 0x88888888,0x88888888,0x88888888,0x88888888
/* The software-AES target links its table after these bus-side objects. */
.balign 32

/* ACC-private scratch above the 31,744 B bus window: addresses only, all
 * written before read, never host-read. x2 descends from sfk_stack_end:
 * 32 B frame | 192 B rk (176 + 16 align) | 32 B col-buf. */
.set sfk_stack,     31744
.set sfk_stack_end, 32000

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
    /* acc/target come up as loader-written .data zeros, so FINAL before INIT
     * would compare 0 == 0 and ACCEPT. Sentinel, set by INIT. */
    lw   x5, 16(x0)
    li   x6, 0x517
    bne  x5, x6, _f_noinit
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
    sw   x0, 16(x3)           /* invalidate init_done up-front (stale-guard) */
    /* Early, wrap-safe msg bound: sign-bit test alone wraps on huge lengths
     * after the absorb has already walked DMEM. len >= 2^15 first. */
    srli x5, x14, 15
    bne  x5, x0, _msgbad
    li   x5, 22496            /* msg past this would sit under the T-table */
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _msgbad
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

    /* p1p2 fold, from ov-Is-verify_backend.s sw arm (inline: no x1 save) */
    la   x2, sfk_stack_end    /* private stack, descending */
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x10, 0x80            /* sig */
    li   x11, 0x20            /* acc out */
    li   x12, 0xE0            /* seed = AES key */
    addi x2, x2, -32
    add  x3, x0, x2
    sw   x10,  0(x3)
    sw   x11,  4(x3)
    sw   x12,  8(x3)
    sw   x13, 12(x3)
    sw   x14, 16(x3)

    bn.xor w31, w31, w31           # zero const
    bn.xor w25, w25, w25            # accumulator = 0

    /* Packed AES key schedule, 176 B. */
    addi x2, x2, -192              # 176 B rk + 16 B align pad
    add  x10, x0, x12              # x10 = pk_seed pointer
    add  x11, x0, x2               # x11 = rk buffer base
    jal  x1, AES_128_keyschedule
    add  x18, x0, x2               # x18 = rk base survivor, set AFTER KS

    /* CTR + 32 B scratch buf for aes128_col_is (2 AES blocks = 1 col) */
    addi x13, x0, 0                # AES-CTR LE counter starts at 0
    addi x2, x2, -32
    add  x4, x0, x2
    sw   x4, 20(x3)                # buf base for helper to lw

    /* sig load + v / o window extract */
    li   x31, 5
    lw   x5, 0(x3)                 # x5 = sig base
    bn.lid x31++, 0(x5)            # w5 = bytes [0..31]   = v[0..63]
    bn.lid x31++, 32(x5)           # w6 = v[64..95] || o[0..31]
    bn.lid x31++, 64(x5)           # w7 = o[32..63] || salt
    bn.mov  w23, w5                # v-window lo (full 64 nibbles)
    bn.rshi w26, w7, w6 >> 128     # o-window = o[0..63]
    bn.rshi w24, w6, w31 >> 128
    bn.rshi w24, w31, w24 >> 128   # w24 = v[64..95] lo, 0 hi

    /* VxV. 96 rows, row i has 96-i entries. x17 = row ctr (survivor). */
    li x17, 96
    loopi 96, 18
        bn.mov w1, w23
        bn.mov w2, w23                   #scalar = v[i]
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef lo = v[i]*v_window[0..63]
        bn.mov w1, w24
        jal x1, gf16_mul                  #w2 still = v[i]
        bn.mov w12, w0                   #coef hi
        loop x17, 7
            jal x1, aes128_col_is        #w13 = 1 col (32 B), x13 += 2
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w12, w11 >> 4
            bn.rshi w12, w31, w12 >> 4
        bn.rshi w23, w24, w23 >> 4
        bn.rshi w24, w31, w24 >> 4
        addi x17, x17, -1

    /* VxO setup: reload sig + rebuild windows */
    li   x31, 5
    lw   x6, 0(x3)
    bn.lid x31++, 0(x6)
    bn.lid x31++, 32(x6)
    bn.lid x31++, 64(x6)
    bn.mov  w23, w5
    bn.rshi w26, w7, w6 >> 128
    bn.rshi w24, w6, w31 >> 128
    bn.rshi w24, w31, w24 >> 128

    /* VxO. 96 rows x 64 cols, const inner. */
    loopi 96, 13
        bn.mov w1, w26
        bn.mov w2, w23                   #scalar = v[i]
        jal x1, gf16_mul
        bn.mov w11, w0                   #coef = v[i]*o[0..63]
        loopi 64, 6
            jal x1, aes128_col_is
            bn.mov w1, w13
            bn.mov w2, w11
            jal x1, gf16_mul
            bn.xor  w25, w25, w0
            bn.rshi w11, w31, w11 >> 4
        bn.rshi w23, w24, w23 >> 4
        bn.rshi w24, w31, w24 >> 4

    bn.wsrr w8, 0xA           /* 32B digest -> ctx.target */
    li   x3, 0x60
    bn.sd w8, 0(x3)
    li   x3, 0x20
    li   x6, 25
    bn.sid x6, 0(x3)          /* acc (w25) -> ctx */
    li   x5, 0x517
    sw   x5, 16(x0)           /* init_done: FINAL/UPDATE reject -3 without it */
    ecall

/* ============================ UPDATE ============================ */
_UPDATE:
    li     x3, 0x00
    lw     x9, 4(x3)          /* row_start */
    lw     x8, 8(x3)          /* row_count */

    lw   x5, 16(x3)
    li   x6, 0x517
    bne  x5, x6, _u_noinit    /* UPDATE before a completed INIT */
    /* Capacity gate: past winend a fold would eat caprows + the T-table. */
    or   x5, x9, x8
    srli x5, x5, 6
    bne  x5, x0, _U_bad       /* row_start or row_count >= 64 */
    li   x5, 63
    sub  x5, x5, x9
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_start > 63 */
    add  x5, x9, x8
    li   x6, 64
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _U_bad       /* row_start + row_count > 64 */
    slli x6, x9, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_count > caprows[row_start] */

    beq  x8, x0, _U_done      /* zero-row window -> no-op */

    /* P3 row fold, from ov-Is-verify_backend.s sw arm (inline) */
    bn.xor w31, w31, w31
    la   x5, sfk_msb
    li   x6, 3
    bn.lid x6, 0(x5)          /* w3 = gf16_mul msb mask */
    li   x5, 0x20
    li   x6, 25
    bn.lid x6, 0(x5)          /* w25 = acc <- ctx */
    li   x5, 0x40
    li   x6, 26
    bn.lid x6, 0(x5)          /* w26 = oil (host-aligned to row_start) */
    li   x23, 1               /* bn.lid dest w1: entries are aligned */
    li   x4, 0x100            /* P3 window */
    li   x7, 64
    sub  x7, x7, x9           /* first row size */
    loop x8, 13
    bn.mov w1, w26
    bn.mov w2, w26            # scalar = O[row]
    jal x1, gf16_mul
    bn.mov w11, w0            # coef = O[row]*o_window
    loop x7, 6
        bn.lid x23, 0(x4)     # w1 = entry (aligned)
        bn.mov w2, w11
        jal x1, gf16_mul
        bn.xor w25, w25, w0
        bn.rshi w11, w31, w11 >> 4
        addi x4, x4, 32
    bn.rshi w26, w31, w26 >> 4
    addi x7, x7, -1
    li   x5, 0x20
    li   x6, 25
    bn.sid x6, 0(x5)          /* acc -> ctx */
_U_done:
    ecall

_U_bad:
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* bad UPDATE args */
    ecall
_msgbad:
    li   x6, -2
    li   x3, 0x00
    sw   x6, 12(x3)           /* msg would overrun the window */
    ecall
_f_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* FINAL before a completed INIT */
    ecall
_u_noinit:
    li   x6, -3
    sw   x6, 12(x0)           /* UPDATE before a completed INIT */
    ecall

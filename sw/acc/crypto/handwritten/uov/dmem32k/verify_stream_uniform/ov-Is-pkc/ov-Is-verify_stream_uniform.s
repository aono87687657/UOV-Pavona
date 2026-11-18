/* ov-Is-verify_stream_uniform.s - streamed UOV-Is verify, stream_uniform outer.
 * Backend-neutral: the whole public-map fold goes through backend_verify_*;
 * the SAME outer links against each backend arm.
 * INVARIANT: compiles with NO copts - this object must stay byte-identical
 * across arms, or an arm-to-arm ratio stops measuring only the backend.
 * tools/stream_uniform_gates.sh checks it (disasm + .data + relocations).
 * Host contract =
 * verify_stream Is streamed verify + init_done guard word at 0x010
 * (FINAL/UPDATE reject with status -3 before INIT has completed).
 * Window ABI: max packed P3 window = 26624 B (0x100..0x6900); backend-
 * private .data links after winend. Hosts use MAX_WINDOW_BYTES=26624.
 * clob: everything. mod1 = 0 on every phase exit.
 */
.section .data
ctrl:      .word 0, 0, 0, 0      /* phase, arg0, arg1, status */
initdone:  .word 0               /* 0x010: INIT-completed magic */
           .zero 12
acc:       .zero 32              /* 0x020 ctx (single WDR, GF16 m=64) */
oil:       .zero 32              /* 0x040 host-rewritten per UPDATE */
target:    .zero 32              /* 0x060 ctx */
sig:       .zero 96              /* 0x080 (80B s + 16B salt) */
seed:      .zero 32              /* 0x0E0 (16B seed + pad) */
msgwin:    .zero 26624           /* 0x100 .. 0x6900 msg / P3 window ABI */
winend:
/* Largest row_count each row_start can still fit in msgwin (aligned 32B
 * entries, exact reads). UPDATE rejects rc > caprows[rs] with -2: the row
 * loop would otherwise read past winend and fold caprows and backend .data
 * into the accumulator, returning a wrong verdict instead of an error. */
caprows:
    .word 14, 14, 15, 15, 15, 16, 16, 16
    .word 17, 17, 18, 18, 19, 20, 20, 21
    .word 22, 23, 24, 25, 26, 28, 30, 33
    .word 40, 39, 38, 37, 36, 35, 34, 33
    .word 32, 31, 30, 29, 28, 27, 26, 25
    .word 24, 23, 22, 21, 20, 19, 18, 17
    .word 16, 15, 14, 13, 12, 11, 10, 9
    .word 8, 7, 6, 5, 4, 3, 2, 1

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _UPDATE
    li   x5, 2
    beq  x4, x5, _FINAL
    csrrw x0, mod1, x0
    li   x6, -2
    sw   x6, 12(x0)           /* invalid phase */
    ecall

/* ============================ FINAL ============================ */
_FINAL:
    lw   x5, 16(x0)           /* init_done guard */
    li   x6, 0x517
    bne  x5, x6, _F_noinit
    li   x3, 0x020
    bn.ld w0, 0(x3)          /* acc */
    li   x3, 0x060
    bn.ld w8, 0(x3)          /* target */
    bn.cmp w0, w8, FG0
    csrrs x5, 0x7c0, x0
    srli x5, x5, 3
    andi x5, x5, 1           /* Z: acc == target */
    li   x3, 0x000
    beq  x5, x0, _F_fail
    li   x6, 0
    sw   x6, 12(x3)          /* status = 0 (accept) */
    ecall
_F_fail:
    li   x6, -1
    sw   x6, 12(x3)          /* status = -1 (reject) */
    ecall
_F_noinit:
    li   x6, -3
    sw   x6, 12(x0)          /* status = -3 (no completed INIT) */
    ecall

/* ============================ INIT ============================ */
_INIT:
    sw   x0, 16(x0)           /* invalidate init_done up-front (stale-guard) */
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
    jal  x1, backend_verify_p1p2

    /* -------------- read 32B digest -> ctx.target --------------- */
    bn.wsrr w8, 0xA
    li   x3, 0x60
    bn.sd w8, 0(x3)          /* target */
    li   x5, 0x517
    sw   x5, 16(x0)           /* init_done */
    csrrw x0, mod1, x0
    ecall

/* ============================ UPDATE ============================ */
_UPDATE:
    lw   x5, 16(x0)           /* require completed INIT */
    li   x6, 0x517
    bne  x5, x6, _U_noinit    /* same lifecycle status (-3) as FINAL */
    li   x3, 0x00
    lw   x9, 4(x3)            /* row_start */
    lw   x8, 8(x3)            /* row_count */
    beq  x8, x0, _isw_skip    /* zero-row window -> no-op */
    /* bounds. First reject any high bits (>=128) so the sign-bit trick below
     * cannot be wrapped by a huge unsigned row_start/row_count. rc=64 gets
     * this far but caprows rejects it - whole P3 is 66,560 B, no window. */
    or   x5, x9, x8
    srli x5, x5, 7
    bne  x5, x0, _U_bad       /* row_start or row_count >= 128 */
    /* now both in [0,127] (< 2^31): sign-bit trick is wrap-safe */
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
    bne  x5, x0, _U_bad       /* row_count > caprows[row_start] (capacity) */
    jal  x1, backend_verify_p3_rows
_isw_skip:
    csrrw x0, mod1, x0
    ecall
_U_bad:
    csrrw x0, mod1, x0
    li   x6, -2
    sw   x6, 12(x0)           /* bad UPDATE args */
    ecall
_U_noinit:
    csrrw x0, mod1, x0
    li   x6, -3
    sw   x6, 12(x0)           /* UPDATE before a completed INIT */
    ecall

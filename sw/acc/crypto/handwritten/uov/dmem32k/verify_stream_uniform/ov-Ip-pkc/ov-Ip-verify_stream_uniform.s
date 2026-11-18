/* ov-Ip-verify_stream_uniform.s - streamed UOV-Ip verify, stream_uniform outer.
 * Backend-neutral: the whole public-map fold goes through backend_verify_*
 * (contract in ov-Ip-verify_backend.s); the SAME outer links against each arm.
 * INVARIANT: compiles with NO copts - this object must stay byte-identical
 * across arms, or an arm-to-arm ratio stops measuring only the backend.
 * tools/stream_uniform_gates.sh checks it (disasm + .data + relocations).
 * Host contract = verify_stream streamed verify + init_done guard word
 * at 0x010 (FINAL/UPDATE reject with status -3 before INIT has completed).
 * clob: everything. mod1 = 0 on every phase exit.
 */
.section .data
ctrl:      .word 0, 0, 0, 0      /* phase, arg0, arg1, status */
initdone:  .word 0               /* 0x010: INIT-completed magic */
           .zero 12
acc:       .zero 64              /* 0x020 ctx */
oil:       .zero 64              /* 0x060 host-rewritten per UPDATE */
target:    .zero 64              /* 0x0A0 ctx */
sig:       .zero 128             /* 0x0E0 */
seed:      .zero 32              /* 0x160 */
/* msg / P3-window overlay @0x180. Sized to the MAX backend READ end, not to
 * the host schedule: the worst caprows-admissible window is 504 entries
 * (rs=5/rc=16, rs=10/rc=21) -> 63 load_p3 refills, 192 + 63*352 = 22368 B,
 * ending exactly on winend. The 13/31 host split only reaches 0x5780, so
 * do not re-derive the reservation from it. Host writes end lower still
 * (0x5830); backend-private .data (sw T-table) links after winend, out of
 * reach of any window write that obeys the ABI - nothing on-chip enforces
 * that, the DIF bounds-check only stops writes past the 31,744 B window. */
msgwin:    .zero 22368           /* 0x180 .. 0x58e0 */
winend:
/* Largest row_count each row_start can still fit in msgwin, refill overshoot
 * included. UPDATE rejects rc > caprows[rs] with -2: the row loop would
 * otherwise read past winend and fold caprows and backend .data into the
 * accumulator, returning a wrong verdict instead of an error. */
caprows:
    .word 13, 13, 14, 14, 15, 16, 16, 17
    .word 18, 19, 21, 22, 25, 31, 30, 29
    .word 28, 27, 26, 25, 24, 23, 22, 21
    .word 20, 19, 18, 17, 16, 15, 14, 13
    .word 12, 11, 10, 9, 8, 7, 6, 5
    .word 4, 3, 2, 1

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
_F_noinit:
    li   x6, -3
    sw   x6, 12(x0)          /* status = -3 (no completed INIT) */
    ecall

/* ============================ INIT ============================ */
_INIT:
    sw   x0, 16(x0)           /* invalidate init_done up-front (stale-guard) */
    li   x3, 0x00
    lw   x14, 4(x3)           /* msg_len */
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
    jal  x1, backend_verify_p1p2

    /* ---------------- read 44B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 96
    bn.rshi w14, w31, w14 >> 160
    li   x3, 0x0A0
    bn.sd w13, 0(x3)         /* target lo */
    bn.sd w14, 32(x3)        /* target hi */
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
    beq  x8, x0, _ipw_skip    /* zero-row window -> no-op */
    /* bounds. First reject any high bits (>=64) so the sign-bit trick below
     * cannot be wrapped by a huge unsigned row_start/row_count (e.g.
     * rs=0,rc=0xffffffff would pass a bare sub/srli and spin a 4B-iter loop). */
    or   x5, x9, x8
    srli x5, x5, 6
    bne  x5, x0, _U_bad       /* row_start or row_count >= 64 */
    /* now both in [0,63] (< 2^31): sign-bit trick is wrap-safe */
    li   x5, 43
    sub  x5, x5, x9
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_start > 43 */
    add  x5, x9, x8
    li   x6, 44
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _U_bad       /* row_start + row_count > 44 */
    slli x6, x9, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_count > caprows[row_start] (capacity) */
    jal  x1, backend_verify_p3_rows
_ipw_skip:
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

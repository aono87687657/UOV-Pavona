/* ov-Ip3-verify_stream_uniform.s - streamed UOV-Ip3 verify, stream_uniform outer.
 * Backend-neutral: the whole public-map fold goes through backend_verify_*
 * (contract in ov-Ip3-verify_backend.s); the SAME outer links against each arm.
 * INVARIANT: compiles with NO copts - this object must stay byte-identical
 * across arms, or an arm-to-arm ratio stops measuring only the backend.
 * tools/stream_uniform_gates.sh checks it (disasm + .data + relocations).
 * Host contract = verify_stream/ov-Ip3-pkc streamed verify + init_done guard word
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
sig:       .zero 160             /* 0x0E0; 135B sig in a 160B slot */
seed:      .zero 32              /* 0x180 */
/* msg / P3-window overlay @0x1A0. Derived for THIS rig's backend 2026-08-24:
 * per-arm read ends at the 528-entry cap are hw 192+65*352+512+384 = 23,968
 * (refill j starts at 192+352j+32*floor(j/4)) and sw 65*352+512+384 = 23,776
 * (batch bases advance 352,384,352,352); 23,968 is the max and 32-aligned.
 * Uniform cap = 528 entries: 529 pushes the sw read end to 24,160 > winend.
 * Backend-private .data (sw T-table) links after winend, out of reach of any
 * window write that obeys the ABI - nothing on-chip enforces that, the DIF
 * bounds-check only stops writes past the 31,744 B window. */
msgwin:    .zero 23968           /* 0x1A0 .. 0x5F40 */
winend:
/* Largest row_count each row_start can still fit in msgwin, refill overshoot
 * included. UPDATE rejects rc > caprows[rs] with -2: the row loop would
 * otherwise read past winend and fold caprows and backend .data into the
 * accumulator, returning a wrong verdict instead of an error.
 * caprows[s] = max c with sum_{i<c}(45-s-i) <= 528 (the uniform cap above);
 * from s=13 the whole remaining triangle fits. Re-derived 2026-08-24. */
caprows:
    .word 13, 14, 14, 15, 15, 16, 17, 17
    .word 18, 19, 21, 22, 25, 32, 31, 30
    .word 29, 28, 27, 26, 25, 24, 23, 22
    .word 21, 20, 19, 18, 17, 16, 15, 14
    .word 13, 12, 11, 10, 9, 8, 7, 6
    .word 5, 4, 3, 2, 1

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
    srli x5, x14, 15          /* high bits first: the sign-bit test below */
    bne  x5, x0, _I_bad       /* wraps on huge msg_len (e.g. 0xffffffff) */
    li   x5, 23968
    sub  x5, x5, x14
    srli x5, x5, 31
    bne  x5, x0, _I_bad       /* msg_len > msgwin: absorb would read caprows */
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
    jal  x1, backend_verify_p1p2

    /* ---------------- read 45B digest -> ctx.target ----------------- */
    bn.wsrr w13, 0xA
    bn.wsrr w14, 0xA
    bn.rshi w14, w14, w31 >> 104
    bn.rshi w14, w31, w14 >> 152
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
    /* bounds. First reject any high bits (>=64) so the sign-bit trick below
     * cannot be wrapped by a huge unsigned row_start/row_count (e.g.
     * rs=0,rc=0xffffffff would pass a bare sub/srli and spin a 4B-iter loop).
     * Gate BEFORE the zero-row skip so bad shapes reject even with rc=0. */
    or   x5, x9, x8
    srli x5, x5, 6
    bne  x5, x0, _U_bad       /* row_start or row_count >= 64 */
    /* now both in [0,63] (< 2^31): sign-bit trick is wrap-safe */
    li   x5, 44
    sub  x5, x5, x9
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_start > 44 */
    add  x5, x9, x8
    li   x6, 45
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _U_bad       /* row_start + row_count > 45 */
    slli x6, x9, 2
    la   x5, caprows
    add  x5, x5, x6
    lw   x5, 0(x5)
    sub  x5, x5, x8
    srli x5, x5, 31
    bne  x5, x0, _U_bad       /* row_count > caprows[row_start] (capacity) */
    beq  x8, x0, _ipw_skip    /* zero-row window -> no-op after the gates */
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
_I_bad:
    csrrw x0, mod1, x0
    li   x6, -2
    sw   x6, 12(x0)           /* INIT msg_len over the window bound */
    ecall

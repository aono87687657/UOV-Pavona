/* ov-Is-keygen_stream_uniform.s - streamed UOV-Is keygen, swappable-backend outer (WJ=10).
 * Backend-neutral: all AES/GF work via the backend_* ABI (contract in
 * ov-Is-keygen_backend.s); the SAME object links against each backend arm. Host contract =
 * Is stream kernel (phase 0 INIT / phase 1 WINDOW(col_start, col_count<=10
 * EVEN), fixed-320 slice, 7 windows: 6x10+4).
 * clob: everything. mod1 = 0 on every phase exit.
 */
.section .data
.balign 32
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
slice:     .zero 20480      /* 20480: 64 rows x WJ x 32, host-read */
slice_end:                    /* INIT overlays expandsk here (3,104B) */
o_ctx:     .zero 3072
.global p1buf            /* backend_window_init la-resolves it */
p1buf:     .zero 3072
gbuf01:    .zero 640       /* rows 0,1 of a group */
winend:

/* ACC-private, above the 31,744 B bus window: addresses, not linker objects, so
 * they claim no load space. Both are written before they are read and neither is
 * reachable by the host, which is what makes the placement legal. Same pattern as
 * ../../keygen_stream/ov-Is-pkc+skc/ov-Is-keygen_stream_sw.s. The sw backend continues the
 * region at 32,416; keep the two in step. */
.set gbuf23, 31744      /* 640 B, rows 2,3 of a group */
.set frame,  32384      /* 32 B */

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _WINDOW
    csrrw x0, mod1, x0
    li   x6, -2
    sw   x6, 12(x0)           /* invalid phase */
    ecall

/* ============================ INIT ============================ */
_INIT:
    la x2, slice_end          /* expandsk overlays the slice (3,104B) */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3104; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid) */
    addi x4, x2, 32           /* raw O (3,072B) -> ctx */
    la x5, o_ctx
    li x6, 96
    li x17, 0
    loop x6, 2
        bn.lid x17, 0(x4++)
        bn.sid x17, 0(x5++)
    la x10, pk_seed
    jal x1, backend_init_once /* sw derives rkbuf (DMEM); hw no-op */
    csrrw x0, mod1, x0
    sw x0, 12(x0)             /* status = 0 */
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x5, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count */
    sw x5, 4(x3)
    beq x18, x0, _bad_args
    andi x4, x18, 1
    bne x4, x0, _bad_args     /* col_count must be even (col-pairs) */
    /* bounds (beq/bne-only ISA: sub + srli sign trick) */
    li   x4, 10
    sub  x4, x4, x18
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_count <= 10 = WJ (slice is 64 x 320B) */
    andi x4, x5, 1
    bne  x4, x0, _bad_args    /* col_start even (48B col stride alignment) */
    li   x4, 62
    sub  x4, x4, x5
    srli x4, x4, 31
    bne  x4, x0, _bad_args    /* col_start <= 62 (also kills cs+wc wrap) */
    add  x4, x5, x18
    li   x6, 64
    sub  x6, x6, x4
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_start + col_count <= 64 */
    bn.xor w31, w31, w31
    li x4, 0x13
    csrrw x0, mod0, x4
    csrrw x0, mod1, x0
    la x6, o_ctx
    sw x6, 0(x3)              /* true O base (fold) */
    slli x4, x5, 5
    slli x7, x5, 4
    add  x4, x4, x7           /* col_start*48 */
    add  x6, x6, x4
    sw x6, 8(x3)              /* window O base */
    la x10, pk_seed
    jal x1, backend_window_init
    /* zero the full slice (fixed layout, all windows). x9 = count: NOT an
     * idx GPR - x8=12 is a persistent WDR-index window_init set + backend_row
     * needs (bn.sid x8 = w12 store); clobbering it -> bn.sid idx>31 ILLEGAL. */
    li x31, 31
    la x10, slice
    li x9, 640
    loop x9, 1
        bn.sid x31, 0(x10++)
    li x7, 0                  /* row */
    li x30, 96                /* 96 - r */
    loopi 24, 64
    slli x4, x7, 7                    # 128*row
    lw   x5, 4(x3)                    # col_start
    slli x6, x5, 1
    add  x4, x4, x6                   # +2*col_start
    li   x5, 9312
    add  x13, x4, x5                  # P2 ctr = 9312+128r+2cs
    la   x10, gbuf01
    lw   x18, 8(x0)                  # col_count (reload; row clobbers)
    jal  x1, backend_row
    addi x7, x7, 1
    addi x30, x30, -1
    slli x4, x7, 7                    # 128*row
    lw   x5, 4(x3)                    # col_start
    slli x6, x5, 1
    add  x4, x4, x6                   # +2*col_start
    li   x5, 9312
    add  x13, x4, x5                  # P2 ctr = 9312+128r+2cs
    la   x10, gbuf01
    addi x10, x10, 320
    lw   x18, 8(x0)                  # col_count (reload; row clobbers)
    jal  x1, backend_row
    addi x7, x7, 1
    addi x30, x30, -1
    slli x4, x7, 7                    # 128*row
    lw   x5, 4(x3)                    # col_start
    slli x6, x5, 1
    add  x4, x4, x6                   # +2*col_start
    li   x5, 9312
    add  x13, x4, x5                  # P2 ctr = 9312+128r+2cs
    la   x10, gbuf23
    lw   x18, 8(x0)                  # col_count (reload; row clobbers)
    jal  x1, backend_row
    addi x7, x7, 1
    addi x30, x30, -1
    slli x4, x7, 7                    # 128*row
    lw   x5, 4(x3)                    # col_start
    slli x6, x5, 1
    add  x4, x4, x6                   # +2*col_start
    li   x5, 9312
    add  x13, x4, x5                  # P2 ctr = 9312+128r+2cs
    la   x10, gbuf23
    addi x10, x10, 320
    lw   x18, 8(x0)                  # col_count (reload; row clobbers)
    jal  x1, backend_row
    addi x7, x7, 1
    addi x30, x30, -1
    addi x21, x7, -4                  # i0 = group base row
    lw   x18, 8(x0)
    la   x13, gbuf01
    la   x14, gbuf23
    la   x11, slice
    jal  x1, backend_fold_group
    nop
    csrrw x0, mod1, x0
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0
    li x6, -2
    sw x6, 12(x0)
    ecall

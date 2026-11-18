/* ov-Ip3-keygen_stream_uniform.s - streamed UOV-Ip3 keygen, swappable-backend outer (WJ=5).
 * Backend-neutral streamed UOV-Ip3 keygen outer (v=74, o=45, WJ=5): all AES/GF
 * work via the backend_* ABI (contract in the backend headers), so a
 * bazel dep swap changes ONLY the backend and cycle ratios price the backend alone.
 *   phase 0 INIT  : expandsk(sk_seed@0x20) -> pk_seed@0x40 + padded O ctx,
 *                   then backend_init_once.
 *   phase 1 WINDOW(arg0=col_start, arg1=1<=col_count<=5): slice[k][j] =
 *           sum_i O[i][k]*B[i][col_start+j], B = P1*O+P2 via the backend.
 * WINDOW requires a prior INIT. Fixed slice: entry (k,j) at slice + k*320 + j*64
 * (45B valid + 19B pad). 9 windows of 5. Rows: 18 groups of 4 + 2-row tail.
 * P2 stream: g = 2775 + 45*row + col; the outer derives the canonical AES block
 * ctr = floor(45*b/2), phase = b&1 for every batch b; backends only adapt the
 * representation. No bn.gfmul/bn.aes128/bn.mulv in this file (gated).
 * mod1 pinned 0 on every phase exit. clob: everything (phase app, no caller).
 */
.section .data
.balign 32
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
slice:     .zero 14400
slice_end:
o_aligned: .zero 4320
p1buf:     .zero 5120
group_buf: .zero 1280
frame:     .zero 32
p2buf:     .zero 1024

.section .text.start
.balign 4
.global main
main:
    lw   x4, 0(x0)            /* phase */
    beq  x4, x0, _INIT
    li   x5, 1
    beq  x4, x5, _WINDOW
    jal  x0, _bad_args

/* ============================ INIT ============================ */
_INIT:
    bn.xor w31, w31, w31
    la x2, group_buf          /* p1buf_end; expandsk frame grows down */
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid, high zero) */
    addi x12, x2, 32
    la x11, o_aligned
    li x6, 0
    loopi 135, 2
        bn.lid x6, 0(x12++)
        bn.sid x6, 0(x11++)
    la x10, pk_seed
    jal x1, backend_init_once
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x8, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count (outer-owned seam arg) */
    sw x8, 4(x3)
    beq x18, x0, _bad_args
    or   x30, x8, x18         /* pre-gate cs|cc < 64: the signed-trick */
    srli x30, x30, 6          /* checks below wrap on huge inputs */
    bne  x30, x0, _bad_args
    addi x30, x18, -6    /* col_count <= 5 */
    srli x30, x30, 31
    beq  x30, x0, _bad_args
    li   x30, 44           /* col_start <= 44 */
    sub  x30, x30, x8
    srli x30, x30, 31
    bne  x30, x0, _bad_args
    add  x30, x8, x18
    li   x29, 45             /* col_start + col_count <= 45 */
    sub  x29, x29, x30
    srli x29, x29, 31
    bne  x29, x0, _bad_args
    bn.xor w31, w31, w31
    la x6, o_aligned
    sw x6, 0(x3)              /* true O base (folds) */
    slli x7, x8, 6
    slli x30, x8, 5
    add  x7, x7, x30          /* col_start*96 */
    add  x6, x6, x7
    sw x6, 16(x3)             /* window O base (reduce) */
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    la x10, pk_seed
    jal x1, backend_window_init
    /* zero the FULL 5-wide slice (fixed-320 layout, all windows) */
    li x8, 31
    la x10, slice
    li x30, 450
    loop x30, 1
        bn.sid x8, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 18, 323
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_0
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_0:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_1
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_1:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 320
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_2
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_2:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 640
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_3
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_3:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 960
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    lw x4, 0(x3)
    addi x21, x7, -4
    la x12, group_buf
    la x11, slice
    jal x1, backend_gf256_fold4_entries
    nop
    /* ---- tail: rows 72,73 (true 2-row fold) ---- */
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_T0
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_T0:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    /* P1 restream for row x7 */
    srli x21, x9, 3
    andi x15, x9, 7
    lw x11, 20(x3)
    slli x8, x15, 6
    add x8, x8, x11
    sw x8, 28(x3)
    li x8, 74
    sub x8, x8, x7
    add x8, x8, x15
    addi x8, x8, 7
    srli x8, x8, 3
    loop x8, 10
        slli x13, x21, 5
        slli x30, x21, 3
        add  x13, x13, x30
        slli x30, x21, 2
        add  x13, x13, x30
        add  x13, x13, x21
        srli x13, x13, 1
        andi x16, x21, 1
        jal x1, backend_aes_ctr_batch
        addi x21, x21, 1
    /* P2: g = 2775 + 45*row + col_start */
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    add  x8, x8, x7
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2775
    add  x8, x8, x30
    srli x21, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    lw x11, 24(x3)
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_T1
    slli x13, x21, 5
    slli x30, x21, 3
    add  x13, x13, x30
    slli x30, x21, 2
    add  x13, x13, x30
    add  x13, x13, x21
    srli x13, x13, 1
    andi x16, x21, 1
    jal x1, backend_aes_ctr_batch
    addi x21, x21, 1
_bskip_T1:
    lw x13, 16(x3)
    lw x14, 28(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 320
    li x20, 74
    sub x20, x20, x7
    jal x1, backend_gf256_reduce_entries
    li x8, 74
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    lw x4, 0(x3)
    addi x21, x7, -2
    la x12, group_buf
    la x11, slice
    jal x1, backend_gf256_fold2_entries
    csrrw x0, mod1, x0
    sw x0, 12(x0)
    ecall

_bad_args:
    csrrw x0, mod1, x0
    li x6, -2
    sw x6, 12(x0)
    ecall

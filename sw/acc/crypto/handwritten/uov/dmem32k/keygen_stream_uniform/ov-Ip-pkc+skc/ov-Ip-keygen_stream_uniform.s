/* ov-Ip-keygen_stream_uniform.s - streamed UOV-Ip keygen, swappable-backend outer (WJ=5).
 * Backend-neutral: all AES/GF work via the backend_* ABI (contract in
 * ov-Ip-keygen_backend.s); the SAME object links against each backend
 * adapter, so arm deltas measure the backend alone. Host contract = stream kernel
 * (phase 0 INIT / phase 1 WINDOW(col_start, col_count<=5), fixed-320
 * slice, 9 windows: 8x5+4).
 * clob: everything. mod1 = 0 on every phase exit.
 * stack: INIT overlays slice (expandsk 3,040B); WINDOW x2 backend-owned.
 */
.section .data
.balign 32
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
slice:     .zero 14080
slice_end:
o_aligned: .zero 4224
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
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li   x6, -2
    sw   x6, 12(x0)           /* invalid phase */
    ecall

/* ============================ INIT ============================ */
_INIT:
    la x2, slice_end          /* expandsk overlays the slice (3,040B) */
    bn.xor w31, w31, w31
    la x11, sk_seed
    jal x1, expandsk_ret_O_pkseed   /* x2 -= 3040; pk_seed@x2, O@x2+32 */
    bn.ld w0, 0(x2)
    la x5, pk_seed
    bn.sd w0, 0(x5)           /* pk_seed ctx (low 16B valid, high zero) */
    la x10, pk_seed
    jal x1, backend_init_once
    la x3, frame
    la x5, o_aligned
    sw x5, 16(x3)             /* align-block dest */
    addi x12, x2, 32          /* raw O source */
    /* ---- O-align (P3_cal Phase 1 verbatim) ---- */
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    lw x11, 16(x3)                  # O aligned dest base
    li x9, 17                       # WDR idx for w17 (temp)
    li x29, 1                       # WDR idx for w1
    li x30, 2                       # WDR idx for w2

    loopi 5, 57                     # 5 full batches x 8 cols = 40 cols
        li x8, 0                    # WDR load idx
        loopi 17, 2                 # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)           # w0
        bn.sid x29, 32(x11)         # w1
        bn.sid x30, 64(x11)         # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128  # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                        # WDR load idx
    loopi 9, 2                      # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)               # w0
    bn.sid x29, 32(x11)             # w1
    bn.sid x30, 64(x11)             # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96       # hi
    bn.sid x9, 64(x11)

    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

/* ============================ WINDOW ============================ */
_WINDOW:
    la x3, frame
    lw x5, 4(x0)              /* col_start */
    lw x18, 8(x0)             /* col_count */
    sw x5, 4(x3)
    beq x18, x0, _bad_args    /* zero-col window: reject (loop-0 traps) */
    /* reject high bits (>=64) first so a huge unsigned col_start/col_count
     * cannot wrap the sign-bit checks below (e.g. col_start=0xffffffff). */
    or   x6, x5, x18
    srli x6, x6, 6
    bne  x6, x0, _bad_args    /* col_start or col_count >= 64 */
    li   x6, 5
    sub  x6, x6, x18
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_count <= 5 */
    li   x6, 43
    sub  x6, x6, x5
    srli x6, x6, 31
    bne  x6, x0, _bad_args    /* col_start <= 43 (kills cs+wc wrap) */
    add  x6, x5, x18
    li   x7, 44
    sub  x7, x7, x6
    srli x7, x7, 31
    bne  x7, x0, _bad_args    /* col_start + col_count <= 44 */
    bn.xor w31, w31, w31
    la x6, o_aligned
    sw x6, 0(x3)              /* true O base (fold) */
    slli x7, x5, 6
    slli x8, x5, 5
    add  x7, x7, x8           /* col_start*96 */
    add  x6, x6, x7
    sw x6, 16(x3)             /* window O base */
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    la x10, pk_seed
    jal x1, backend_window_init
    /* zero the FULL 5-wide slice (fixed-320 layout, all windows) */
    li x31, 31
    la x10, slice
    li x8, 440
    loop x8, 1
        bn.sid x31, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 17, 271
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4
    slli x8, x29, 2
    add x30, x30, x8
    slli x8, x29, 1
    add x30, x30, x8                   # x30 = batch*22
    add x13, x0, x30                   # logical AES-CTR counter
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, backend_aes_ctr_batch
        nop
    lw x14, 20(x3)
    andi x29, x9, 7                    # offset again (x15 not preserved)
    slli x29, x29, 6
    add x14, x14, x29
    sw x14, 28(x3)                     # adjusted P1 read ptr
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30                   # 44r
    lw   x30, 4(x3)                    # col_start
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30                   # g
    srli x30, x8, 3                    # batch
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)                    # off*64
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1                   # 22*batch
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, backend_aes_ctr_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_0
    jal x1, backend_aes_ctr_batch
_bskip_0:
    lw x13, 16(x3)                     # window O base (col records)
    lw x14, 28(x3)                     # adjusted P1 read ptr
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8                   # P2 read ptr = p2buf + off*64
    li x20, 68
    sub x20, x20, x7                   # nrows = 68-r
    la x22, group_buf
    jal x1, backend_gf256_reduce_entries
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8                     # cumulative element count
    addi x7, x7, 1
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4
    slli x8, x29, 2
    add x30, x30, x8
    slli x8, x29, 1
    add x30, x30, x8                   # x30 = batch*22
    add x13, x0, x30                   # logical AES-CTR counter
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, backend_aes_ctr_batch
        nop
    lw x14, 20(x3)
    andi x29, x9, 7                    # offset again (x15 not preserved)
    slli x29, x29, 6
    add x14, x14, x29
    sw x14, 28(x3)                     # adjusted P1 read ptr
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30                   # 44r
    lw   x30, 4(x3)                    # col_start
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30                   # g
    srli x30, x8, 3                    # batch
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)                    # off*64
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1                   # 22*batch
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, backend_aes_ctr_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_1
    jal x1, backend_aes_ctr_batch
_bskip_1:
    lw x13, 16(x3)                     # window O base (col records)
    lw x14, 28(x3)                     # adjusted P1 read ptr
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8                   # P2 read ptr = p2buf + off*64
    li x20, 68
    sub x20, x20, x7                   # nrows = 68-r
    la x22, group_buf
    addi x22, x22, 320
    jal x1, backend_gf256_reduce_entries
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8                     # cumulative element count
    addi x7, x7, 1
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4
    slli x8, x29, 2
    add x30, x30, x8
    slli x8, x29, 1
    add x30, x30, x8                   # x30 = batch*22
    add x13, x0, x30                   # logical AES-CTR counter
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, backend_aes_ctr_batch
        nop
    lw x14, 20(x3)
    andi x29, x9, 7                    # offset again (x15 not preserved)
    slli x29, x29, 6
    add x14, x14, x29
    sw x14, 28(x3)                     # adjusted P1 read ptr
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30                   # 44r
    lw   x30, 4(x3)                    # col_start
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30                   # g
    srli x30, x8, 3                    # batch
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)                    # off*64
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1                   # 22*batch
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, backend_aes_ctr_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_2
    jal x1, backend_aes_ctr_batch
_bskip_2:
    lw x13, 16(x3)                     # window O base (col records)
    lw x14, 28(x3)                     # adjusted P1 read ptr
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8                   # P2 read ptr = p2buf + off*64
    li x20, 68
    sub x20, x20, x7                   # nrows = 68-r
    la x22, group_buf
    addi x22, x22, 640
    jal x1, backend_gf256_reduce_entries
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8                     # cumulative element count
    addi x7, x7, 1
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4
    slli x8, x29, 2
    add x30, x30, x8
    slli x8, x29, 1
    add x30, x30, x8                   # x30 = batch*22
    add x13, x0, x30                   # logical AES-CTR counter
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, backend_aes_ctr_batch
        nop
    lw x14, 20(x3)
    andi x29, x9, 7                    # offset again (x15 not preserved)
    slli x29, x29, 6
    add x14, x14, x29
    sw x14, 28(x3)                     # adjusted P1 read ptr
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30                   # 44r
    lw   x30, 4(x3)                    # col_start
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30                   # g
    srli x30, x8, 3                    # batch
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)                    # off*64
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1                   # 22*batch
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, backend_aes_ctr_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_3
    jal x1, backend_aes_ctr_batch
_bskip_3:
    lw x13, 16(x3)                     # window O base (col records)
    lw x14, 28(x3)                     # adjusted P1 read ptr
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8                   # P2 read ptr = p2buf + off*64
    li x20, 68
    sub x20, x20, x7                   # nrows = 68-r
    la x22, group_buf
    addi x22, x22, 960
    jal x1, backend_gf256_reduce_entries
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8                     # cumulative element count
    addi x7, x7, 1
    addi x21, x7, -4                   # i0 = first row of the group
    lw x4, 0(x3)                       # o_aligned base
    la x12, group_buf
    la x11, slice
    jal x1, backend_gf256_fold4_entries
    nop
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li x6, -2
    sw x6, 12(x0)
    ecall

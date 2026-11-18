/* ov-Ip-keygen_stream_sw.s - streamed UOV-Ip keygen (sw tier, 32 KiB DMEM
 * target). T-table AES (GPR x13 counter, DMEM RKs derived once in INIT) +
 * gf256_macc_dualvec_sw dots. SW AES, but the GF dots use bn.mulv.l, so this
 * still needs the PQC vector datapath - it is not a PQC-free tier.
 *   phase 0 INIT  : expandsk -> pk_seed ctx + RK buf + O-aligned ctx
 *   phase 1 WINDOW(arg0=col_start, arg1=col_count<=5): slice[k][j] =
 *           sum_i O[i][k]*B[i][col_start+j], B = P1*O+P2 restreamed.
 * Fixed-320 slice layout: entry (k,j) at slice + k*320 + j*64 (44B valid +
 * 20B zero pad); kernel zeroes the full slice per WINDOW; host reads
 * col_count cols out BEFORE the next call. 9 windows (8x5+4).
 * P2 stream: entry p = 44*row+col is global CTR entry g = 2346+p; batch =
 * g>>3, x13 = 22*batch, 2 batches expanded, read at p2buf + (g&7)*64.
 * mod1 = 0 on every phase exit (nothing here sets it). clob: everything.
 * stack: INIT overlays slice (expandsk 3,040B); WINDOW uses the static
 * frame + swstack (expand_batch GPR saves + AES staging, 416B).
 */
.section .data
.balign 32
/* Everything (incl. the linked 4 KiB AES128_TABLE appended after this
 * .data) ends ~30.6 KiB < 31,744: the whole map is bus-visible, nothing
 * straddles the boundary, no scratch placement needed on this tier. */
ctrl:      .word 0, 0, 0, 0
           .zero 16
sk_seed:   .zero 32
pk_seed:   .zero 32
.globl slice
.globl slice_end
slice:     .zero 14080
slice_end:
o_aligned: .zero 4224
p1buf:     .zero 5120
group_buf: .zero 1280
frame:     .zero 32
rkbuf:     .zero 192
swstack:   .zero 416
swstack_end:
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
    /* SW AES key schedule once: pk_seed -> rkbuf (DMEM persists).
     * Clobbers x5-x8, x11-x18, x29-x31 -> runs BEFORE the O-align setup. */
    la x10, pk_seed
    la x11, rkbuf
    jal x1, AES_128_keyschedule
    addi x12, x2, 32          /* raw O source */
    /* ---- O-align (P3_cal Phase 1 verbatim) ---- */
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    la x11, o_aligned               # O aligned dest base
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
    /* bounds (beq/bne-only ISA: sub + srli sign trick) */
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
    sw x6, 16(x3)             /* window O base (col walk via setup) */
    la x6, p1buf
    sw x6, 20(x3)
    la x6, p2buf
    sw x6, 24(x3)
    la x6, rkbuf
    sw x6, 8(x3)              /* expand_batch reads RKs from slot 8 */
    la x2, swstack_end        /* expand_batch pushes its saves here */
    /* macc consts (persist: expand_batch clobbers w0-w11 only) */
    li x9, 16
    la x14, msb_mask
    bn.lid x9, 0(x14)         /* w16 = 0x80 per byte */
    bn.addi w17, w31, 0x1b    /* w17.0 = reduction constant */
    /* WDR-index GPR constants */
    li x23, 6
    li x26, 3
    li x27, 4
    li x28, 5
    /* zero the FULL 5-wide slice (fixed-320 layout, all windows) */
    la x10, slice
    li x8, 440
    loop x8, 1
        bn.sd w31, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 17, 351
    jal x1, phase4_row_setup
    add x20, x0, x8
    li x24, 7
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_0
    jal x1, expand_batch
_bskip_0:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 29
        add x14, x0, x5
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_0
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_0:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_1
    jal x1, expand_batch
_bskip_1:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 320
    loop x18, 29
        add x14, x0, x5
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_1
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_1:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_2
    jal x1, expand_batch
_bskip_2:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 640
    loop x18, 29
        add x14, x0, x5
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_2
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_2:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    jal x1, phase4_row_setup
    add x20, x0, x8
    slli x8, x7, 5
    slli x30, x7, 3
    add  x8, x8, x30
    slli x30, x7, 2
    add  x8, x8, x30
    lw   x30, 4(x3)
    add  x8, x8, x30
    li   x30, 2346
    add  x8, x8, x30
    srli x30, x8, 3
    andi x8, x8, 7
    slli x8, x8, 6
    sw   x8, 12(x3)
    slli x29, x30, 2
    add  x29, x29, x30
    slli x29, x29, 1
    add  x29, x29, x30
    slli x29, x29, 1
    add  x13, x0, x29
    lw x11, 24(x3)
    jal x1, expand_batch
    lw x8, 12(x3)
    srli x8, x8, 6
    add x8, x8, x18
    addi x8, x8, -9
    srli x8, x8, 31
    bne x8, x0, _bskip_3
    jal x1, expand_batch
_bskip_3:
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    addi x22, x22, 960
    loop x18, 29
        add x14, x0, x5
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        beq x7, x0, _nskip_3
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_nskip_3:
        bn.xor w20, w20, w20
        bn.xor w30, w30, w30
        loop x20, 9
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    addi x21, x7, -4
    li x30, 96
    li x29, 320
    li x19, 20
    li x17, 30
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    lw x5, 0(x3)
    add x5, x5, x21
    loop x18, 49
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 320(x12)
      addi x8, x8, 1
      bn.lid x8, 352(x12)
      addi x8, x8, 1
      bn.lid x8, 640(x12)
      addi x8, x8, 1
      bn.lid x8, 672(x12)
      addi x8, x8, 1
      bn.lid x8, 960(x12)
      addi x8, x8, 1
      bn.lid x8, 992(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 44, 28
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        bn.ld w14, 0(x24)
        bn.lid x19, 0(x10)
        bn.lid x17, 32(x10)
        bn.mov w0, w2
        bn.mov w1, w3
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w4
        bn.mov w1, w5
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w6
        bn.mov w1, w7
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.rshi w14, w31, w14 >> 8
        bn.mov w0, w8
        bn.mov w1, w9
        bn.mov w19, w14
        jal x1, gf256_macc_dualvec_sw
        bn.sd w20, 0(x10)
        bn.sd w30, 32(x10)
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    sw x0, 12(x0)             /* status = 0 */
    ecall

_bad_args:
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    li x6, -2
    sw x6, 12(x0)
    ecall

/* ===== expand_batch: 22 AES-CTR blocks via aes128table_352 (rk slot 8), repacked ===== */
expand_batch:
    # SWONLY AES-CTR: single jal aes128table_352 wraps 22 AES blocks
    # aes128table_352 ABI: x10 = RK buf addr (input; clobbered internally),
    #                       x11 = output buf (352 B written), x13 = counter (in: start, out: start+22).
    # Clobbers: x6, x7, x9, x10, x11, x12, x28, x30 + all of AES_128_encrypt's clobbers
    # (x5..x8, x13..x16, x19..x22, x29, x31). Save+restore caller's live GPRs.
    addi x2, x2, -416                       # alloc 352 B staging + 64 B for 7 caller-saves (32-B aligned)
    sw x5,  352(x2)                         # save caller x5 (the cached P1 read ptr; aes128table_352 inner AES_128_encrypt clobbers x5..x8)
    sw x7,  360(x2)                         # save caller x7 (row counter)
    sw x9,  364(x2)                         # save caller x9 (cumulative P1 entries)
    sw x11, 372(x2)                         # save caller x11 (buf write cursor; advances by 512 across this call)
    sw x15, 380(x2)                         # save caller x15 (batch offset; row setup reads it after its expand loop)
    sw x20, 388(x2)                         # save caller x20 (68-r, the inner walk count once set; AES_128_encrypt clobbers x19..x22)
    sw x28, 400(x2)                         # save caller x28 (= 5 = w5 WDR idx; aes128table_352 clobbers x28 as rk-save)
    # (x29 not saved: the caller recomputes it after each call)

    # Single call to aes128table_352 produces 352 B of AES-CTR keystream.
    lw x10, 8(x3)                           # x10 = RK buf base (slot 8, set in the WINDOW prologue)
    addi x11, x2, 0                         # x11 = output buf = staging base
    # x13 IN: caller-supplied AES counter.
    jal x1, aes128table_352                 # writes 352 B keystream at x11, x13 += 22 on exit

    # Reload 22 single-block (= 11 dual-block-in-WDR) ciphertexts into w0..w10.
    bn.ld w0, 0(x2)
    bn.ld w1, 32(x2)
    bn.ld w2, 64(x2)
    bn.ld w3, 96(x2)
    bn.ld w4, 128(x2)
    bn.ld w5, 160(x2)
    bn.ld w6, 192(x2)
    bn.ld w7, 224(x2)
    bn.ld w8, 256(x2)
    bn.ld w9, 288(x2)
    bn.ld w10, 320(x2)

    # Rebuild w13 = mask96 (aes128table_352 doesn't touch WDRs, but caller assumed w13 stale across phases)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160

    # Restore caller-saved GPRs (7 saved, matching the prologue list)
    lw x5,  352(x2)
    lw x7,  360(x2)
    lw x9,  364(x2)
    lw x11, 372(x2)
    lw x15, 380(x2)
    lw x20, 388(x2)
    lw x28, 400(x2)
    addi x2, x2, 416                        # free 416 B staging buffer

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.sd w0, 0(x11++)                      # lo = w0, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sd w11, 0(x11++)                     # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sd w11, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sd w11, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.sd w11, 0(x11++)

    ret

/* phase4_row_setup: P1 re-expand for row x7 (sw: x13 GPR counter) */
phase4_row_setup:
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4
    slli x8, x29, 2
    add x30, x30, x8
    slli x8, x29, 1
    add x30, x30, x8                   # x30 = batch*22
    add x13, x0, x30                   # AES-CTR counter
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x14, 20(x3)
    slli x29, x15, 6
    add x14, x14, x29
    add x5, x0, x14                    # adjusted P1 read ptr, kept in x5
    li x8, 68
    sub x8, x8, x7                     # x8 = 68-r
    ret

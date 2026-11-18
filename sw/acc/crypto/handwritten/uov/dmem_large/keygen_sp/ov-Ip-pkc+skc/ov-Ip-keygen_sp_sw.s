/* ov-Ip-keygen_sp_sw.s - one-shot UOV-Ip keygen, single pass over P1,
 * software GF (gf256 sw dots); the AES leaf decides the arm: T-table (sw) or
 * aes128_mem (bnaesonly). Every P1 row is expanded once and folded into all 44
 * oil columns; the P3 accumulator is the upper triangle in 64B cells (tri),
 * packed in place into the 44B cpk slots at the end. Host contract as _min:
 * write sk_seed, EXECUTE, read cpk 43,576B + csk. Bodies from
 * ov-Ip-keygen_min_sw.s; stage 2 visits (k, c) in _min's order with
 * T column c resident, cell = tri(min(k,c), max(k,c)). Guard bytes after cpk
 * are re-zeroed after the pack (tri overlays them). mod1 = 0 on exit.
 * clob: everything (app, no caller). stack: INIT overlays tri (expandsk
 * 3,040B); the window uses the frame + swstack (expand_batch 416B).
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid, high zero) */
cpk:       .zero 16           /* 32B-aligned; prefix copied at the end */
cpk_payload: .zero 80         /* 990 x 44B slots, packed in place at the end; the slots
                               * continue inside tri (payload ends at tri + 43,480) */
tri:       .zero 63360        /* 990 x 64B upper-tri cells, cell(a,b) at 64*(44a - a(a-1)/2 + b - a) */
tri_end:
o_aligned: .zero 4224
p1buf:     .zero 5120
group_buf: .zero 2816         /* T rows of the current 4-row group, 44 x 64B per row */
group_row1: .zero 2816
group_row2: .zero 2816
group_row3: .zero 2816
frame:     .zero 64
rkbuf:     .zero 192          /* AES round keys, scheduled once in INIT */
swstack:   .zero 416          /* expand_batch frame: 352B staging + 13 caller saves */
swstack_end:
p2buf:     .zero 3584         /* one P2 row: up to 7 batches of 8 entries; stage-2 scratch word */

.section .text.start
.balign 4
.global main
main:
_INIT:
    la x2, tri_end            /* expandsk overlays tri (3,040B), dead until zeroed */
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

    /* window loop: runtime-init state in the frame extension */
    /* one-time setup (the _min window loop body, run once): col_start 0, 44 cols */
    la   x3, frame
    li   x5, 0
    sw   x5, 4(x3)            /* col_start */
    li   x18, 44
    sw   x18, 32(x3)          /* wc: the bodies reload x18 from here */
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
    li x31, 31
    li x23, 6
    li x24, 7
    li x25, 8
    li x6,  9
    li x26, 3
    li x27, 4
    li x28, 5
    li x16, 11
    /* zero the 63,360B triangle once (x31 = 31 set above) */
    la x10, tri
    li x8, 1980
    loop x8, 1
        bn.sid x31, 0(x10++)
    li x9, 0
    li x7, 0
    /* ---- 17 groups of 4 rows ---- */
    loopi 17, 384
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 51
    srli x8, x8, 3            /* (off2 + 44 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_buf
    loop x18, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 51
    srli x8, x8, 3            /* (off2 + 44 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row1
    loop x18, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 51
    srli x8, x8, 3            /* (off2 + 44 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row2
    loop x18, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
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
    lw x8, 12(x3)
    srli x8, x8, 6
    addi x8, x8, 51
    srli x8, x8, 3            /* (off2 + 44 + 7) >> 3 = 6 or 7 batches */
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x12, 16(x3)
    lw x15, 24(x3)
    lw x8, 12(x3)
    add x15, x15, x8
    la x22, group_row3
    loop x18, 31
        lw x14, 28(x3)
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
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    li x8, 68
    sub x8, x8, x7
    add x9, x9, x8
    addi x7, x7, 1
    /* stage 2: T column c (4 rows, w2..w9) against O column k (word at row r0,
     * one byte per row via rshi), cell tri(min(k,c), max(k,c)) */
    addi x21, x7, -4
    li   x30, 96
    lw   x24, 24(x3)          /* p2buf: scratch word for the O bytes (dead between rows) */
    la   x12, group_buf
    la   x10, tri
    li   x20, 0
    loop x18, 82
      bn.ld w2, 0(x12)
      bn.ld w3, 32(x12)
      bn.ld w4, 2816(x12)
      bn.ld w5, 2848(x12)
      bn.ld w6, 5632(x12)
      bn.ld w7, 5664(x12)
      bn.ld w8, 8448(x12)
      bn.ld w9, 8480(x12)
      lw   x4, 0(x3)
      add  x4, x4, x21          /* O column 0, row r0 */
      li   x29, 2752            /* 64 x 43: cell(k,c) -> cell(k+1,c) for k = 0 */
      beq  x20, x0, _sp2_d      /* c = 0: nothing above the diagonal */
      loop x20, 30
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        bn.ld w20, 0(x10)
        bn.ld w30, 32(x10)
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
        add  x10, x10, x29
        addi x29, x29, -64
_sp2_d:
      li   x8, 44
      sub  x8, x8, x20          /* k = c .. 43, contiguous cells */
      loop x8, 29
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
        bn.ld w20, 0(x10)
        bn.ld w30, 32(x10)
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
        addi x10, x10, 64
      addi x20, x20, 1
      addi x12, x12, 64
      la   x10, tri
      slli x8, x20, 6
      add  x10, x10, x8         /* cell(0, c+1) */
    nop
_pack:
    /* tri cells (64B stride) -> packed 44B slots, front to back, in place */
    la   x24, tri
    la   x22, cpk_payload
    loopi 990, 6
        loopi 11, 4
            lw   x8, 0(x24)
            sw   x8, 0(x22)
            addi x24, x24, 4
            addi x22, x22, 4
        addi x24, x24, 20
    sw   x0, 0(x22)           /* guard (8B after the payload) back to zero */
    sw   x0, 4(x22)
    /* cpk = pk_seed(16B) || compact payload (already in place) */
    la   x10, pk_seed
    la   x11, cpk
    lw   x12, 0(x10)
    sw   x12, 0(x11)
    lw   x12, 4(x10)
    sw   x12, 4(x11)
    lw   x12, 8(x10)
    sw   x12, 8(x11)
    lw   x12, 12(x10)
    sw   x12, 12(x11)
    csrrw x0, mod1, x0        /* pin mod1 = 0 on exit */
    ecall


/* ===== expand_batch: monolith P1O_P2.s sw arm verbatim (rk slot 8) ===== */
expand_batch:
    # SWONLY AES-CTR: single jal aes128table_352 wraps 22 AES blocks
    # aes128table_352 ABI: x10 = RK buf addr (input, preserved by caller; clobbered internally),
    #                       x11 = output buf (352 B written), x13 = counter (in: start, out: start+22).
    # Clobbers: x6, x7, x9, x10, x11, x12, x28, x30 + all of AES_128_encrypt's clobbers
    # (x5..x8, x13..x16, x19..x22, x29, x31). Save+restore caller's live GPRs.
    addi x2, x2, -416                       # alloc 352 B staging + 64 B for 13 caller-saves (32-B aligned)
    sw x5,  352(x2)                         # save caller x5 (= 1, w1 WDR idx; aes128table_352 inner AES_128_encrypt clobbers x5..x8)
    sw x6,  356(x2)                         # save caller x6 (= 9, w9 WDR idx)
    sw x7,  360(x2)                         # save caller x7 (Phase 4 row counter)
    sw x9,  364(x2)                         # save caller x9 (Phase 2 batch idx OR Phase 4 cumulative)
    sw x10, 368(x2)                         # save caller x10 (result cursor)
    sw x11, 372(x2)                         # save caller x11 (buf write cursor; advances by 512 across this call)
    sw x14, 376(x2)                         # save caller x14 (Phase 4 P1 read ptr / adjusted)
    sw x15, 380(x2)                         # save caller x15 (Phase 2/4 batch base addr / offset)
    sw x16, 384(x2)                         # save caller x16 (= 11 = w11 WDR idx for repack)
    sw x20, 388(x2)                         # save caller x20 (= 15 = w15 WDR idx; AES_128_encrypt clobbers x19..x22)
    sw x21, 392(x2)                         # save caller x21 (= 16 = w16 WDR idx)
    sw x22, 396(x2)                         # save caller x22 (= 10 = w10 WDR idx)
    sw x28, 400(x2)                         # save caller x28 (= 5 = w5 WDR idx; aes128table_352 clobbers x28 as rk-save)
    # (x29 not saved: caller recomputes in Phase 4; AES_128_encrypt clobber x29 OK)
    addi x12, x2, 0                         # x12 = staging buf base ptr

    # Single call to aes128table_352 produces 352 B of AES-CTR keystream.
    lw x10, 8(x3)                           # x10 = RK buf base (set in P1O_P2 prologue)
    addi x11, x2, 0                         # x11 = output buf = staging base
    # x13 IN: caller-supplied current counter (set by outer Phase 2/3/4 code).
    jal x1, aes128table_352                 # writes 352 B keystream at x11, x13 += 22 on exit
    addi x12, x2, 0                         # re-derive x12 (aes128table_352 clobbers x12)

    # Reload 22 single-block (= 11 dual-block-in-WDR) ciphertexts into w0..w10.
    li x14, 0
    bn.lid x14, 0(x12)
    li x14, 1
    bn.lid x14, 32(x12)
    li x14, 2
    bn.lid x14, 64(x12)
    li x14, 3
    bn.lid x14, 96(x12)
    li x14, 4
    bn.lid x14, 128(x12)
    li x14, 5
    bn.lid x14, 160(x12)
    li x14, 6
    bn.lid x14, 192(x12)
    li x14, 7
    bn.lid x14, 224(x12)
    li x14, 8
    bn.lid x14, 256(x12)
    li x14, 9
    bn.lid x14, 288(x12)
    li x14, 10
    bn.lid x14, 320(x12)

    # Rebuild w13 = mask96 (aes128table_352 doesn't touch WDRs, but caller assumed w13 stale across phases)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160

    # Restore caller-saved GPRs (13 saved, matching the prologue list)
    lw x5,  352(x2)
    lw x6,  356(x2)
    lw x7,  360(x2)
    lw x9,  364(x2)
    lw x10, 368(x2)
    lw x11, 372(x2)
    lw x14, 376(x2)
    lw x15, 380(x2)
    lw x16, 384(x2)
    lw x20, 388(x2)
    lw x21, 392(x2)
    lw x22, 396(x2)
    lw x28, 400(x2)
    addi x2, x2, 416                        # free 416 B staging buffer

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.mov w11, w0                          # lo = w0
    bn.sid x16, 0(x11++)                    # store lo, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sid x16, 0(x11++)                    # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.and w11, w11, w13                    # mask (redundant but consistent)
    bn.sid x16, 0(x11++)

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
    sw x14, 28(x3)                     # adjusted P1 read ptr
    li x8, 68
    sub x8, x8, x7                     # x8 = 68-r
    lw x12, 16(x3)                     # window O base (expand clobbered x12)
    ret

/* host interface for C (ACC_DECLARE_SYMBOL_ADDR): seed in, csk == seed, cpk out */
.globl sk_seed
.globl csk
.globl cpk

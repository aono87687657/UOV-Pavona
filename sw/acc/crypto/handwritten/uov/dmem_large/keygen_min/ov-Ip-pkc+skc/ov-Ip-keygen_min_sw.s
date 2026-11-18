/* ov-Ip-keygen_min_sw.s - one-shot UOV-Ip keygen, sw tier, minimal
 * DMEM. WJ=2: 22 windows re-expand P1 (more cycles, less DMEM); T-table AES
 * + gf16/gf256 sw dots. Accumulator is compact 44B slots, GPR word-written
 * (44 = 4x11, always 4B-aligned; no cpk_pack, no padding).
 * Host contract: write sk_seed, EXECUTE, read cpk 43,576B + csk.
 * Fold per slice col c: k >= c plain 11-word copies to the row-c segment;
 * k < c 11-word XOR-RMW slot(k,c). First touch each run = plain store ->
 * re-EXECUTE clean. Frame ext: +4 col_start | +32 wc | +36 seg_c | +40 c.
 * mod1 = 0 on exit. clob: everything (app, no caller).
 * stack: INIT overlays slice (expandsk 3,040B); WINDOW frame + swstack.
 */
.section .data
.balign 32
sk_seed:                      /* harness injects the KAT seed here */
csk:                          /* same buffer: csk == sk_seed, left in place */
    .zero 32
pk_seed:   .zero 32           /* INIT ctx (low 16B valid, high zero) */
cpk:       .zero 16           /* 32B-aligned; prefix copied at the end */
cpk_payload: .zero 43560      /* 990 x 44B compact upper-tri, GPR-written */
           .zero 8            /* verify overreads 8B past cpk; stays zero */
slice:     .zero 5632
slice_end:
o_aligned: .zero 4224
p1buf:     .zero 5120
group_buf: .zero 512
frame:     .zero 64
rkbuf:     .zero 192
swstack:   .zero 416
swstack_end:
p2buf:     .zero 1024

.section .text.start
.balign 4
.global main
main:
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
    la   x3, frame
    sw   x0, 36(x3)           /* seg_c */
    sw   x0, 40(x3)           /* c = next col_start */
_wloop:
    la   x3, frame
    lw   x5, 40(x3)           /* col_start = c */
    li   x18, 2               /* 22 exact windows (44 % 2 == 0) */
    sw   x5, 4(x3)
    sw   x18, 32(x3)          /* wc: fold reads this */
    /* falls into the spliced WINDOW body (post-validation) */
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
    /* zero the FULL 2-wide slice (fixed-128 layout, all windows) */
    la x10, slice
    li x8, 176
    loop x8, 1
        bn.sid x31, 0(x10++)
    li x9, 0
    li x7, 0
    loopi 17, 362
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
    addi x22, x22, 128
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
    addi x22, x22, 256
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
    addi x22, x22, 384
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
    addi x21, x7, -4
    li x30, 96
    li x29, 128
    li x19, 20
    li x17, 30
    lw x24, 24(x3)
    la x12, group_buf
    la x11, slice
    loop x18, 51
      li x8, 2
      bn.lid x8, 0(x12)
      addi x8, x8, 1
      bn.lid x8, 32(x12)
      addi x8, x8, 1
      bn.lid x8, 128(x12)
      addi x8, x8, 1
      bn.lid x8, 160(x12)
      addi x8, x8, 1
      bn.lid x8, 256(x12)
      addi x8, x8, 1
      bn.lid x8, 288(x12)
      addi x8, x8, 1
      bn.lid x8, 384(x12)
      addi x8, x8, 1
      bn.lid x8, 416(x12)
      lw x4, 0(x3)
      add x4, x4, x21
      add x10, x0, x11
      loopi 44, 29
        lw x8, 0(x4)
        add x4, x4, x30
        sw x8, 0(x24)
        li x8, 14
        bn.lid x8, 0(x24)
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
        bn.sid x19, 0(x10)
        bn.sid x17, 32(x10)
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    nop
    jal  x0, _fold


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

/* ---- fold-scatter: slice window cols -> compact 44B upper-tri accumulator ---- */
_fold:
    la   x3, frame
    lw   x14, 40(x3)          /* c = global col (cols strictly ascend) */
    lw   x15, 36(x3)          /* seg_c = payload offset of row-c segment */
    lw   x18, 32(x3)          /* col_count */
    la   x20, slice
    la   x21, cpk_payload
_fold_j:
    beq  x14, x0, _fold_ge    /* c = 0: nothing above the diagonal */
    /* k < c: XOR slot(k,c), 11-word GPR RMW (44B compact, 4B-aligned);
     * slice row stride 128, payload dst stride 44*(43-k) shrinking 44. */
    slli x22, x14, 5
    slli x23, x14, 3
    add  x22, x22, x23
    slli x23, x14, 2
    add  x22, x22, x23        /* 44c */
    add  x22, x21, x22        /* slot(0,c) */
    add  x24, x20, x0
    li   x23, 1848            /* 1,892 - the 44 the inner loop advances */
    loop x14, 10
        loopi 11, 6
            lw   x8, 0(x22)
            lw   x9, 0(x24)
            xor  x8, x8, x9
            sw   x8, 0(x22)
            addi x22, x22, 4
            addi x24, x24, 4
        addi x24, x24, 84     /* +44 done above -> 128B slice row stride */
        add  x22, x22, x23
        addi x23, x23, -44
_fold_ge:
    /* k >= c: contiguous 44B stores of the row-c segment; slice row c */
    add  x22, x21, x15
    li   x25, 44
    sub  x25, x25, x14
    slli x26, x14, 7
    add  x24, x20, x26        /* slice + c*128 (this col) */
    loop x25, 6
        loopi 11, 4
            lw   x8, 0(x24)
            sw   x8, 0(x22)
            addi x24, x24, 4
            addi x22, x22, 4
        addi x24, x24, 84
    /* seg_{c+1} = seg_c + 44*(44-c); advance col */
    slli x26, x14, 5
    slli x27, x14, 3
    add  x26, x26, x27
    slli x27, x14, 2
    add  x26, x26, x27        /* 44c */
    li   x27, 1936
    sub  x27, x27, x26
    add  x15, x15, x27
    addi x14, x14, 1
    addi x20, x20, 64
    addi x18, x18, -1
    bne  x18, x0, _fold_j
    sw   x14, 40(x3)          /* c == next col_start */
    sw   x15, 36(x3)
    li   x6, 44
    bne  x14, x6, _wloop
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

/* host interface for C (ACC_DECLARE_SYMBOL_ADDR): seed in, csk == seed, cpk out */
.globl sk_seed
.globl csk
.globl cpk

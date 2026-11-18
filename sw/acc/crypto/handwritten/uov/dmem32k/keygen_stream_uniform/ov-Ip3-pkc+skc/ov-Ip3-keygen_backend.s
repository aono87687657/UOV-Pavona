/* ov-Ip3-keygen_backend.s - backend arms for the Ip3 keygen stream_uniform outer.
 * Four backend arms behind the fixed backend_* ABI:
 *   -DAES_INSTRUCTIONS -DGF_INSTRUCTIONS  bngfaes  (inline HW AES + HW GF)
 *   -DGF_INSTRUCTIONS                     bngfonly (aes128_sign + HW GF)
 *   -DAES_INSTRUCTIONS                    bnaesonly(aes128hw_384_sign + SW GF)
 *   (none)                                sw       (T-table AES + SW GF)
 * HW-GF expansion leaf: expand_360 (its own arms pick inline vs aes128_sign).
 * SW-GF expansion leaf: expand_360_table (aesonly vs T-table arms).
 * Every fn re-establishes its own selector GPRs; x1 saved to a private word
 * around internal jals. Literal bn.ld/bn.sd wherever no post-inc is needed
 * (the R2 rig's persistent bn.lid x16/x17 selectors are UNSAFE here: the R3
 * leaves own x16 as phase state and bngfonly's leaf leaves x17=11).
 */
.section .data
.balign 32
backend_bounce: .zero 32
backend_x1s:    .word 0
#if defined(GF_INSTRUCTIONS) && !defined(AES_INSTRUCTIONS)
/* bngfonly: AES consts by name (constants lib NOT linked) + leaf stack
 * (448 expand_360 frame + 8 aes128_sign push; top 32-aligned). */
.balign 32
.global byte_swap_mask
byte_swap_mask:
    .word 0, 0, 0, 0x000000ff
    .word 0, 0, 0, 0x000000ff
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
.global shiftrow_mask
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b, 0
    .zero 16
.balign 32
backend_stack: .zero 480
backend_stack_end:
#endif
#ifndef GF_INSTRUCTIONS
/* table-arm leaf stack (expand_360_table 448-B frame) */
.balign 32
backend_stack: .zero 448
backend_stack_end:
#ifdef AES_INSTRUCTIONS
backend_keyptr: .word 0
#else
.balign 32
backend_rkbuf:  .zero 192
#endif
#endif

.section .text
.balign 4

/* INIT-time: only sw has a persistent derive (T-table RKs; DMEM persists). */
.global backend_init_once
backend_init_once:
#if !defined(AES_INSTRUCTIONS) && !defined(GF_INSTRUCTIONS)
    la x12, backend_x1s
    sw x1, 0(x12)
    la x11, backend_rkbuf
    jal x1, AES_128_keyschedule    /* x10 = pk_seed (in) */
    la x12, backend_x1s
    lw x1, 0(x12)
#endif
    ret

/* Per-WINDOW: keys / GF consts / private stack. in: x10=pk_seed, x18=cc. */
.global backend_window_init
backend_window_init:
#ifdef GF_INSTRUCTIONS
    la x12, backend_x1s
    sw x1, 0(x12)             /* bngfonly KS jals clobber x1 */
    li x8, 0x11b
    csrrw x0, mod0, x8
    csrrw x0, mod1, x0
    li x8, 30
    bn.lid x8, 0(x10)         /* w30 = pk_seed (AES key) */
#ifdef AES_INSTRUCTIONS
    bn.aes128.kf w29, w30, 1
    bn.aes128.kf w28, w29, 2
    bn.aes128.kf w27, w28, 3
    bn.aes128.kf w26, w27, 4
    bn.aes128.kf w25, w26, 5
    bn.aes128.kf w24, w25, 6
    bn.aes128.kf w23, w24, 7
    bn.aes128.kf w22, w23, 8
    bn.aes128.kf w21, w22, 9
    bn.aes128.kf w20, w21, 10
#else
    /* SW KS via KeySchedule_sign: RK1..RK10 dual-stored FORWARD in w20..w29
     * (aes128_sign layout), w30 = RK0 dual. Clobbers w7, w11..w17, x5. */
    la x2, backend_stack_end
    la x13, affine_value
    li x6, 8
    bn.lid x6, 0(x13)
    la x14, msb_mask
    li x6, 9
    bn.lid x6, 0(x14)
    la x15, rcon
    li x6, 11
    bn.lid x6, 0(x15)
    bn.mov w17, w30
    bn.or w30, w30, w30 << 128
    jal x1, KeySchedule_sign
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_sign
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_sign
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_sign
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_sign
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_sign
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_sign
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_sign
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_sign
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_sign
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128
    li x8, 0x11b
    csrrw x0, mod0, x8        /* KS left mod0=0x11B anyway; re-pin explicit */
#endif
    bn.addi w19, w31, 2       /* dual-block IV increment, positioned */
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    la x12, backend_x1s
    lw x1, 0(x12)
#else
    /* SW-GF arms: resident macc consts (leaves preserve w16..w31) */
    csrrw x0, mod1, x0
    li x8, 16
    la x14, msb_mask
    bn.lid x8, 0(x14)         /* w16 = 0x80 per byte */
    bn.addi w17, w31, 0x1b    /* w17.0 = reduction constant */
    la x2, backend_stack_end
#ifdef AES_INSTRUCTIONS
    la x12, backend_keyptr
    sw x10, 0(x12)            /* raw key ptr (x18 is outer-owned here) */
#endif
#endif
    ret

/* 8 P1/P2 entries: x11=dst, x13=canonical block ctr, x16=phase -> records. */
.global backend_aes_ctr_batch
backend_aes_ctr_batch:
    la x12, backend_x1s
    sw x1, 0(x12)
#ifdef GF_INSTRUCTIONS
    /* IV = [ctr+1 | ctr] positioned, via the private bounce slot */
    la x12, backend_bounce
    li x14, 31
    bn.sid x14, 0(x12)
    sw x13, 0(x12)
    li x14, 14
    bn.lid x14, 0(x12)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    jal x1, expand_360
#else
#ifdef AES_INSTRUCTIONS
    la x12, backend_keyptr
    lw x10, 0(x12)
#else
    la x10, backend_rkbuf
#endif
    jal x1, expand_360_table
#endif
    bn.sd w0, 0(x11)
    bn.sd w1, 32(x11)
    bn.sd w2, 64(x11)
    bn.sd w3, 96(x11)
    bn.sd w4, 128(x11)
    bn.sd w5, 160(x11)
    bn.sd w6, 192(x11)
    bn.sd w7, 224(x11)
    bn.sd w8, 256(x11)
    bn.sd w9, 288(x11)
    bn.sd w10, 320(x11)
    bn.sd w11, 352(x11)
    bn.sd w12, 384(x11)
    bn.sd w13, 416(x11)
    bn.sd w14, 448(x11)
    bn.sd w15, 480(x11)
    addi x11, x11, 512
    la x12, backend_x1s
    lw x1, 0(x12)
    ret

/* dst[e] = P2[e] ^ sum_{q<x20} P1[q] * O[e][x7+q], e < x18 */
.global backend_gf256_reduce_entries
backend_gf256_reduce_entries:
#ifdef GF_INSTRUCTIONS
    li x23, 6
    li x24, 7
    li x26, 3
    li x27, 4
    li x28, 5
    add x12, x0, x14           /* P1 stream base */
    /* bands from row x7: n3(w3)=x5, n4(w4)=x10, n5(w5)=x21, cursor=x30 */
    li x5, 0
    li x10, 0
    add x30, x0, x7
    addi x8, x7, -64
    srli x8, x8, 31
    beq x8, x0, _rh_bandC      /* x7 >= 64 */
    addi x8, x7, -32
    srli x8, x8, 31
    beq x8, x0, _rh_bandB      /* x7 >= 32 */
    li x8, 32
    sub x5, x8, x7             /* n3 = 32 - row */
    li x10, 32
    li x21, 10
    jal x0, _rh_go
_rh_bandB:
    li x8, 64
    sub x10, x8, x7            /* n4 = 64 - row */
    li x21, 10
    addi x30, x7, -32
    jal x0, _rh_go
_rh_bandC:
    li x8, 74
    sub x21, x8, x7            /* n5 = 74 - row */
    addi x30, x7, -64
_rh_go:
    loop x18, 32
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x12
        csrrw x0, mod1, x30
        beq x5, x0, _rh_s3
        loop x5, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
_rh_s3:
        beq x10, x0, _rh_s4
        loop x10, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
_rh_s4:
        loop x21, 4
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.ld w6, 0(x15)
        bn.ld w7, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    ret
#else
    la x12, backend_x1s
    sw x1, 0(x12)              /* macc jals clobber x1 */
    li x23, 6
    li x24, 7
    li x26, 3
    li x27, 4
    li x28, 5
    add x12, x0, x14           /* P1 stream base */
    loop x18, 29
        add x14, x0, x12
        bn.lid x26, 0(x13++)
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        beq x7, x0, _rs_nskip
        loop x7, 3
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_rs_nskip:
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
        bn.ld w6, 0(x15)
        bn.ld w7, 32(x15)
        bn.xor w8, w20, w6
        bn.xor w9, w30, w7
        bn.sd w8, 0(x22)
        bn.sd w9, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    la x12, backend_x1s
    lw x1, 0(x12)
    ret
#endif

/* slice[k,e] ^= sum_{q<4} group[q,e] * O[i0+q,k], k = 0..44, e < x18 */
#ifdef GF_INSTRUCTIONS
.global backend_gf256_fold4_entries
backend_gf256_fold4_entries:
    andi x14, x21, 31          /* cursor = i0 & 31 (no group crosses */
    sub x8, x21, x14           /* a 32-B band) -> band_off = i0 & ~31 */
    add x5, x4, x8
    li x30, 96
    li x29, 320
    loop x18, 31
      bn.ld w0, 0(x12)
      bn.ld w1, 32(x12)
      bn.ld w2, 320(x12)
      bn.ld w3, 352(x12)
      bn.ld w4, 640(x12)
      bn.ld w5, 672(x12)
      bn.ld w6, 960(x12)
      bn.ld w7, 992(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 18
        bn.ld w12, 0(x4)
        csrrw x0, mod1, x14
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.gfmul.8.acc      w8, w4, w12
        bn.gfmul.8.acch.inc w9, w5, w12
        bn.gfmul.8.acc      w8, w6, w12
        bn.gfmul.8.acch.inc w9, w7, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    ret

.global backend_gf256_fold2_entries
backend_gf256_fold2_entries:
    andi x14, x21, 31          /* cursor = i0 & 31 (no group crosses */
    sub x8, x21, x14           /* a 32-B band) -> band_off = i0 & ~31 */
    add x5, x4, x8
    li x30, 96
    li x29, 320
    loop x18, 23
      bn.ld w0, 0(x12)
      bn.ld w1, 32(x12)
      bn.ld w2, 320(x12)
      bn.ld w3, 352(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 14
        bn.ld w12, 0(x4)
        csrrw x0, mod1, x14
        bn.ld w10, 0(x10)
        bn.ld w11, 32(x10)
        bn.wsrw acc, w10
        bn.wsrw acch, w11
        bn.gfmul.8.acc      w8, w0, w12
        bn.gfmul.8.acch.inc w9, w1, w12
        bn.gfmul.8.acc      w8, w2, w12
        bn.gfmul.8.acch.inc w9, w3, w12
        bn.sd w8, 0(x10)
        bn.sd w9, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    ret
#else
.global backend_gf256_fold4_entries
backend_gf256_fold4_entries:
    la x24, backend_x1s
    sw x1, 0(x24)
    add x5, x4, x21            /* O scalar base = o_aligned + i0 */
    li x30, 96
    li x29, 320
    la x24, backend_bounce
    loop x18, 42
      bn.ld w2, 0(x12)
      bn.ld w3, 32(x12)
      bn.ld w4, 320(x12)
      bn.ld w5, 352(x12)
      bn.ld w6, 640(x12)
      bn.ld w7, 672(x12)
      bn.ld w8, 960(x12)
      bn.ld w9, 992(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 29
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
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    la x24, backend_x1s
    lw x1, 0(x24)
    ret

.global backend_gf256_fold2_entries
backend_gf256_fold2_entries:
    la x24, backend_x1s
    sw x1, 0(x24)
    add x5, x4, x21            /* O scalar base = o_aligned + i0 */
    li x30, 96
    li x29, 320
    la x24, backend_bounce
    loop x18, 28
      bn.ld w2, 0(x12)
      bn.ld w3, 32(x12)
      bn.ld w4, 320(x12)
      bn.ld w5, 352(x12)
      add x4, x0, x5
      add x10, x0, x11
      loopi 45, 19
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
        bn.sd w20, 0(x10)
        bn.sd w30, 32(x10)
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    la x24, backend_x1s
    lw x1, 0(x24)
    ret
#endif

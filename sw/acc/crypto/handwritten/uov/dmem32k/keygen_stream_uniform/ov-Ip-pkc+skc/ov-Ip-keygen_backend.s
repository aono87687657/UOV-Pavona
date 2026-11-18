/* ov-Ip-keygen_backend.s - backend arms for the keygen-Ip stream_uniform outer.
 * cpp picks the arm (same convention as the monolith kernels):
 *   bngfaes  -DAES_INSTRUCTIONS -DGF_INSTRUCTIONS  bn.aes128 CTR + bn.gfmul
 *   bngfonly -DGF_INSTRUCTIONS                     compute-AES + bn.gfmul
 *   sw       (none)                                T-table AES + gf256 dots
 * ABI + preserve/clobber convention: backend_* entry headers below.
 */
#if defined(GF_INSTRUCTIONS)
/* ----------------------------- hw arms ------------------------------
 * bngfaes (-DAES_INSTRUCTIONS -DGF_INSTRUCTIONS): bn.aes128 CTR + bn.gfmul.
 * bngfonly (-DGF_INSTRUCTIONS): KeySchedule_keygen/aes128_keygen SW AES +
 * bn.gfmul. Round keys w30..w20, w19=ctr inc, w13=mask96 per WINDOW (no
 * WDR persistence across ecall). GF reduce w3-w9 + ACC/ACCH + mod1; fold
 * w0-w12. Runtime scalar banding replaces the tuned kernels' compile-time
 * bands (call sites share one outer).
 */
.section .data
.balign 32
backend_hw_bounce: .zero 32
backend_hw_x1s:    .word 0
#ifndef AES_INSTRUCTIONS
/* bngfonly locals: AES consts (helpers reference by name; constants lib
 * not linked) + 352B expand staging. */
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
aes_stage: .zero 352
#endif

.section .text
.balign 4

/* INIT-time: HW arms have no persistent derive (RKs rebuilt per WINDOW). */
.global backend_init_once
backend_init_once:
    ret

/* Per-WINDOW: GF poly + RK derive (w30..w20) + stream consts + idx GPRs. */
.global backend_window_init
backend_window_init:
    la x12, backend_hw_x1s
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
    /* SW KS via KeySchedule_keygen: RK1..RK10 dual-stored FORWARD in
     * w20..w29 (aes128_keygen layout), w30 = RK0 dual. Clobbers w7,
     * w11..w16, x5, x13..x15 (all dead here). */
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
    jal x1, KeySchedule_keygen
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_keygen
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_keygen
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_keygen
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_keygen
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_keygen
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_keygen
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_keygen
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_keygen
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_keygen
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128
    li x8, 0x11b
    csrrw x0, mod0, x8        /* KS left mod0=0x11B anyway; re-pin explicit */
#endif
    bn.addi w19, w31, 2       /* CTR inc = 2 (dual-block), positioned */
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    bn.not w13, w31           /* mask96 for the repack */
    bn.rshi w13, w31, w13 >> 160
    li x23, 6
    li x24, 7
    li x25, 8
    li x6,  9
    li x26, 3
    li x27, 4
    li x28, 5
    li x16, 11                /* expand repack live-in */
    li x19, 12                /* fold O-scalar WDR idx */
    li x17, 10                /* fold slice-lo WDR idx */
    la x12, backend_hw_x1s
    lw x1, 0(x12)
    ret

/* 22 AES-CTR blocks from logical counter x13 -> 8x64B records at x11. */
.global backend_aes_ctr_batch
backend_aes_ctr_batch:
    la x12, backend_hw_x1s
    sw x1, 0(x12)
    /* IV = [ctr+1 | ctr] positioned, via private bounce slot */
    la x12, backend_hw_bounce
    li x14, 31
    bn.sid x14, 0(x12)
    sw x13, 0(x12)
    li x14, 14
    bn.lid x14, 0(x12)
    bn.addi w18, w14, 1
    bn.or w18, w14, w18 << 128
    bn.rshi w18, w18, w31 >> 160
    addi x13, x13, 22         /* contract: counter chains */
#ifdef AES_INSTRUCTIONS
    # AES-CTR: 11 parallel blocks
    bn.aes128.encz.swap w0, w18, w30        # block 0
    bn.add w18, w18, w19                    # IV += 2
    bn.aes128.encz.swap w1, w18, w30        # block 1
    bn.add w18, w18, w19
    bn.aes128.encz.swap w2, w18, w30        # block 2
    bn.add w18, w18, w19
    bn.aes128.encz.swap w3, w18, w30        # block 3
    bn.add w18, w18, w19
    bn.aes128.encz.swap w4, w18, w30        # block 4
    bn.add w18, w18, w19
    bn.aes128.encz.swap w5, w18, w30        # block 5
    bn.add w18, w18, w19
    bn.aes128.encz.swap w6, w18, w30        # block 6
    bn.add w18, w18, w19
    bn.aes128.encz.swap w7, w18, w30        # block 7
    bn.add w18, w18, w19
    bn.aes128.encz.swap w8, w18, w30        # block 8
    bn.add w18, w18, w19
    bn.aes128.encz.swap w9, w18, w30        # block 9
    bn.add w18, w18, w19
    bn.aes128.encz.swap w10, w18, w30       # block 10
    bn.add w18, w18, w19
    # Round 1
    bn.aes128.encm w0, w0, w29
    bn.aes128.encm w1, w1, w29
    bn.aes128.encm w2, w2, w29
    bn.aes128.encm w3, w3, w29
    bn.aes128.encm w4, w4, w29
    bn.aes128.encm w5, w5, w29
    bn.aes128.encm w6, w6, w29
    bn.aes128.encm w7, w7, w29
    bn.aes128.encm w8, w8, w29
    bn.aes128.encm w9, w9, w29
    bn.aes128.encm w10, w10, w29
    # Round 2
    bn.aes128.encm w0, w0, w28
    bn.aes128.encm w1, w1, w28
    bn.aes128.encm w2, w2, w28
    bn.aes128.encm w3, w3, w28
    bn.aes128.encm w4, w4, w28
    bn.aes128.encm w5, w5, w28
    bn.aes128.encm w6, w6, w28
    bn.aes128.encm w7, w7, w28
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    # Round 3
    bn.aes128.encm w0, w0, w27
    bn.aes128.encm w1, w1, w27
    bn.aes128.encm w2, w2, w27
    bn.aes128.encm w3, w3, w27
    bn.aes128.encm w4, w4, w27
    bn.aes128.encm w5, w5, w27
    bn.aes128.encm w6, w6, w27
    bn.aes128.encm w7, w7, w27
    bn.aes128.encm w8, w8, w27
    bn.aes128.encm w9, w9, w27
    bn.aes128.encm w10, w10, w27
    # Round 4
    bn.aes128.encm w0, w0, w26
    bn.aes128.encm w1, w1, w26
    bn.aes128.encm w2, w2, w26
    bn.aes128.encm w3, w3, w26
    bn.aes128.encm w4, w4, w26
    bn.aes128.encm w5, w5, w26
    bn.aes128.encm w6, w6, w26
    bn.aes128.encm w7, w7, w26
    bn.aes128.encm w8, w8, w26
    bn.aes128.encm w9, w9, w26
    bn.aes128.encm w10, w10, w26
    # Round 5
    bn.aes128.encm w0, w0, w25
    bn.aes128.encm w1, w1, w25
    bn.aes128.encm w2, w2, w25
    bn.aes128.encm w3, w3, w25
    bn.aes128.encm w4, w4, w25
    bn.aes128.encm w5, w5, w25
    bn.aes128.encm w6, w6, w25
    bn.aes128.encm w7, w7, w25
    bn.aes128.encm w8, w8, w25
    bn.aes128.encm w9, w9, w25
    bn.aes128.encm w10, w10, w25
    # Round 6
    bn.aes128.encm w0, w0, w24
    bn.aes128.encm w1, w1, w24
    bn.aes128.encm w2, w2, w24
    bn.aes128.encm w3, w3, w24
    bn.aes128.encm w4, w4, w24
    bn.aes128.encm w5, w5, w24
    bn.aes128.encm w6, w6, w24
    bn.aes128.encm w7, w7, w24
    bn.aes128.encm w8, w8, w24
    bn.aes128.encm w9, w9, w24
    bn.aes128.encm w10, w10, w24
    # Round 7
    bn.aes128.encm w0, w0, w23
    bn.aes128.encm w1, w1, w23
    bn.aes128.encm w2, w2, w23
    bn.aes128.encm w3, w3, w23
    bn.aes128.encm w4, w4, w23
    bn.aes128.encm w5, w5, w23
    bn.aes128.encm w6, w6, w23
    bn.aes128.encm w7, w7, w23
    bn.aes128.encm w8, w8, w23
    bn.aes128.encm w9, w9, w23
    bn.aes128.encm w10, w10, w23
    # Round 8
    bn.aes128.encm w0, w0, w22
    bn.aes128.encm w1, w1, w22
    bn.aes128.encm w2, w2, w22
    bn.aes128.encm w3, w3, w22
    bn.aes128.encm w4, w4, w22
    bn.aes128.encm w5, w5, w22
    bn.aes128.encm w6, w6, w22
    bn.aes128.encm w7, w7, w22
    bn.aes128.encm w8, w8, w22
    bn.aes128.encm w9, w9, w22
    bn.aes128.encm w10, w10, w22
    # Round 9
    bn.aes128.encm w0, w0, w21
    bn.aes128.encm w1, w1, w21
    bn.aes128.encm w2, w2, w21
    bn.aes128.encm w3, w3, w21
    bn.aes128.encm w4, w4, w21
    bn.aes128.encm w5, w5, w21
    bn.aes128.encm w6, w6, w21
    bn.aes128.encm w7, w7, w21
    bn.aes128.encm w8, w8, w21
    bn.aes128.encm w9, w9, w21
    bn.aes128.encm w10, w10, w21
    # Final round
    bn.aes128.encf w0, w0, w20
    bn.aes128.encf w1, w1, w20
    bn.aes128.encf w2, w2, w20
    bn.aes128.encf w3, w3, w20
    bn.aes128.encf w4, w4, w20
    bn.aes128.encf w5, w5, w20
    bn.aes128.encf w6, w6, w20
    bn.aes128.encf w7, w7, w20
    bn.aes128.encf w8, w8, w20
    bn.aes128.encf w9, w9, w20
    bn.aes128.encf w10, w10, w20
#else
    # bngfonly AES-CTR: 11 aes128_keygen calls (dual-block w2 out) staged to
    # aes_stage, reloaded to w0..w10 for the shared repack. Helper clobbers
    # w1, w10-w17, x18, x19; needs w7/w8/w9 consts (loaded here) + w18 IV.
    la x12, byte_swap_mask
    li x14, 7
    bn.lid x14, 0(x12)
    la x12, affine_value
    li x14, 8
    bn.lid x14, 0(x12)
    la x12, msb_mask
    li x14, 9
    bn.lid x14, 0(x12)
    la x12, aes_stage
    li x6, 2
    loopi 11, 3
        jal x1, aes128_keygen
        bn.sid x6, 0(x12++)
        bn.add w18, w18, w19
    la x12, aes_stage
    li x14, 0
    loopi 11, 2
        bn.lid x14, 0(x12++)
        addi x14, x14, 1
    # Rebuild w13 = mask96 (helper scratch killed it)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160
    # Tail-restore caller invariants (keeps every call site edit-free):
    li x6, 9                  # w9 store idx
    li x19, 12                # w12 load idx (group-folds)
    lw x18, 8(x0)             # col_count (batch-skip reads it post-return)
#endif

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

    la x12, backend_hw_x1s
    lw x1, 0(x12)
    ret

/* dst[e] = P2[e] ^ sum_{r<nrows} P1row[r] * Ocol[e][row+r], e < x18 */
.global backend_gf256_reduce_entries
backend_gf256_reduce_entries:
    add x12, x0, x14           /* P1 stream base (re-read per entry) */
    /* bands from row_start x7: n3(w3)=x5, n4(w4)=x10, n5(w5)=x21, cur=x30 */
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
    li x21, 4
    jal x0, _rh_go
_rh_bandB:
    li x8, 64
    sub x10, x8, x7            /* n4 = 64 - row */
    li x21, 4
    addi x30, x7, -32
    jal x0, _rh_go
_rh_bandC:
    li x8, 68
    sub x21, x8, x7            /* n5 = 68 - row */
    addi x30, x7, -64
_rh_go:
    loop x18, 32
        bn.lid x26, 0(x13++)       # w3 = O col [0:31]
        bn.lid x27, 0(x13++)
        bn.lid x28, 0(x13++)
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x14, x0, x12           # P1 row stream (re-read per entry)
        csrrw x0, mod1, x30        # scalar cursor (band start)
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
        loop x21, 4                # n5 >= 1 always
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        bn.lid x23, 0(x15)         # P2 seed fold
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    ret

/* slice[k,e] ^= sum_{r<4} group[r,e] * O[i0+r,k], k = 0..43, e < x18 */
.global backend_gf256_fold4_entries
backend_gf256_fold4_entries:
    andi x14, x21, 31          /* cursor = i0 & 31 */
    sub x8, x21, x14           /* band_off = i0 & ~31 (0/32/64) */
    add x5, x4, x8             /* per-entry O walk restart */
    li x30, 96
    li x29, 320                 /* slice row stride */
    loop x18, 39
      li x8, 0                    # B rows -> w0..w7
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
      add x4, x0, x5              # o_aligned + band_off (saved)
      add x10, x0, x11
      loopi 44, 18
        bn.lid x19, 0(x4)          # w12 = O col k rows-block
        csrrw x0, mod1, x14        # cursor (\.inc leaves +4)
        bn.lid x17, 0(x10)         # w10 = slice lo (RMW via ACC)
        bn.lid x16, 32(x10)        # w11 = slice hi
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
        bn.sid x25, 0(x10)
        bn.sid x6, 32(x10)
        add x4, x4, x30
        add x10, x10, x29
      addi x11, x11, 64
      addi x12, x12, 64
    ret

#else

/* ------------------------------ sw arm ------------------------------
 * T-table AES (rkbuf derived once in INIT, DMEM persists; GPR x13 ctr) +
 * gf256_macc_dualvec_sw dots. No gfmul/aes128; the GF reduce uses the repo
 * sw-tier bn.mulv.l helper (gf256_sw_helpers).
 * ABI + preserve/clobber convention: backend_* entry headers below.
 * Private state: rkbuf/swstack/bounce below; w16/w17 + x6,x16,x23..x28,x2
 * set by window_init, persist across calls (outer never touches them;
 * ctr_batch clobbers w0-w11 only).
 */
.section .data
.balign 32
backend_rkbuf:   .zero 192
backend_swstack: .zero 416
backend_swstack_end:
backend_bounce:  .zero 32

.section .text
.balign 4

/* INIT-time: derive the 11 round keys once; persists in DMEM. */
.global backend_init_once
backend_init_once:
    la x12, backend_bounce
    sw x1, 0(x12)             /* keyschedule clobbers x1-range GPRs */
    la x11, backend_rkbuf
    jal x1, AES_128_keyschedule
    la x12, backend_bounce
    lw x1, 0(x12)
    ret

/* Per-WINDOW: GF consts + private index GPRs + private stack. No derive. */
.global backend_window_init
backend_window_init:
    li x8, 16
    la x14, msb_mask
    bn.lid x8, 0(x14)         /* w16 = 0x80 per byte */
    bn.addi w17, w31, 0x1b    /* w17.0 = reduction constant */
    li x23, 6
    li x24, 7
    li x25, 8
    li x6,  9
    li x26, 3
    li x27, 4
    li x28, 5
    li x16, 11                /* ctr_batch repack live-in */
    la x2, backend_swstack_end    /* ctr_batch pushes GPR saves here */
    ret

/* dst[e] = P2[e] ^ sum_{r<nrows} P1row[r] * Ocol[e][row+r], e < x18 */
.global backend_gf256_reduce_entries
backend_gf256_reduce_entries:
    add x29, x0, x1            /* dual_vec clobbers no GPRs; x29 is ours */
    add x30, x0, x14           /* P1 stream base, reloaded per entry */
    loop x18, 31
        add x14, x0, x30           # P1 row stream (re-read per entry)
        bn.lid x26, 0(x13++)       # w3 = O col [0:31]
        bn.lid x27, 0(x13++)       # w4 = O col [32:63]
        bn.lid x28, 0(x13++)       # w5 = O col [64:67+pad]
        beq x7, x0, _backend_nskip     # row 0: nothing to skip
        loop x7, 3                 # skip row scalars
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
_backend_nskip:
        bn.xor w20, w20, w20       # lo acc
        bn.xor w30, w30, w30       # hi acc
        loop x20, 9                # nrows P1 elements
            bn.lid x23, 0(x14++)   # w6 = P1 lo
            bn.lid x24, 0(x14++)   # w7 = P1 hi
            bn.mov w0, w6
            bn.mov w1, w7
            bn.mov w19, w3         # scalar byte 0
            jal x1, gf256_macc_dualvec_sw
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        bn.mov w8, w20
        bn.mov w9, w30
        bn.lid x23, 0(x15)         # P2 seed fold
        bn.lid x24, 32(x15)
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x22)
        bn.sid x6, 32(x22)
        addi x22, x22, 64
        addi x15, x15, 64
    add x1, x0, x29
    ret

/* slice[k,e] ^= sum_{r<4} group[r,e] * O[i0+r,k], k = 0..43, e < x18 */
.global backend_gf256_fold4_entries
backend_gf256_fold4_entries:
    add x22, x0, x1            /* save ret (dual_vec clobbers no GPRs) */
    add x4, x4, x21            /* + i0 */
    add x23, x0, x4            /* per-entry O walk restart (x23 ours) */
    li x30, 96
    li x29, 320                /* slice row stride (WJ*64) */
    li x19, 20                 /* w20 lid/sid idx */
    li x17, 30                 /* w30 lid/sid idx */
    la x24, backend_bounce
    loop x18, 50
      li x8, 2                    # B rows -> w2..w9 (macc kills w0/w1)
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
      add x10, x0, x11
      add x4, x0, x23             # o_aligned + i0 (saved)
      loopi 44, 29
        lw x8, 0(x4)              # O[i0..i0+3][k] (word-aligned)
        add x4, x4, x30           # next O col (+96)
        sw x8, 0(x24)             # bounce word -> private slot
        li x8, 14
        bn.lid x8, 0(x24)         # w14 = 4 O scalars at bytes 0..3
        bn.lid x19, 0(x10)        # w20 = slice lo (RMW)
        bn.lid x17, 32(x10)       # w30 = slice hi
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
    li x23, 6                  /* restore private idx consts */
    li x24, 7
    add x1, x0, x22
    ret

/* backend_aes_ctr_batch: monolith P1O_P2.s sw arm verbatim (rk -> backend_rkbuf) */
.balign 4
.global backend_aes_ctr_batch
backend_aes_ctr_batch:
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
    la x10, backend_rkbuf                   # x10 = RK buf base (filled by backend_init_once)
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

#endif

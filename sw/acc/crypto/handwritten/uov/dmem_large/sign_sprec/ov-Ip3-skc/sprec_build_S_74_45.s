/* sprec_build_S_74_45 (Ip3): the once-per-signature half of the S-precomputed sign.
 *   cache = the 2,775 raw upper-triangular P1 entries (row-major, diagonal kept)
 *   S     = (P1 + P1^T) O + P2, 74 x 45 entries, row r at r*2880, entry j at +j*64
 * Row r of S = row_mul_O(t_r, O) + P2[r, :], t_r[k] = P1[min(r,k)][max(r,k)] for
 * k != r and t_r[r] = 0 (the diagonal of P1 + P1^T vanishes). GF256 (0x11B),
 * v = 74, o = m = 45; every entry is 45 B in a 64-B slot with a zero pad.
 * P1/P2 come from the expand_360 stream: P1 = 346 full batches + slots 0..6 of
 * batch 346, P2 starts at slot 7 of that batch (block 7785 = 45*173, phase 0).
 *
 * Built here as the bngfaes arm (-DAES_INSTRUCTIONS -DGF_INSTRUCTIONS): inline bn.aes128.kf
 * key schedule, HW expand_360 and row_mul_O. The other arms are not built in this package.
 *
 * in:    x10 pk_seed (32-B slot, high 16 B zero), x11 O (45 x 96 B, col-major),
 *        x12 S (213,120 B), x13 cache (177,600 B)
 * clob:  x5-x9, x14-x17, x19, x28-x31; w0-w31 (w31 = 0 on return); ACC, ACCH, FG0
 *        (x10-x13 preserved).
 * stack: 4,768 B frame (32 args + 4,736 t row), freed on ret. mod0 = 0x11B, mod1 = 0.
 * calls: _sb_keys, expand_360, row_mul_O. x2 must be 32-B aligned on entry.
 */

.section .text
.balign 4
.global sprec_build_S_74_45

#if defined(GF_INSTRUCTIONS)

sprec_build_S_74_45:
    li x5, 4768
    sub x2, x2, x5
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0

    /* ---- key schedule and P1 stream start: IV = [1 | 0], +2 per lane ---- */
    jal x1, _sb_keys
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32
    li x16, 0

    /* ---- cache: 346 full batches, then slots 0..6 of batch 346 ---- */
    add x14, x0, x13
    loopi 346, 18
        jal x1, expand_360
        bn.sd w0, 0(x14)
        bn.sd w1, 32(x14)
        bn.sd w2, 64(x14)
        bn.sd w3, 96(x14)
        bn.sd w4, 128(x14)
        bn.sd w5, 160(x14)
        bn.sd w6, 192(x14)
        bn.sd w7, 224(x14)
        bn.sd w8, 256(x14)
        bn.sd w9, 288(x14)
        bn.sd w10, 320(x14)
        bn.sd w11, 352(x14)
        bn.sd w12, 384(x14)
        bn.sd w13, 416(x14)
        bn.sd w14, 448(x14)
        bn.sd w15, 480(x14)
        addi x14, x14, 512
    jal x1, expand_360
    bn.sd w0, 0(x14)
    bn.sd w1, 32(x14)
    bn.sd w2, 64(x14)
    bn.sd w3, 96(x14)
    bn.sd w4, 128(x14)
    bn.sd w5, 160(x14)
    bn.sd w6, 192(x14)
    bn.sd w7, 224(x14)
    bn.sd w8, 256(x14)
    bn.sd w9, 288(x14)
    bn.sd w10, 320(x14)
    bn.sd w11, 352(x14)
    bn.sd w12, 384(x14)
    bn.sd w13, 416(x14)

    /* ---- S rows: gather t_r from the cache, then row_mul_O ----
     * x7 = r, x9 = &cache[q(r,r)], x17 = (74 - r) * 64 (the step to the next
     * diagonal), x6 = t base, x12 = S row (row_mul_O advances it by 2,880). */
    li x19, 1
    li x28, 19
    li x29, 20
    addi x6, x2, 32
    li x7, 0
    add x9, x0, x13
    li x17, 4736
    lw x12, 8(x2)
_sb_row:
    add x14, x0, x6
    /* k < r: t[k] = cache[q(k, r)]; q(0, r) = r, then steps of (73 - k) entries */
    beq x7, x0, _sb_a_done
    slli x5, x7, 6
    add x15, x13, x5
    li x16, 4672
    loop x7, 6
        bn.ld w16, 0(x15)
        bn.ld w17, 32(x15)
        bn.sd w16, 0(x14++)
        bn.sd w17, 0(x14++)
        add x15, x15, x16
        addi x16, x16, -64
_sb_a_done:
    /* k = r: zero */
    bn.sd w31, 0(x14++)
    bn.sd w31, 0(x14++)
    /* k > r: t[k] = cache[q(r, k)], contiguous after the diagonal */
    li x5, 73
    sub x5, x5, x7
    beq x5, x0, _sb_c_done
    addi x15, x9, 64
    loop x5, 4
        bn.ld w16, 0(x15++)
        bn.ld w17, 0(x15++)
        bn.sd w16, 0(x14++)
        bn.sd w17, 0(x14++)
_sb_c_done:
    lw x11, 4(x2)
    jal x1, row_mul_O
    add x9, x9, x17
    addi x17, x17, -64
    addi x7, x7, 1
    li x5, 74
    bne x7, x5, _sb_row

    /* ---- P2: S[k] ^= P2[k], k = 0..3329, from slot 7 of the boundary batch ---- */
    lw x10, 0(x2)
    jal x1, _sb_keys
    bn.addi w0, w31, 45
    bn.addi w1, w31, 173
    bn.mulqacc.wo.z w0, w0.0, w1.0, 0
    bn.addi w1, w0, 1
    bn.or w18, w0, w1 << 128
    bn.rshi w18, w18, w31 >> 160
    li x16, 0
    jal x1, expand_360
    li x29, 14
    li x28, 16
    li x30, 1
    lw x15, 8(x2)
    li x5, 3330
    loop x5, 11
        bne x29, x28, _sb_p2_have
        li x29, 0
        jal x1, expand_360
_sb_p2_have:
        bn.movr x0, x29++
        bn.movr x30, x29++
        bn.ld w16, 0(x15)
        bn.ld w17, 32(x15)
        bn.xor w16, w16, w0
        bn.xor w17, w17, w1
        bn.sd w16, 0(x15++)
        bn.sd w17, 0(x15++)

    lw x10, 0(x2)
    lw x11, 4(x2)
    lw x12, 8(x2)
    lw x13, 12(x2)
    li x5, 4768
    add x2, x2, x5
    csrrw x0, mod1, x0
    ret

/* RK0 (dual) in w30, RK1..RK10 in the order expand_360 consumes them: bngfaes
 * w29..w20, bngfonly w20..w29 forward with every key dual-stored. +2 dual
 * increment in w19. in: x10 pk_seed (32-B slot, high 16 B zero).
 * clob: w19-w30, FG0; needs w31 = 0. */
_sb_keys:
    bn.ld w30, 0(x10)
    bn.or w30, w30, w30 << 128
#if defined(AES_INSTRUCTIONS)
    bn.aes128.kf w29, w30,  1
    bn.aes128.kf w28, w29,  2
    bn.aes128.kf w27, w28,  3
    bn.aes128.kf w26, w27,  4
    bn.aes128.kf w25, w26,  5
    bn.aes128.kf w24, w25,  6
    bn.aes128.kf w23, w24,  7
    bn.aes128.kf w22, w23,  8
    bn.aes128.kf w21, w22,  9
    bn.aes128.kf w20, w21, 10
#else
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)
    bn.rshi w17, w31, w30 >> 128
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
#endif
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    ret

#else

/* sw keeps the round keys in the frame at [32..207] (x18 = their base); bnaesonly
 * has x18 = the key slot (pk_seed) and that area unused; expand_360_table keeps x18.
 * t row at frame [224..4959]; expand_360_table takes the block counter in x13 and the
 * phase in x16 and clobbers x13-x16, so the cache and S cursors live in x9. */
sprec_build_S_74_45:
    li x5, 4960
    sub x2, x2, x5
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0

#ifdef AES_INSTRUCTIONS
    /* ---- bnaesonly: bn.aes128 expands per call, so x18 = the key slot (pk_seed) ---- */
    add x18, x0, x10
#else
    /* ---- round keys (x10 = pk_seed, preserved by the key schedule) ---- */
    addi x11, x2, 32
    jal x1, AES_128_keyschedule
    addi x18, x2, 32
#endif

    /* ---- cache: 346 full batches, then slots 0..6 of batch 346 (P1 from block 0) ---- */
    lw x9, 12(x2)
    li x13, 0
    li x16, 0
    loopi 346, 19
        addi x10, x18, 0
        jal x1, expand_360_table
        bn.sd w0, 0(x9)
        bn.sd w1, 32(x9)
        bn.sd w2, 64(x9)
        bn.sd w3, 96(x9)
        bn.sd w4, 128(x9)
        bn.sd w5, 160(x9)
        bn.sd w6, 192(x9)
        bn.sd w7, 224(x9)
        bn.sd w8, 256(x9)
        bn.sd w9, 288(x9)
        bn.sd w10, 320(x9)
        bn.sd w11, 352(x9)
        bn.sd w12, 384(x9)
        bn.sd w13, 416(x9)
        bn.sd w14, 448(x9)
        bn.sd w15, 480(x9)
        addi x9, x9, 512
    addi x10, x18, 0
    jal x1, expand_360_table
    bn.sd w0, 0(x9)
    bn.sd w1, 32(x9)
    bn.sd w2, 64(x9)
    bn.sd w3, 96(x9)
    bn.sd w4, 128(x9)
    bn.sd w5, 160(x9)
    bn.sd w6, 192(x9)
    bn.sd w7, 224(x9)
    bn.sd w8, 256(x9)
    bn.sd w9, 288(x9)
    bn.sd w10, 320(x9)
    bn.sd w11, 352(x9)
    bn.sd w12, 384(x9)
    bn.sd w13, 416(x9)

    /* ---- S rows: as the GF arms, with the t row after the round keys ---- */
    lw x13, 12(x2)
    li x19, 1
    li x28, 19
    li x29, 20
    addi x6, x2, 224
    li x7, 0
    add x9, x0, x13
    li x17, 4736
    lw x12, 8(x2)
_sb_row:
    add x14, x0, x6
    beq x7, x0, _sb_a_done
    slli x5, x7, 6
    add x15, x13, x5
    li x16, 4672
    loop x7, 6
        bn.ld w16, 0(x15)
        bn.ld w17, 32(x15)
        bn.sd w16, 0(x14++)
        bn.sd w17, 0(x14++)
        add x15, x15, x16
        addi x16, x16, -64
_sb_a_done:
    bn.sd w31, 0(x14++)
    bn.sd w31, 0(x14++)
    li x5, 73
    sub x5, x5, x7
    beq x5, x0, _sb_c_done
    addi x15, x9, 64
    loop x5, 4
        bn.ld w16, 0(x15++)
        bn.ld w17, 0(x15++)
        bn.sd w16, 0(x14++)
        bn.sd w17, 0(x14++)
_sb_c_done:
    lw x11, 4(x2)
    jal x1, row_mul_O
    add x9, x9, x17
    addi x17, x17, -64
    addi x7, x7, 1
    li x5, 74
    bne x7, x5, _sb_row

    /* ---- P2: S[k] ^= P2[k], k = 0..3329, block 7785 phase 0 from slot 7, no re-key:
     * sw keeps the round keys in the frame (x18 = their base); bnaesonly reloads
     * x18 = the key slot (pk_seed) here ---- */
#ifdef AES_INSTRUCTIONS
    lw x18, 0(x2)
#else
    addi x18, x2, 32
#endif
    li x13, 7785
    li x16, 0
    addi x10, x18, 0
    jal x1, expand_360_table
    li x29, 14
    li x28, 16
    li x30, 1
    lw x9, 8(x2)
    li x5, 3330
    loop x5, 12
        bne x29, x28, _sb_p2_have
        li x29, 0
        addi x10, x18, 0
        jal x1, expand_360_table
_sb_p2_have:
        bn.movr x0, x29++
        bn.movr x30, x29++
        bn.ld w16, 0(x9)
        bn.ld w17, 32(x9)
        bn.xor w16, w16, w0
        bn.xor w17, w17, w1
        bn.sd w16, 0(x9++)
        bn.sd w17, 0(x9++)

    lw x10, 0(x2)
    lw x11, 4(x2)
    lw x12, 8(x2)
    lw x13, 12(x2)
    li x5, 4960
    add x2, x2, x5
    csrrw x0, mod1, x0
    ret

#endif

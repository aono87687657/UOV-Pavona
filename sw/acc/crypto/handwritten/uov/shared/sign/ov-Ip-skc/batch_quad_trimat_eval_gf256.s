/* batch_quad_trimat_eval_gf256 (Ip). Dual-accumulator: inner low chain (w28)
 * in ACC, inner high chain
 * (w29) in ACCH, dropping the per-element acc spill on the high chain. Outer
 * chains (w20/w21) keep the acc spill at the outer-boundary MACs.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW gf256 + AES_128_keyschedule + expand_352_table
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8/.acch + KeySchedule_sign + jal expand_352 (aes128_sign)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8/.acch + inline bn.aes128.kf + jal expand_352 (bn.aes128.enc*)
 *
 * in: x10 pk_seed, x11 vinegar, x12 y out.  stack: 352 B frame (sw tier: 320 B).
 */

.section .text
.balign 4
.global batch_quad_trimat_eval_gf256


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8 + inline bn.aes128.* via expand_352) =============== */
batch_quad_trimat_eval_gf256:

    bn.xor w31, w31, w31
    addi x2, x2, -352
    sw x10, 320(x2)        /* x10 = pk_seed addr */
    sw x11, 324(x2)        /* x11 = vinegar addr */
    sw x12, 328(x2)        /* x12 = y output addr */

    li x31, 31
    bn.sid x31, 0(x12)     /* clear y[0..31] */
    bn.sid x31, 32(x12)    /* clear y[32..63] */

    li x31, 0x11b
    csrrw x0, mod0, x31    /* GF(256) AES poly */
    csrrw x0, mod1, x0     /* mod1 = 0 (bn.gfmul.8 broadcast byte 0) */

    /* === Preamble: derive AES-128 round-key schedule === */
    li x31, 30
    bn.lid x31, 0(x10)            /* w30 = pk_seed | 0; expandsk stored it zero-extended */
    bn.or w30, w30, w30 << 128    /* dual-store rk0; bn.aes128.* reads only the low 128 */
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
    /* IV increment w19 = +2 per AES-CTR step */
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    /* IV w18 = 1 (initial counter) */
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    /* First expand_352 -> w0..w15 = first 8 P1 entries */
    jal x1, expand_352

    /* Load vinegar v[0..67] -> w22..w24 (clobbers rk8..rk6; re-derived inside refresh) */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31++, 64(x11)


    li x28, 16
    li x29, 0
    li x30, 1
    li x7, 68
    bn.mov w20, w31        /* y_low accumulator = 0 */
    bn.mov w21, w31        /* y_mid accumulator = 0 */
    /* w28/w29 inner sums zeroed via wsrw acc/acch at outer-iter start below */
    loopi 68, 56
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        /* Zero ACC (w28 chain) and ACCH (w29 chain) for this outer iteration */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        loop x7, 42
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bne x29, x28, skip_expand_352
            /* --- refresh: save w20..w29, re-derive round keys, expand, restore --- */
            bn.sd w20, 0(x2)
            bn.sd w21, 32(x2)
            bn.sd w22, 64(x2)
            bn.sd w23, 96(x2)
            bn.sd w24, 128(x2)
            bn.sd w25, 160(x2)
            bn.sd w26, 192(x2)
            bn.sd w27, 224(x2)
            bn.sd w28, 256(x2)
            bn.sd w29, 288(x2)
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
            jal x1, expand_352
            bn.ld w20, 0(x2)
            bn.ld w21, 32(x2)
            bn.ld w22, 64(x2)
            bn.ld w23, 96(x2)
            bn.ld w24, 128(x2)
            bn.ld w25, 160(x2)
            bn.ld w26, 192(x2)
            bn.ld w27, 224(x2)
            bn.ld w28, 256(x2)
            bn.ld w29, 288(x2)
            /* Re-seat ACC/ACCH from restored w28/w29 before continuing inner loop */
            bn.wsrw acc,  w28
            bn.wsrw acch, w29
            li x29, 0
            skip_expand_352: bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bn.wsrw acc, w20
        bn.gfmul.8.acc w20, w28, w22
        bn.wsrw acc, w21
        bn.gfmul.8.acc w21, w29, w22
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        addi x7, x7, -1
    li x31, 20
    bn.sid x31++, 0(x12)
    bn.sid x31++, 32(x12)
    addi x2, x2, 352
    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8 + aes128_sign via expand_352) =============== */
batch_quad_trimat_eval_gf256:

    bn.xor w31, w31, w31
    addi x2, x2, -352
    sw x10, 320(x2)        /* x10 = pk_seed addr */
    sw x11, 324(x2)        /* x11 = vinegar addr */
    sw x12, 328(x2)        /* x12 = y output addr */
    /* Save caller's x13..x15 (we clobber them with AES-constant addresses
     * via `la` below; orchestrator depends on x14=pk_seed, x15=O after return). */
    sw x13, 332(x2)
    sw x14, 336(x2)
    sw x15, 340(x2)

    li x31, 31
    bn.sid x31, 0(x12)     /* clear y[0..31] */
    bn.sid x31, 32(x12)    /* clear y[32..63] */

    li x31, 0x11b
    csrrw x0, mod0, x31    /* GF(256) AES poly */
    /* mod1=0 assumed on entry per kernel exit convention */

    /* === Preamble: pre-resolve AES-constants addresses (hoisted out of refresh loop) === */
    la x13, affine_value           /* x13 = &affine_value (used in refresh) */
    la x14, msb_mask               /* x14 = &msb_mask */
    la x15, rcon                   /* x15 = &rcon */
    /* Initial constant load */
    li x6, 8
    bn.lid x6, 0(x13)              /* w8 = affine_value */
    li x6, 9
    bn.lid x6, 0(x14)              /* w9 = msb_mask */
    li x6, 11
    bn.lid x6, 0(x15)              /* w11 = rcon */

    li x31, 30
    bn.lid x31, 0(x10)             /* w30 = pk_seed (low 128 bits, high half = 0) */

    /* Prime w17 (KS I/O) BEFORE dual-storing w30; KS reads w17 bits 96..255
     * so high half must be zero. Copying AFTER the dual-store would put the
     * key into w17 high half and corrupt the KS body. */
    bn.mov w17, w30                /* w17 = key | 0 */
    bn.or w30, w30, w30 << 128    /* NOW dual-store w30 = key | key */

    /* 10 SW key-schedule calls produce RK1..RK10 in w20..w29 (FORWARD layout). */
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

    /* IV increment w19 = +2 per AES-CTR step */
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    /* IV w18 = 1 (initial counter) */
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    /* First expand_352 to w0..w15 = first 8 P1 entries */
    jal x1, expand_352

    /* Load vinegar v[0..67] to w22..w24 (clobbers rk8..rk6; re-derived inside refresh) */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    /* WDR-index GPRs for save/restore chain (w20..w29 <-> x4, x6, x17, x18..x24) */
    li x4,  20
    li x6,  21
    li x17, 22
    li x18, 23
    li x19, 24
    li x20, 25
    li x21, 26
    li x22, 27
    li x23, 28
    li x24, 29

    li x28, 16
    li x29, 0
    li x30, 1
    li x7, 68
    bn.mov w20, w31        /* y_low accumulator = 0 */
    bn.mov w21, w31        /* y_mid accumulator = 0 */
    /* w28/w29 inner sums zeroed via wsrw acc/acch at outer-iter start below */
    loopi 68, 93
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        /* Zero ACC (w28 chain) and ACCH (w29 chain) for this outer iteration */
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        loop x7, 79
            bn.movr x0, x29++
            bn.movr x30, x29++
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bne x29, x28, skip_expand_352
            /* --- refresh: save w20..w29, re-derive round keys, expand, restore --- */
            bn.sid x4,   0(x2)
            bn.sid x6,  32(x2)
            bn.sid x17, 64(x2)
            bn.sid x18, 96(x2)
            bn.sid x19, 128(x2)
            bn.sid x20, 160(x2)
            bn.sid x21, 192(x2)
            bn.sid x22, 224(x2)
            bn.sid x23, 256(x2)
            bn.sid x24, 288(x2)
            /* Reload AES consts using pre-resolved addresses (x13/x14/x15) */
            li x6, 8
            bn.lid x6, 0(x13)        /* w8 = affine_value */
            li x6, 9
            bn.lid x6, 0(x14)        /* w9 = msb_mask */
            li x6, 11
            bn.lid x6, 0(x15)        /* w11 = rcon */
            /* Re-prime w17 = RK0 | 0 (w30 currently dual-stored = RK0|RK0) */
            bn.rshi w17, w31, w30 >> 128
            /* 10 SW key-schedule calls */
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
            jal x1, expand_352
            /* aes128_sign clobbered x5, x6; reload x4..x24 indices */
            li x4,  20
            li x6,  21
            li x17, 22
            li x18, 23
            li x19, 24
            li x20, 25
            li x21, 26
            li x22, 27
            li x23, 28
            li x24, 29
            bn.lid x4,   0(x2)
            bn.lid x6,  32(x2)
            bn.lid x17, 64(x2)
            bn.lid x18, 96(x2)
            bn.lid x19, 128(x2)
            bn.lid x20, 160(x2)
            bn.lid x21, 192(x2)
            bn.lid x22, 224(x2)
            bn.lid x23, 256(x2)
            bn.lid x24, 288(x2)
            /* Re-seat ACC/ACCH from restored w28/w29 before continuing inner loop */
            bn.wsrw acc,  w28
            bn.wsrw acch, w29
            li x29, 0
            skip_expand_352: bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bn.wsrw acc, w20
        bn.gfmul.8.acc w20, w28, w22
        bn.wsrw acc, w21
        bn.gfmul.8.acc w21, w29, w22
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        addi x7, x7, -1
    li x31, 20
    bn.sid x31++, 0(x12)
    bn.sid x31, 32(x12)
    csrrw x0, mod1, x0     /* reset mod1=0 before return */
    /* Restore caller's x13..x15 */
    lw x13, 332(x2)
    lw x14, 336(x2)
    lw x15, 340(x2)
    addi x2, x2, 352
    ret

#else

/* sw tier: pure SW GF256 + T-table AES (AES_128_keyschedule + expand_352_table);
 * copied from batch_quad_trimat_eval_gf256.s sw arm, ACCH-independent (no acc/acch). */

/* =============== sw (SW gf256 + AES_128_keyschedule + expand_352_table) =============== */
batch_quad_trimat_eval_gf256:

    bn.xor w31, w31, w31

    /* 320 B frame: 0..175 RK output, 176..191 pad, 192..223 saved args
     * (x10..x15 at 192..212, x8 at 216, x16 at 220), 224..319 = caller-side
     * scratch (w20 save at 224, w0 save at 256, w1 save at 288). */
    addi x2, x2, -320
    sw x10, 192(x2)
    sw x11, 196(x2)
    sw x12, 200(x2)
    sw x13, 204(x2)
    sw x14, 208(x2)
    sw x15, 212(x2)
    sw x8,  216(x2)                 /* save caller x8 (sig_loop counter — KS clobbers x5..x8) */
    sw x16, 220(x2)                 /* save caller x16 (S_i ptr — KS clobbers x12..x18) */

    /* Derive AES round keys into top of frame. AES_128_keyschedule:
     *   x10 = key input (= pk_seed/cpk ptr, already in x10 from caller)
     *   x11 = RK output base
     * Clobbers x5..x8, x12..x18, x29..x31. */
    add x11, x0, x2                 /* RK dst = x2 (offset 0) */
    jal x1, AES_128_keyschedule
    add x18, x0, x2                 /* x18 = RK base (survivor) */
    lw x11, 196(x2)                 /* restore x11 = v ptr (used at bn.lid below) */
    lw x12, 200(x2)                 /* restore x12 = y ptr (used immediately below) */

    li x31, 31
    bn.sid x31, 0(x12)              /* y[0..31] = 0 */
    bn.sid x31, 32(x12)             /* y[32..63] = 0 */

    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) AES poly (kept for ACC if any) */

    /* Load msb_mask into w16 (from .data symbol). */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)

    /* Build 0x1b broadcast in w17 low byte (helper uses w17.0 for mulqacc;
     * only low byte matters). */
    bn.addi w17, w31, 0x1b

    /* AES setup (aestable native): x18 = rk survivor (set above), x13 = LE counter */
    li x13, 0

    /* First expand_352_table -> w1..w15 = first 8 packed P1 entries */
    addi x10, x18, 0
    jal x1, expand_352_table        /* x13: 0 -> 22 */

    /* Load vinegar v[0..67] into w22..w24 */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    /* Inner cursor / constants */
    li x28, 16
    li x29, 0
    li x30, 1
    li x7, 68

    bn.mov w20, w31                 /* y_lo = 0 */
    bn.mov w21, w31                 /* y_mid = 0 */
    bn.mov w28, w31
    bn.mov w29, w31

    loopi 68, 43
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        bn.xor w28, w28, w28        /* inner acc lo = 0 */
        bn.xor w29, w29, w29        /* inner acc hi = 0 */

        /* Save w20 (y_lo) to stack — inner loop will use w20 as helper
         * acc_lo slot, destroying y_lo. Restored after inner loop.
         * Offset 224 = 192 RK frame + old 32 B slot. */
        li x4, 20
        bn.sid x4, 224(x2)

        loop x7, 15
            bn.movr x0, x29++       /* w0 = w(x29) = P1 chunk lo */
            bn.movr x30, x29++      /* w1 = w(x29+1) = P1 chunk hi */
            /* Transfer caller acc (w28, w29) + scalar (w25) to helper slots */
            bn.mov w20, w28          /* helper acc_lo input */
            bn.mov w30, w29          /* helper acc_hi input */
            bn.mov w19, w25          /* scalar at byte 0 */
            jal x1, gf256_macc_dualvec_sw
            /* Helper updated w20, w30; transfer back to caller's inner accs */
            bn.mov w28, w20
            bn.mov w29, w30
            bne x29, x28, skip_expand_352
                addi x10, x18, 0
                jal x1, expand_352_table
                li x29, 0
            skip_expand_352: bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8

        /* Restore w20 (y_lo) from stack (offset 224 = 192 RK + old 32). */
        li x4, 20
        bn.lid x4, 224(x2)

        /* Save w0, w1 (P1 entry 0 of latest expand) BEFORE outer gfmul-pair
         * clobbers them. Needed for next iter when x29=0 at entry (inner-
         * iter-0's bn.movr does self-copy, reads w0/w1 as-is).
         * Offsets 256/288 = 192 RK + old 64/96. */
        li x4, 0
        bn.sid x4, 256(x2)
        li x4, 1
        bn.sid x4, 288(x2)

        /* Outer gfmul-pair: y_lo ^= w28 × w22_scalar; y_mid ^= w29 × w22_scalar */
        bn.mov w0, w28               /* vector lo for helper */
        bn.mov w1, w29               /* vector hi */
        bn.mov w19, w22              /* scalar at byte 0 of vinegar fixed */
        bn.mov w30, w21              /* helper acc_hi input = caller y_mid */
        /* helper acc_lo input = w20 (caller's y_lo, already there) */
        jal x1, gf256_macc_dualvec_sw
        bn.mov w21, w30              /* helper acc_hi → caller y_mid */
        /* w20 already updated in-place by helper */

        /* Restore w0, w1 (corrupted by helper). Offsets 256/288. */
        li x4, 0
        bn.lid x4, 256(x2)
        li x4, 1
        bn.lid x4, 288(x2)

        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        addi x7, x7, -1

    /* Store y (64 B) */
    li x31, 20
    bn.sid x31++, 0(x12)
    bn.sid x31, 32(x12)
    csrrw x0, mod1, x0

    /* Restore caller's live sign-loop GPRs (clobbered by KS / kernel body). */
    lw x8,  216(x2)                 /* restore caller x8 (sig_loop counter) */
    lw x13, 204(x2)
    lw x14, 208(x2)
    lw x15, 212(x2)
    lw x16, 220(x2)                 /* restore caller x16 (S_i ptr) */
    addi x2, x2, 320
    ret

#endif

#if defined(GF_INSTRUCTIONS)

/* batch_quad_trimat_eval_gf256_cached (sprec): y = v^T P1 v reading the pre-built
 * raw-P1 cache (q-order, 64 B/entry) instead of regenerating P1 via AES. AES-free
 * (no key schedule / expand_352 / refresh) -> both HW tiers link this one symbol.
 * The cache q-order is exactly the consume order (outer r, inner c=r..67).
 * in: x10 = P1 cache base, x11 = vinegar, x12 = y out.  clob: w0-w29, ACC, ACCH, x7/x10/x30/x31. */
.global batch_quad_trimat_eval_gf256_cached
batch_quad_trimat_eval_gf256_cached:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly */
    csrrw x0, mod1, x0              /* mod1 = 0 (broadcast byte 0); self-contained */

    /* Load vinegar v[0..67] -> w22..w24 */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    li x30, 1                       /* WDR index for w1 (cache entry high half) */
    li x7, 68                       /* inner count: shrinks 68..1 */
    bn.mov w20, w31                 /* y_low  accumulator = 0 */
    bn.mov w21, w31                 /* y_mid  accumulator = 0 */
    loopi 68, 22
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        bn.wsrw acc, w31            /* inner low sum = 0 */
        bn.wsrw acch, w31           /* inner mid sum = 0 */
        loop x7, 8
            bn.lid x0, 0(x10)       /* w0 = P1 entry low  (cache) */
            bn.lid x30, 32(x10)     /* w1 = P1 entry high (cache) */
            addi x10, x10, 64       /* next q-entry */
            bn.gfmul.8.acc  w28, w0, w25
            bn.gfmul.8.acch w29, w1, w25
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        bn.wsrw acc, w20
        bn.gfmul.8.acc w20, w28, w22
        bn.wsrw acc, w21
        bn.gfmul.8.acc w21, w29, w22
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        addi x7, x7, -1
    li x31, 20
    bn.sid x31++, 0(x12)            /* y[0..31]  = w20 */
    bn.sid x31, 32(x12)            /* y[32..63] = w21 */
    ret

#else

/* sw cached batch_quad: y = v^T P1 v reading the raw-P1 cache (q-order, 64 B/entry)
 * via gf256_macc_dualvec_sw — the regular sw loop with all AES/key-schedule/expand
 * removed. y_lo/y_mid kept in w2/w3 (helper owns w20/w30). in: x10=cache, x11=v, x12=y.
 * clob: w0-w3,w16-w20,w25-w31, x4/x5/x7/x10/x30/x31. */
.global batch_quad_trimat_eval_gf256_cached
batch_quad_trimat_eval_gf256_cached:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)                /* w16 = msb_mask (helper) */
    bn.addi w17, w31, 0x1b          /* w17.0 = 0x1b (helper) */

    /* Load vinegar v[0..67] -> w22..w24 */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    li x30, 1                       /* WDR index for w1 (cache entry high half) */
    li x7, 68                       /* inner count: shrinks 68..1 */
    bn.mov w2, w31                  /* y_lo  = 0 */
    bn.mov w3, w31                  /* y_mid = 0 */
    loopi 68, 30
        bn.mov w25, w22
        bn.mov w26, w23
        bn.mov w27, w24
        bn.mov w28, w31             /* inner acc lo = 0 */
        bn.mov w29, w31             /* inner acc hi = 0 */
        loop x7, 12
            bn.lid x0, 0(x10)       /* w0 = P1 entry low  (cache) */
            bn.lid x30, 32(x10)     /* w1 = P1 entry high (cache) */
            addi x10, x10, 64       /* next q-entry */
            bn.mov w20, w28         /* helper acc_lo input */
            bn.mov w30, w29         /* helper acc_hi input */
            bn.mov w19, w25         /* scalar at byte 0 */
            jal x1, gf256_macc_dualvec_sw
            bn.mov w28, w20         /* helper acc_lo -> inner acc lo */
            bn.mov w29, w30         /* helper acc_hi -> inner acc hi */
            bn.rshi w25, w26, w25 >> 8
            bn.rshi w26, w27, w26 >> 8
            bn.rshi w27, w31, w27 >> 8
        /* outer MAC: y ^= inner_acc x v[outer] */
        bn.mov w0, w28
        bn.mov w1, w29
        bn.mov w19, w22             /* scalar = current vinegar byte 0 */
        bn.mov w20, w2              /* helper acc_lo = y_lo */
        bn.mov w30, w3              /* helper acc_hi = y_mid */
        jal x1, gf256_macc_dualvec_sw
        bn.mov w2, w20              /* y_lo  updated */
        bn.mov w3, w30              /* y_mid updated */
        bn.rshi w22, w23, w22 >> 8
        bn.rshi w23, w24, w23 >> 8
        bn.rshi w24, w31, w24 >> 8
        addi x7, x7, -1
    /* Caller ABI (matches HW/regular batch_quad): y_lo in w20, y_hi in w21. */
    bn.mov w20, w2
    bn.mov w21, w3
    li x31, 20
    bn.sid x31++, 0(x12)           /* y[0..31]  = w20 */
    bn.sid x31, 32(x12)            /* y[32..63] = w21 */
    ret

#endif

/* batch_quad_trimat_eval_gf16 (Is). Outer accumulator chain (w0) held in
 * ACCH, dropping the
 * per-outer-iteration acc spill. Inner chain (w1) stays in ACC, re-zeroed each
 * outer iteration. ACCH survives the aes128_sign / inline bn.aes128.* calls
 * (neither touches the accumulators). Result in w0.
 *
 *   variant     cpp flag             body
 *   sw          (none)               SW gf16 + aes128_col_is
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.4/.acch + jal aes128_sign + KeySchedule_sign
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.4/.acch + inline bn.aes128.kf / bn.aes128.enc*
 */

.section .text
.balign 4
.global batch_quad_trimat_eval_gf16


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.4 + inline bn.aes128.*) =============== */
batch_quad_trimat_eval_gf16:

    bn.xor w31, w31, w31
    addi x2, x2, -32
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)

    li x31, 0x13
    csrrw x0, mod0, x31
    li x31, 30
    bn.lid x31, 0(x10)
    bn.or w30, w30, w30 << 128
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
    #Setup IV increment
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    #Setup IV
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32
    li x31, 5
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    bn.wsrw acch, w31               # ACCH = 0 (outer chain, one-time init; w31==0)
    li x31, 96
    loopi 96, 23
        bn.mov w3, w5
        bn.mov w4, w6
        bn.wsrw acc, w31
        loop x31, 15
            bn.aes128.encz.swap w2, w18, w30
            bn.aes128.encm w2, w2, w29
            bn.aes128.encm w2, w2, w28
            bn.aes128.encm w2, w2, w27
            bn.aes128.encm w2, w2, w26
            bn.aes128.encm w2, w2, w25
            bn.aes128.encm w2, w2, w24
            bn.aes128.encm w2, w2, w23
            bn.aes128.encm w2, w2, w22
            bn.aes128.encm w2, w2, w21
            bn.aes128.encf w2, w2, w20
            bn.gfmul.4.acc w1, w2, w3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
            bn.add w18, w18, w19
        bn.gfmul.4.acch w0, w1, w5
        bn.rshi w5, w6, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi x31, x31, -1

    bn.sd w0, 0(x12)
    addi  x2, x2, 32
    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.4 + jal aes128_sign) =============== */
batch_quad_trimat_eval_gf16:

    bn.xor w31, w31, w31
    addi x2, x2, -32
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)

    /* ---- Pre-load SW-AES constants ---- */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)               /* w8 = 0x63..63 */
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)               /* w9 = 0x80..80 */
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)               /* w11 = rcon stream */

    /* ---- Load AES key (pk_seed) into w30; w30 = key|0 (low|high) ---- */
    li x31, 30
    bn.lid x31, 0(x10)

    /* Prime KS input BEFORE dual-storing w30. KS_sign reads w17 bits 96..255
       (`bn.rshi w7, w31, w17 >> 96`), so w17 high half MUST be zero. Copying
       AFTER dual-store would put key in w17 high half and corrupt KS body. */
    bn.mov w17, w30                /* w17 = key|0 (clean for KS) */
    bn.or w30, w30, w30 << 128     /* NOW dual-store w30 = key|key for aes128_sign */

    /* ---- SW key schedule: 10 calls, produce RK1..RK10 -> w20..w29 (forward).
            Each KS call writes next RK to w17 (low half). Caller saves to
            destination WDR then dual-stores via bn.or. KS sets mod0=0x11B
            internally; we set mod0=0x13 AFTER all 10 calls. ---- */
    jal x1, KeySchedule_sign       /* w17 = RK1 */
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_sign       /* w17 = RK2 */
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_sign       /* w17 = RK3 */
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_sign       /* w17 = RK4 */
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_sign       /* w17 = RK5 */
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_sign       /* w17 = RK6 */
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_sign       /* w17 = RK7 */
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_sign       /* w17 = RK8 */
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_sign       /* w17 = RK9 */
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_sign       /* w17 = RK10 */
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128

    /* ---- Load byte_swap_mask into w7 (aes128_sign needs it; KS may have
            clobbered w7 since KS uses it as scratch). ---- */
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)

    /* ---- Set mod0 = 0x13 for GF(16) gfmul.4 body; x21 stays resident
            (aes128_sign leaves mod0 = 0x11B, restored per call below) ---- */
    li x21, 0x13
    csrrw x0, mod0, x21

    /* ---- IV increment setup (unchanged from bngfaes) ---- */
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    /* ---- IV setup (unchanged) ---- */
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32
    /* ---- Vinegar load (unchanged) ---- */
    li x31, 5
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)
    bn.wsrw acch, w31               # ACCH = 0 (outer chain, one-time init; w31==0)
    li x31, 96
    loopi 96, 14
        bn.mov w3, w5
        bn.mov w4, w6
        bn.wsrw acc, w31
        loop x31, 6
            jal x1, aes128_sign       /* in: w18 IV, w20..w30 RKs, w7/w8/w9 consts; out: w2 ct */
            csrrw x0, mod0, x21
            bn.gfmul.4.acc w1, w2, w3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
            bn.add w18, w18, w19
        bn.gfmul.4.acch w0, w1, w5
        bn.rshi w5, w6, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi x31, x31, -1

    bn.sd w0, 0(x12)
    addi x2, x2, 32
    ret

#else

/* sw tier: pure SW GF16 + aes128_col_is; copied from batch_quad_trimat_eval_gf16.s sw arm, ACCH-independent. */

/* =============== sw (SW gf16 + aes128_col_is) =============== */
batch_quad_trimat_eval_gf16:
    bn.xor w31, w31, w31

    /* Stack frame: 320 B (10× 32B aligned slots).
     *   0(x2)   = caller x10 save (4 B; doubles as caller x14 save since
     *             sign calls us with x10 = x14 = pk_seed ptr)
     *   4(x2)   = caller x11 save
     *   8(x2)   = caller x12 save
     *  12(x2)   = caller x1 save (ra)
     *  16(x2)   = caller x3 save (kernel sets x3=0 below for col_is comm slot)
     *  20(x2)   = caller x8 save (sig_loop counter — KS clobbers x5..x8)
     *  24(x2)   = caller x15 save (O ptr — KS clobbers x12..x18)
     *  28(x2)   = caller x16 save (S_i ptr — same)
     *  32(x2)   = AES PT slot (32 B aligned)
     *  64(x2)   = AES CT slot
     *  96(x2)   = round keys (176 B = 5.5× 32B)
     * 272..319  = padding / scratch
     */
    addi x2, x2, -320
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x1, 12(x2)
    sw x3, 16(x2)            /* save caller x3; kernel clobbers below */
    sw x8, 20(x2)            /* save caller x8 (sig_loop counter) — KS clobbers */
    sw x15, 24(x2)           /* save caller x15 (O ptr) — KS clobbers */
    sw x16, 28(x2)           /* save caller x16 (S_i ptr) — KS clobbers */

    /* Build msb_mask in w16 for SW gfmul. */
    bn.addi w16, w31, 0x88
    bn.rshi w17, w16, w31 >> 248
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 240
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 224
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 192
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 128
    bn.or   w16, w16, w17

    /* AES key schedule (T-table). */
    addi x11, x2, 96                 /* round-key buffer base */
    jal x1, AES_128_keyschedule

    /* Load vinegar into w5 (low 64 nibbles), w6 (hi 32 nibbles in low half). */
    lw x11, 4(x2)                    /* restore vinegar ptr */
    li x31, 5
    bn.lid x31++, 0(x11)             /* w5 = vinegar[0..31] */
    bn.lid x31, 32(x11)              /* w6 = vinegar[32..47] */

    /* aes128_col_is setup:
     *   x18 = RK base (survivor across calls).
     *   x3  = frame ptr; aes128_col_is reads scratch-buf addr from 20(x3).
     *   x13 = LE counter, starts at 0; incremented by 2 per col_is call.
     * Scratch buf for aes128_col_is = our PT/CT region at 32(x2)..63(x2),
     * which is 32 B aligned and unused outside aes128_col_is's own use.
     */
    addi x18, x2, 96                  /* x18 = rk base */
    addi x3, x0, 0                    /* x3 = 0 (acts as frame base for col_is) */
    addi x4, x2, 32                   /* scratch buf addr = 32(x2) */
    sw x4, 20(x3)                     /* 20(x3) = scratch buf addr (col_is reads this) */
    addi x13, x0, 0                   /* x13 = LE counter, starts at 0 */

    /* Outer accumulator w12 = 0. */
    bn.xor w12, w12, w12

    /* Inner iter = 1 aes128_col_is call (= 2 AES blocks = 32 B = 64 GF16 nibs)
     * + 1 SW gfmul. Mirrors bngfonly's aes128_sign-per-iter pattern with
     * matching counter semantics (BE counter, +2 per iter). */
    /* x17 = outer countdown (safe: aes128_col_is preserves x17, x18, x23..x28). */
    li x17, 96
    loopi 96, 21
        bn.mov w3, w5                 /* A vinegar low window for this outer */
        bn.mov w4, w6                 /* B vinegar high window */
        bn.xor w1, w1, w1             /* C inner accumulator = 0 */
        loop x17, 8                    /* D inner loop directive (8 body instr) */
            jal x1, aes128_col_is      /*  1 w13 = 32 B (2 blocks), x13 += 2 */
            bn.mov w0, w13             /*  2 vec = AES output */
            bn.mov w19, w3             /*  3 scalar = vinegar nib */
            bn.mov w20, w1             /*  4 acc */
            jal x1, gf16_macc_sw /*  5 w20 = w1 + w0*scalar */
            bn.mov w1, w20             /*  6 */
            bn.rshi w3, w4, w3 >> 4    /*  7 advance scalar nib per inner iter */
            bn.rshi w4, w31, w4 >> 4   /*  8 inner end-PC (non-jal) */
        bn.mov w19, w5                 /* E Outer SW gfmul: w12 ^= w1 * w5[nib0] */
        bn.mov w20, w12                /* F */
        bn.mov w0, w1                  /* G vec = inner acc */
        jal x1, gf16_macc_sw /* H */
        bn.mov w12, w20                /* I */
        bn.rshi w5, w6, w5 >> 4        /* J vinegar outer advances */
        bn.rshi w6, w31, w6 >> 4       /* K */
        addi x17, x17, -1              /* L */
        nop                            /* M outer end-PC (non-jal) */

    /* Store result. */
    lw x12, 8(x2)                     /* restore output ptr */
    bn.mov w0, w12                     /* w0 = result */
    bn.sd w0, 0(x12)                  /* store w0 = result */

    lw x1, 12(x2)
    lw x3, 16(x2)            /* restore caller x3 */
    lw x8, 20(x2)            /* restore caller x8 (sig_loop counter) */
    lw x14, 0(x2)            /* restore caller x14 (= pk_seed, same as saved x10) */
    lw x15, 24(x2)           /* restore caller x15 */
    lw x16, 28(x2)           /* restore caller x16 */
    addi x2, x2, 320
    ret

#endif

#if defined(GF_INSTRUCTIONS)
/* cached variant (both HW tiers; AES-free): read raw P1 from the precompute
 * cache (x10=cache base, q-order) instead of regenerating. Same y = v^T P1 v.
 * x11=vinegar, x12=y out. */
.global batch_quad_trimat_eval_gf16_cached
batch_quad_trimat_eval_gf16_cached:

    bn.xor w31, w31, w31
    addi x2, x2, -32
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)

    li x31, 0x13
    csrrw x0, mod0, x31             # mod0 = GF(16) poly for bn.gfmul.4
    csrrw x0, mod1, x0              # mod1 = 0 (scalar lane 0); self-contained, don't rely on caller
    li x5, 2                        # WDR index 2: cache loads -> w2
    li x31, 5
    bn.lid x31++, 0(x11)            # w5 = vinegar[0..31]
    bn.lid x31, 32(x11)            # w6 = vinegar[32..47]
    bn.wsrw acch, w31               # ACCH = 0 (outer chain init; w31==0)
    li x31, 96                      # inner row length 96..1
    loopi 96, 12
        bn.mov w3, w5
        bn.mov w4, w6
        bn.wsrw acc, w31
        loop x31, 4
            bn.lid x5, 0(x10++)            # w2 = cached P1 entry (q-order), advance cursor
            bn.gfmul.4.acc w1, w2, w3
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.gfmul.4.acch w0, w1, w5
        bn.rshi w5, w6, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi x31, x31, -1

    bn.sd w0, 0(x12)
    addi  x2, x2, 32
    ret

#else

/* sw cached gf16 batch_quad: y = v^T P1 v reading the raw-P1 cache (q-order,
 * 32 B/entry) via gf16_macc_sw — the regular sw loop with all AES / col_is /
 * key-schedule removed. Result -> 0(x12) (memory ABI, same as the regular sw
 * arm; the orchestrator reads y back from memory). in: x10=cache base,
 * x11=vinegar, x12=y. clob: w0-w6,w12,w16-w20, x4/x5/x17/x31, x10 (consumed). */
.global batch_quad_trimat_eval_gf16_cached
batch_quad_trimat_eval_gf16_cached:
    bn.xor w31, w31, w31
    addi x2, x2, -32
    sw x1, 0(x2)                   /* save ra (gf16_macc_sw uses x1) */
    sw x12, 4(x2)                  /* save y ptr (x12 free reg below) */

    /* Build msb_mask in w16 for gf16_macc_sw (w17 scratch). */
    bn.addi w16, w31, 0x88
    bn.rshi w17, w16, w31 >> 248
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 240
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 224
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 192
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 128
    bn.or   w16, w16, w17

    /* Load vinegar v -> w5 (low 64 nibs), w6 (hi 32 nibs). */
    li x31, 5
    bn.lid x31++, 0(x11)
    bn.lid x31, 32(x11)

    bn.xor w12, w12, w12           /* outer accumulator = 0 */
    li x17, 96                     /* outer countdown / inner length 96..1 */
    loopi 96, 20
        bn.mov w3, w5
        bn.mov w4, w6
        bn.xor w1, w1, w1          /* inner accumulator = 0 */
        loop x17, 7
            bn.lid x0, 0(x10++)    /* w0 = cached P1 entry (q-order, advance 32 B) */
            bn.mov w19, w3         /* scalar = vinegar nibble */
            bn.mov w20, w1         /* acc */
            jal x1, gf16_macc_sw   /* w20 = w1 + w0 * scalar */
            bn.mov w1, w20
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        bn.mov w19, w5             /* outer SW gfmul: w12 ^= w1 * w5[nib0] */
        bn.mov w20, w12
        bn.mov w0, w1
        jal x1, gf16_macc_sw
        bn.mov w12, w20
        bn.rshi w5, w6, w5 >> 4
        bn.rshi w6, w31, w6 >> 4
        addi x17, x17, -1
        nop

    lw x12, 4(x2)
    bn.mov w0, w12
    bn.sd w0, 0(x12)              /* store result (memory ABI) */
    lw x1, 0(x2)
    addi x2, x2, 32
    ret
#endif

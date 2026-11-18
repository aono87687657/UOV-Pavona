/* batch_quad_cached_74 (Ip3 sprec): y = v^T P1 v from the raw-P1 cache, cached arms of
 * ov-Ip-skc/batch_quad_trimat_eval_gf256.s with v = 68 -> 74.
 *
 * Built here as the HW arm (GF_INSTRUCTIONS); the sw arm is not built in this package.
 */

.section .text
.balign 4

#if defined(GF_INSTRUCTIONS)

/* batch_quad_cached_74 (Ip3 sprec): y = v^T P1 v reading the pre-built
 * raw-P1 cache (q-order, 64 B/entry, 2,775 entries) instead of regenerating P1.
 * AES-free, so both HW tiers link this one symbol. v = 74, m = 45 (45 B used
 * per entry, zero pad). The cache q-order is the consume order (outer r, inner c = r..73).
 * in: x10 = P1 cache base, x11 = vinegar, x12 = y out.
 * clob: w0, w1, w20-w29, w31, ACC, ACCH, FG0, x7/x10/x30/x31; mod0 = 0x11b, mod1 = 0;
 * w31 = 0 on return. stack: none. */
.global batch_quad_cached_74
batch_quad_cached_74:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly */
    csrrw x0, mod1, x0              /* mod1 = 0 (broadcast byte 0); self-contained */

    /* Load vinegar v[0..73] -> w22..w24 */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    li x30, 1                       /* WDR index for w1 (cache entry high half) */
    li x7, 74                       /* inner count: shrinks 74..1 */
    bn.mov w20, w31                 /* y_low  accumulator = 0 */
    bn.mov w21, w31                 /* y_mid  accumulator = 0 */
    loopi 74, 22
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
 * via gf256_macc_dualvec_sw, the regular sw loop with all AES/key-schedule/expand
 * removed. y_lo/y_mid kept in w2/w3 (helper owns w20/w30). in: x10=cache, x11=v, x12=y.
 * clob: w0-w3, w16-w30, FG0, x4/x5/x7/x10/x30/x31; mod0 = 0x11b; w31 = 0 on return.
 * stack: none. */
.global batch_quad_cached_74
batch_quad_cached_74:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31             /* GF(256) poly */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)                /* w16 = msb_mask (helper) */
    bn.addi w17, w31, 0x1b          /* w17.0 = 0x1b (helper) */

    /* Load vinegar v[0..73] -> w22..w24 */
    li x31, 22
    bn.lid x31++, 0(x11)
    bn.lid x31++, 32(x11)
    bn.lid x31, 64(x11)

    li x30, 1                       /* WDR index for w1 (cache entry high half) */
    li x7, 74                       /* inner count: shrinks 74..1 */
    bn.mov w2, w31                  /* y_lo  = 0 */
    bn.mov w3, w31                  /* y_mid = 0 */
    loopi 74, 30
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

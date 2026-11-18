/* back_substitution (Is, 64-row upper-triangular).
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW: w2[nib k] extracted via runtime loop + helper
 *   bngfonly    -DGF_INSTRUCTIONS    HW: bn.gfmul.4 with mod1=x30
 *   bngfaes     -DAES_|GF_           same as bngfonly (no AES used)
 *
 * Matrix col-major, vec at x11 (32 B = 64 nibbles).
 */

.section .text
.balign 4
.global back_substitution

#if defined(GF_INSTRUCTIONS)

/* --------------- bngfaes + bngfonly (HW bn.gfmul.4) --------------- */
back_substitution:
    bn.xor w31, w31, w31
    li x31, 0x13
    csrrw x0, mod0, x31
    addi x2, x2, -32
    sw x10, 4(x2)
    sw x11, 8(x2)
    add x12, x0, x10
    addi x12, x12, 1024
    addi x12, x12, 992

    li x30, 63
    li x31, 2
    bn.addi w30, w31, 0xf
    bn.rshi w30, w30, w31 >> 4
    bn.lid x31, 0(x11)
    loopi 63, 9
        bn.lid x0, 0(x12)
        bn.and w1, w0, w30
        bn.xor w0, w0, w1
        csrrw x0, mod1, x30
        bn.gfmul.4 w0, w0, w2     # w0 *= w2[mod1=x30] (solution nibble directly)
        bn.xor w2, w2, w0
        bn.rshi w30, w31, w30 >> 4
        addi x30, x30, -1
        addi x12, x12, -32

    bn.sid x31, 0(x11)
    addi x2 ,x2, 32
    csrrw x0, mod1, x0   # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
ret

#else

/* ----------------------- sw (SW gf16 multiply) ----------------------- */
/* w2[nib x30] extracted to w19[nib 0] via runtime `loop x30, 1`.
 * Helper destroys w0 (result in w20); copy w20 -> w0 after call.
 * Stack: 32 B frame alloc + free.
 * Clobbers: w0..w2, w16..w20, w30, w31; x12, x30, x31.
 */
back_substitution:
    bn.xor w31, w31, w31

    /* Build msb_mask = 0x88888888... in w16. */
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

    addi x2, x2, -32
    sw x10, 4(x2)
    sw x11, 8(x2)
    add x12, x0, x10
    addi x12, x12, 1024
    addi x12, x12, 992

    li x30, 63
    li x31, 2

    /* mask w30 = 0xf at nibble 63 (bits 252..255). */
    bn.addi w30, w31, 0xf
    bn.rshi w30, w30, w31 >> 4

    /* w2 = solution vec. */
    bn.lid x31, 0(x11)

    loopi 63, 13
        bn.lid x0, 0(x12)                   /* 1  w0 = col[j] */

        /* Extract w2[nibble x30] to w19[nibble 0]. */
        bn.mov w19, w2                       /* 2 */
        loop x30, 1                          /* 3 (directive) */
            bn.rshi w19, w31, w19 >> 4       /* 4 (inner body, shift right 1 nibble) */

        /* Clear diagonal nibble from w0 (col_no_diag). */
        bn.and w1, w0, w30                   /* 5 */
        bn.xor w0, w0, w1                    /* 6 */

        /* Scale col_no_diag by w2[nibble x30]. */
        bn.mov w20, w31                      /* 7 */
        jal x1, gf16_macc_sw       /* 8 w20 = w0 * w19[nibble 0] */
        bn.mov w0, w20                       /* 9 (after jal, not last) */

        /* Back-sub: w2 ^= scaled col. */
        bn.xor w2, w2, w0                    /* 10 */

        bn.rshi w30, w31, w30 >> 4           /* 11 */
        addi x30, x30, -1                    /* 12 */
        addi x12, x12, -32                   /* 13 */

    bn.sid x31, 0(x11)
    addi x2, x2, 32
    ret

#endif

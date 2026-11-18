/* gf16mat_prod_48_64 — Is GF(16) u = O · o. Low chain (w7) in ACC, high chain
 * (w8) in ACCH.inc, dropping the four per-iteration acc spills.
 * Order is load-bearing: low .acc must read
 * the mod1 cursor before high .acch.inc advances it.
 *
 *   variant     cpp flag                            body
 *   sw          (none)                              SW gf16_macc_sw
 *   bngfonly    -DGF_INSTRUCTIONS                   HW bn.gfmul.4.acc + .acch.inc
 *   bngfaes     -DAES_INSTRUCTIONS|GF_INSTRUCTIONS  HW bn.gfmul.4.acc + .acch.inc
 * I/O: w0 = b (64 nibbles, scalar source), x10 = matrix O addr.
 * Out: w7 (lower 32 B) + w8 (upper 32 B), accumulated.
 */
.section .text
.balign 4
.global gf16_matvec_48_64


#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* ----------- bngfaes (HW bn.gfmul.4; explicit mod1 reset) ----------- */
gf16_matvec_48_64:
    bn.xor w31, w31, w31
    bn.xor w7, w7, w7
    bn.xor w8, w8, w8
    bn.wsrw acc,  w31          # ACC  = 0 (low  chain)
    bn.wsrw acch, w31          # ACCH = 0 (high chain)

    li x31, 0x13
    csrrw x0, mod0, x31
    csrrw x0, mod1, x0          # nibble cursor = 0

    li x31, 3
    li x30, 4
    li x29, 5
    loopi 32, 11
        bn.lid x31, 0(x10++)
        bn.lid x30, 0(x10++)
        bn.lid x29, 0(x10++)
        bn.rshi w6, w31, w5 >> 128
        bn.rshi w5, w5, w4 >> 128
        bn.rshi w4, w4, w31 >> 128
        bn.rshi w4, w31, w4 >> 128
        bn.gfmul.4.acc w7, w3, w0
        bn.gfmul.4.acch.inc w8, w4, w0   # inc mod1 -> next nibble
        bn.gfmul.4.acc w7, w5, w0
        bn.gfmul.4.acch.inc w8, w6, w0   # inc mod1 -> next nibble

    csrrw x0, mod1, x0          # restore mod1=0 before ret
    ret

#elif defined(GF_INSTRUCTIONS)

/* ---------- bngfonly (HW bn.gfmul.4; mod1=0 entry assumed) ---------- */
gf16_matvec_48_64:
    bn.xor w31, w31, w31
    bn.xor w7, w7, w7
    bn.xor w8, w8, w8
    bn.wsrw acc,  w31          # ACC  = 0 (low  chain)
    bn.wsrw acch, w31          # ACCH = 0 (high chain)

    li x31, 0x13
    csrrw x0, mod0, x31
    # mod1=0 assumed on entry per kernel exit convention

    li x31, 3
    li x30, 4
    li x29, 5
    loopi 32, 11
        bn.lid x31, 0(x10++)
        bn.lid x30, 0(x10++)
        bn.lid x29, 0(x10++)
        bn.rshi w6, w31, w5 >> 128
        bn.rshi w5, w5, w4 >> 128
        bn.rshi w4, w4, w31 >> 128
        bn.rshi w4, w31, w4 >> 128
        bn.gfmul.4.acc w7, w3, w0
        bn.gfmul.4.acch.inc w8, w4, w0   # inc mod1 -> next nibble
        bn.gfmul.4.acc w7, w5, w0
        bn.gfmul.4.acch.inc w8, w6, w0   # inc mod1 -> next nibble

    csrrw x0, mod1, x0          # restore mod1=0 before ret
    ret

#else

/* sw tier: pure SW GF16 matvec; copied from gf16mat_prod_48_64.s sw arm, ACCH-independent. */

/* --------------- sw (SW gf16_macc_sw) --------------- */
/* Save/restore w19 around non-inc helper calls; inc helper auto-advances w19. */
gf16_matvec_48_64:
    bn.xor w31, w31, w31
    bn.xor w7, w7, w7
    bn.xor w8, w8, w8

    /* Build msb_mask in w16. */
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

    /* w19 = b vector (scalar source; helper consumes 64 nibbles). */
    bn.mov w19, w0

    li x31, 3
    li x30, 4
    li x29, 5
    loopi 32, 28
        bn.lid x31, 0(x10++)
        bn.lid x30, 0(x10++)
        bn.lid x29, 0(x10++)
        bn.rshi w6, w31, w5 >> 128
        bn.rshi w5, w5, w4 >> 128
        bn.rshi w4, w4, w31 >> 128
        bn.rshi w4, w31, w4 >> 128

        /* === scalar nibble k (used by w3, w4 -- non-inc first, inc second) === */
        bn.mov w15, w19
        bn.mov w0, w3
        bn.mov w20, w7
        jal x1, gf16_macc_sw
        bn.mov w7, w20
        bn.mov w19, w15

        bn.mov w0, w4
        bn.mov w20, w8
        jal x1, gf16_macc_sw
        bn.mov w8, w20

        /* === scalar nibble k+1 (used by w5, w6) === */
        bn.mov w15, w19
        bn.mov w0, w5
        bn.mov w20, w7
        jal x1, gf16_macc_sw
        bn.mov w7, w20
        bn.mov w19, w15

        bn.mov w0, w6
        bn.mov w20, w8
        jal x1, gf16_macc_sw
        bn.mov w8, w20
        nop                              /* loop body end-PC: not jal */

    ret

#endif

/* SW GF(16) helpers. mod 0x13. nibbles in WDR (64 lanes).
 * helpers: gf16_macc_sw, gf16_scalar_inv_sw.
 */

.section .text

/* gf16_macc_sw : w20 ^= w0 * scalar (4 bits consumed from w19)
 * setup: w0=vec, w19=scalar@nibble 0, w20=acc, w16=0x88../nibble, w31=0
 * clob : w0, w18, w19, w20, FG0 M/L/Z
 */
.balign 4
.global gf16_macc_sw
gf16_macc_sw:
    /* === BIT 0 === */
    bn.or   w18, w19, w31, FG0       /* test scalar bit 0 */
    bn.sel  w18, w0, w31, FG0.l      /* w18 = bit0 ? w0 : 0 */
    bn.xor  w20, w20, w18            /* acc ^= */

    /* === a <<= 1 in GF(16) === */
    bn.and  w18, w0, w16             /* MSBs of each nibble */
    bn.xor  w0, w0, w18              /* clear MSBs */
    bn.rshi w0, w0, w31 >> 255       /* shift left whole reg */
    bn.rshi w18, w31, w18 >> 2       /* msb >> 2 */
    bn.xor  w0, w0, w18
    bn.rshi w18, w31, w18 >> 1       /* msb >> 3 */
    bn.xor  w0, w0, w18

    /* === BIT 1 === */
    bn.rshi w19, w31, w19 >> 1       /* scalar >>= 1 */
    bn.or   w18, w19, w31, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === a <<= 1 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 2
    bn.xor  w0, w0, w18
    bn.rshi w18, w31, w18 >> 1
    bn.xor  w0, w0, w18

    /* === BIT 2 === */
    bn.rshi w19, w31, w19 >> 1
    bn.or   w18, w19, w31, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* === a <<= 1 === */
    bn.and  w18, w0, w16
    bn.xor  w0, w0, w18
    bn.rshi w0, w0, w31 >> 255
    bn.rshi w18, w31, w18 >> 2
    bn.xor  w0, w0, w18
    bn.rshi w18, w31, w18 >> 1
    bn.xor  w0, w0, w18

    /* === BIT 3 === */
    bn.rshi w19, w31, w19 >> 1
    bn.or   w18, w19, w31, FG0
    bn.sel  w18, w0, w31, FG0.l
    bn.xor  w20, w20, w18

    /* final shift: 4 bits total per call (next call sees next nibble) */
    bn.rshi w19, w31, w19 >> 1

    ret



/* gf16_scalar_inv_sw : w29[nibble 0] = inv(w29[nibble 0])
 * setup: w29[nibble 0]=a, rest=0; w16=0x88../nibble, w31=0
 * stack: 64 B (w0 save at 0, x1 at 32)
 * clob : w0, w18..w20, w22..w28; x4; FG0 M/L/Z
 */
.balign 4
.global gf16_scalar_inv_sw
gf16_scalar_inv_sw:
    /* 64 B frame, x2 must be 32-B aligned. */
    addi x2, x2, -64
    sw x1, 32(x2)
    li x4, 0
    bn.sid x4, 0(x2)                  /* save caller's w0 */

    /* a^2 -> w28 */
    bn.mov w0, w29
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w28, w20

    /* a^4 -> w27 = (a^2)^2 */
    bn.mov w0, w28
    bn.mov w19, w28
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w27, w20

    /* a^8 -> w26 */
    bn.mov w0, w27
    bn.mov w19, w27
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w26, w20

    /* a^6 = a^4 * a^2 -> w29 */
    bn.mov w0, w27
    bn.mov w19, w28
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w29, w20

    /* a^14 = a^8 * a^6 -> w29 (= a^-1) */
    bn.mov w0, w26
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w29, w20

    /* Restore caller's w0 */
    li x4, 0
    bn.lid x4, 0(x2)
    lw x1, 32(x2)
    addi x2, x2, 64
    ret

/*
 * aes128_sign dual-block AES-128 encrypt, sign-native register layout.
 *
 * Algorithm: identical to ov-verify_base/ov-Is-pkc_gf/AES/aes128.s (Itoh-Tsujii
 * SubBytes x^254 + affine, ShiftRows, MixColumns, AddRoundKey). Fresh
 * implementation with sign-native register names not a literal fork.
 *
 * Round-key WDR layout (FORWARD: RK0 = w30, RK1 = w20, ..., RK10 = w29):
 *   w30 = RK0 (initial, dual-stored K | K<<128 by caller)
 *   w20 = RK1
 *   w21 = RK2
 *   ...
 *   w29 = RK10
 *
 * Caller must pre-load:
 *   w7  = byte_swap_mask (0xff at CTR bytes 12, 28)
 *   w8  = affine_value   (0x63..63)
 *   w9  = msb_mask       (0x80..80)
 *   w20..w29 = RK1..RK10 (each dual-stored by caller after KS phase)
 *   w30 = RK0 (initial key, dual-stored)
 *   w18 = IV (LE counters at bytes 12..15 and 28..31; rest 0)
 *   w31 = 0
 *
 * Output:
 *   w2 = ciphertext (dual-block, 32 B)
 *
 * Internal (clobbered):
 *   w1, w10 (shiftrow_mask, self-loaded), w11 (rotating mask, self-init),
 *   w12..w17 = scratch
 *
 * CSR side effects:
 *   mod0 set to 0x11B for the SW-AES body, NOT restored - GF(16) callers
 *   re-set 0x13 after the call (same leave-set contract as KeySchedule_sign).
 * mod1 set to 0 on exit (sign caller doesn't use mod1).
 *
 * Stack: 8 bytes pushed at entry (x5, x6), popped at exit.
 *
 * GPRs: x5, x6 saved/restored on stack caller's values preserved.
 *       gf256trimat uses x5 as P1+P1T row cursor and x6 as base ptr;
 *       both must survive across aes128_sign calls.
 */
.section .text
.balign 4
.global aes128_sign
aes128_sign:
    # ---- prologue: save caller's x5, x6 on stack ----
    addi x2, x2, -8
    sw x5, 0(x2)                    # save caller's x5
    sw x6, 4(x2)                    # save caller's x6
    li x5, 0x11b
    csrrw x0, mod0, x5               # GF(256) reduction poly
    csrrw x0, mod1, x0               # mod1 = 0 (byte 0 scalar mode for bn.gfmul.8)

    bn.xor w31, w31, w31

    # Load shiftrow_mask into w10
    la x5, shiftrow_mask
    li x6, 10
    bn.lid x6, 0(x5)

    # Initialize rotating mask base w11 = 0xff at bytes 0 and 16
    bn.addi w11, w31, 0xff
    bn.or w11, w11, w11 << 128

    # Round-key cursor: x5 = 20 (= w20 = RK1), x6 = 14 (target = scratch w14)
    li x5, 20
    li x6, 14

    # ---- byte-swap w18 (LE counter) to w2 (BE-at-end AES input) ----
    # Mask = w7 has 0xff at CTR bytes 12, 28. The byte-swap reverses bytes
    # within each 4-byte group of w18 only bytes 12..15 / 28..31 are non-zero
    # in the IV so the effective transform is the LEtoBE swap of the CTR slots.
    bn.and w16, w18, w7
    bn.or  w2, w31, w16 << 24
    bn.and w16, w18, w7 << 8
    bn.or  w2, w2, w16 << 8
    bn.and w16, w18, w7 << 16
    bn.or  w2, w2, w16 >> 8
    bn.and w16, w18, w7 << 24
    bn.or  w2, w2, w16 >> 24

    # AddRoundKey 0
    bn.xor w2, w30, w2

    # ---- rounds 1..9 ----
    loopi 9, 91
        # SubBytes via Itoh-Tsujii: w17 = w2 ^ 254
        bn.gfmul.8.vv w17, w2,  w2          # a^2
        bn.gfmul.8.vv w16, w17, w17         # a^4
        bn.gfmul.8.vv w17, w17, w16         # a^(2+4)
        bn.gfmul.8.vv w16, w16, w16         # a^8
        bn.gfmul.8.vv w17, w17, w16         # a^(6+8)
        bn.gfmul.8.vv w16, w16, w16         # a^16
        bn.gfmul.8.vv w17, w17, w16         # a^(14+16)
        bn.gfmul.8.vv w16, w16, w16         # a^32
        bn.gfmul.8.vv w17, w17, w16         # a^(30+32)
        bn.gfmul.8.vv w16, w16, w16         # a^64
        bn.gfmul.8.vv w17, w17, w16         # a^(62+64)
        bn.gfmul.8.vv w16, w16, w16         # a^128
        bn.gfmul.8.vv w13, w17, w16         # a^254 to w13 (= SubBytes input b)
        # Affine: result = b XOR (b<<<1..<<<4) XOR affine_value
        bn.and w17, w13, w9
        bn.xor w16, w13, w17
        bn.rshi w17, w31, w17 >> 7
        bn.rshi w16, w16, w31 >> 255
        bn.xor w17, w16, w17                # w17 = b <<< 1
        bn.and w16, w17, w9
        bn.xor w15, w17, w16
        bn.rshi w16, w31, w16 >> 7
        bn.rshi w15, w15, w31 >> 255
        bn.xor w16, w15, w16                # w16 = b <<< 2
        bn.xor w17, w16, w17                # w17 = (b<<<1) ^ (b<<<2)
        bn.and w15, w16, w9
        bn.xor w14, w16, w15
        bn.rshi w15, w31, w15 >> 7
        bn.rshi w14, w14, w31 >> 255
        bn.xor w16, w15, w14                # w16 = b <<< 3
        bn.xor w17, w16, w17                # w17 = w17 ^ (b<<<3)
        bn.and w15, w16, w9
        bn.xor w14, w16, w15
        bn.rshi w15, w31, w15 >> 7
        bn.rshi w14, w14, w31 >> 255
        bn.xor w16, w15, w14                # w16 = b <<< 4
        bn.xor w17, w16, w17                # w17 = w17 ^ (b<<<4)
        bn.xor w13, w13, w17                # w13 = b ^ Σ(b<<<i)
        bn.xor w13, w13, w8                 # w13 ^= affine_value
        # ShiftRows row 1
        bn.and w16, w13, w10                # mask = shiftrow_mask (w10)
        bn.xor w13, w16, w13
        bn.and w15, w16, w11 << 8           # rotating mask = w11 << 8
        bn.xor w16, w16, w15
        bn.rshi w16, w31, w16 >> 32
        bn.or  w15, w31, w15 << 96
        bn.or  w16, w15, w16
        bn.or  w13, w16, w13
        # ShiftRows row 2
        bn.or  w14, w31, w10 << 8           # row-2 mask = w10 << 8
        bn.and w16, w14, w13
        bn.xor w13, w16, w13
        bn.or  w15, w11, w11 << 32
        bn.or  w15, w31, w15 << 16
        bn.and w15, w16, w15
        bn.xor w16, w15, w16
        bn.rshi w16, w31, w16 >> 64
        bn.or  w15, w31, w15 << 64
        bn.or  w16, w15, w16
        bn.or  w13, w16, w13
        # ShiftRows row 3
        bn.or  w14, w31, w14 << 8           # row-3 mask = w10 << 16
        bn.and w16, w13, w14
        bn.xor w13, w16, w13
        bn.or  w15, w31, w11 << 120
        bn.and w15, w16, w15
        bn.xor w16, w15, w16
        bn.rshi w16, w16, w31 >> 224
        bn.rshi w15, w31, w15 >> 96
        bn.or  w16, w15, w16
        bn.or  w13, w16, w13
        # MixColumns: standard AES MixCol matrix mult
        bn.addi w1, w31, 0x02
        bn.gfmul.8 w12, w13, w1
        bn.xor w16, w12, w13
        bn.and w15, w16, w10 >> 8
        bn.xor w16, w16, w15
        bn.rshi w16, w31, w16 >> 8
        bn.or  w16, w16, w15 << 24
        bn.xor w12, w12, w16
        bn.and w15, w13, w10 >> 8
        bn.xor w16, w13, w15
        bn.rshi w16, w31, w16 >> 8
        bn.or  w16, w16, w15 << 24
        bn.and w15, w16, w10 >> 8
        bn.xor w16, w16, w15
        bn.rshi w16, w31, w16 >> 8
        bn.or  w16, w16, w15 << 24
        bn.xor w12, w12, w16
        bn.and w15, w16, w10 >> 8
        bn.xor w16, w16, w15
        bn.rshi w16, w31, w16 >> 8
        bn.or  w16, w16, w15 << 24
        bn.xor w12, w12, w16
        # AddRoundKey: load next RK into w14, XOR with MixCol result
        bn.movr x6, x5++
        bn.xor w2, w14, w12

    # ---- round 10 (no MixCols, unrolled) ----
    # SubBytes
    bn.gfmul.8.vv w17, w2,  w2
    bn.gfmul.8.vv w16, w17, w17
    bn.gfmul.8.vv w17, w17, w16
    bn.gfmul.8.vv w16, w16, w16
    bn.gfmul.8.vv w17, w17, w16
    bn.gfmul.8.vv w16, w16, w16
    bn.gfmul.8.vv w17, w17, w16
    bn.gfmul.8.vv w16, w16, w16
    bn.gfmul.8.vv w17, w17, w16
    bn.gfmul.8.vv w16, w16, w16
    bn.gfmul.8.vv w17, w17, w16
    bn.gfmul.8.vv w16, w16, w16
    bn.gfmul.8.vv w13, w17, w16
    # Affine
    bn.and w17, w13, w9
    bn.xor w16, w13, w17
    bn.rshi w17, w31, w17 >> 7
    bn.rshi w16, w16, w31 >> 255
    bn.xor w17, w16, w17
    bn.and w16, w17, w9
    bn.xor w15, w17, w16
    bn.rshi w16, w31, w16 >> 7
    bn.rshi w15, w15, w31 >> 255
    bn.xor w16, w15, w16
    bn.xor w17, w16, w17
    bn.and w15, w16, w9
    bn.xor w14, w16, w15
    bn.rshi w15, w31, w15 >> 7
    bn.rshi w14, w14, w31 >> 255
    bn.xor w16, w15, w14
    bn.xor w17, w16, w17
    bn.and w15, w16, w9
    bn.xor w14, w16, w15
    bn.rshi w15, w31, w15 >> 7
    bn.rshi w14, w14, w31 >> 255
    bn.xor w16, w15, w14
    bn.xor w17, w16, w17
    bn.xor w13, w13, w17
    bn.xor w13, w13, w8
    # ShiftRows row 1
    bn.and w16, w13, w10
    bn.xor w13, w16, w13
    bn.and w15, w16, w11 << 8
    bn.xor w16, w16, w15
    bn.rshi w16, w31, w16 >> 32
    bn.or  w15, w31, w15 << 96
    bn.or  w16, w15, w16
    bn.or  w13, w16, w13
    # ShiftRows row 2
    bn.or  w14, w31, w10 << 8
    bn.and w16, w14, w13
    bn.xor w13, w16, w13
    bn.or  w15, w11, w11 << 32
    bn.or  w15, w31, w15 << 16
    bn.and w15, w16, w15
    bn.xor w16, w15, w16
    bn.rshi w16, w31, w16 >> 64
    bn.or  w15, w31, w15 << 64
    bn.or  w16, w15, w16
    bn.or  w13, w16, w13
    # ShiftRows row 3
    bn.or  w14, w31, w14 << 8
    bn.and w16, w13, w14
    bn.xor w13, w16, w13
    bn.or  w15, w31, w11 << 120
    bn.and w15, w16, w15
    bn.xor w16, w15, w16
    bn.rshi w16, w16, w31 >> 224
    bn.rshi w15, w31, w15 >> 96
    bn.or  w16, w15, w16
    bn.or  w13, w16, w13
    # AddRoundKey RK10 (= w29)
    bn.xor w2, w29, w13

    # ---- epilogue: restore caller's x5, x6 from stack ----
    lw x5, 0(x2)
    lw x6, 4(x2)
    addi x2, x2, 8
    ret

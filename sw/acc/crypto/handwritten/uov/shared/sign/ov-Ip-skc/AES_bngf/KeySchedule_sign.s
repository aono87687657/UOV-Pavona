/*
 * KeySchedule_sign single-call AES-128 key-schedule round, sign-native registers.
 *
 * Algorithm: same as ov-verify_base/ov-Is-pkc_gf/AES/KeySchedule.s RotWord +
 * SubBytes (Itoh-Tsujii x^254) + affine + rcon XOR + column derivation.
 * Register allocation chosen to avoid collision with sign's HW kernel layout
 * (RK1..RK10 at w29..w20; HW kernel reserves w20..w30 for round keys).
 *
 * Input WDRs (caller pre-loads, preserved by this routine):
 *   w8  = affine_value     (0x63..63, 32 bytes)
 *   w9  = msb_mask         (0x80..80, 32 bytes)
 *   w11 = rcon carrier     consumed 8 bits per call; caller pre-loads from .data rcon
 *   w31 = 0
 *
 * In-out WDR:
 *   w17 = current round key (in) to next round key (out)
 *
 * Clobbered WDRs (caller saves what it cares about):
 *   w7, w12, w13, w14, w15, w16
 *
 * CSR side effects:
 *   mod0 set to 0x11B (GF(256) poly) and LEFT caller must restore to 0x13 (GF(16))
 *   before any subsequent bn.gfmul.4. Sign caller convention: do all 10 KS calls in
 *   a row, then set mod0=0x13 once.
 */
.section .text
.balign 4
.global KeySchedule_sign
KeySchedule_sign:
    # mod0 = 0x11B (GF(256) reduction poly)
    li x5, 0x0000011b
    csrrw x0, mod0, x5
    bn.xor w31, w31, w31

    # Get last 32 bits of current RK (w17[127:96]) into w7[31:0]
    bn.rshi w7, w31, w17 >> 96

    # RotWord: rotate the 32-bit word left by 8 bits
    bn.rshi w15, w7, w31 >> 8
    bn.rshi w15, w31, w15 >> 224
    bn.or  w7, w15, w7 >> 8

    # SubBytes via Itoh-Tsujii: w15 = w7 ^ 254 (i.e., GF(256) inverse)
    # 13 multiplies / squarings: 254 = 2 + 4 + 8 + 16 + 32 + 64 + 128 + 6 + 14 + 30 + 62 + 126
    bn.gfmul.8.vv w15, w7,  w7         # w15 = a^2
    bn.gfmul.8.vv w14, w15, w15        # w14 = a^4
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(2+4)
    bn.gfmul.8.vv w14, w14, w14        # w14 = a^8
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(6+8)
    bn.gfmul.8.vv w14, w14, w14        # w14 = a^16
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(14+16)
    bn.gfmul.8.vv w14, w14, w14        # w14 = a^32
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(30+32)
    bn.gfmul.8.vv w14, w14, w14        # w14 = a^64
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(62+64)
    bn.gfmul.8.vv w14, w14, w14        # w14 = a^128
    bn.gfmul.8.vv w15, w15, w14        # w15 = a^(126+128) = a^254

    bn.mov w16, w15                    # w16 = b (= inverse of rotword)

    # Affine: w16 = b XOR (b<<<1) XOR (b<<<2) XOR (b<<<3) XOR (b<<<4) XOR affine_value
    # done as a chain of "circular shift then accumulate" steps. msb_mask (w9) isolates
    # the top bit of each byte for the shift wrap-around.

    # b<<<1 to w15
    bn.and w15, w16, w9
    bn.xor w14, w16, w15
    bn.rshi w15, w31, w15 >> 7
    bn.rshi w14, w14, w31 >> 255
    bn.xor w15, w14, w15

    # b<<<2 to w14
    bn.and w14, w15, w9
    bn.xor w13, w15, w14
    bn.rshi w14, w31, w14 >> 7
    bn.rshi w13, w13, w31 >> 255
    bn.xor w14, w13, w14

    # accumulate: w15 = (b<<<1) XOR (b<<<2)
    bn.xor w15, w14, w15

    # b<<<3 to w14
    bn.and w13, w14, w9
    bn.xor w12, w14, w13
    bn.rshi w13, w31, w13 >> 7
    bn.rshi w12, w12, w31 >> 255
    bn.xor w14, w13, w12

    # accumulate: w15 = (b<<<3) XOR (b<<<1 XOR b<<<2)
    bn.xor w15, w14, w15

    # b<<<4 to w14
    bn.and w13, w14, w9
    bn.xor w12, w14, w13
    bn.rshi w13, w31, w13 >> 7
    bn.rshi w12, w12, w31 >> 255
    bn.xor w14, w13, w12

    # accumulate: w15 = (b<<<4) XOR (b<<<1 XOR b<<<2 XOR b<<<3)
    bn.xor w15, w14, w15
    # w16 = b XOR (b<<<1..4) the SubBytes-via-affine result
    bn.xor w16, w16, w15
    # w16 = affine_value XOR (b XOR b<<<1..4)
    bn.xor w16, w16, w8

    # Truncate to low 32 bits (affine_value spans 32 bytes; we only want one word)
    bn.rshi w16, w16, w31 >> 32
    bn.rshi w16, w31, w16 >> 224

    # Round constant: extract next byte of rcon stream, shift-consume w11
    bn.rshi w7,  w11, w31 >> 8         # w7 = byte 0 of w11 to wider position
    bn.rshi w11, w31, w11 >> 8         # consume one byte from w11
    bn.rshi w7,  w31, w7  >> 248       # w7 = rcon byte placed at low 8 bits

    # XOR rcon into SubBytes result
    bn.xor w7, w16, w7

    # Compute new RK columns:
    #   col0 = SubWord(RotWord(prev_col3)) XOR Rcon XOR prev_col0
    #   col1 = col0 XOR prev_col1
    #   col2 = col1 XOR prev_col2
    #   col3 = col2 XOR prev_col3

    # w15 = col0  (= w7 XOR prev_col0, where prev_col0 = w17[31:0])
    bn.xor w15, w7, w17
    bn.rshi w15, w15, w31 >> 32
    bn.rshi w15, w31, w15 >> 224       # w15 = col0 in low 32 bits

    # Mask = 0xffffffff (32-bit-wide all-ones) for column extraction
    bn.addi w7, w31, 0xff
    bn.or   w7, w7, w7 << 8
    bn.or   w7, w7, w7 << 16

    # w14 = col1 = prev_col1 XOR col0
    bn.and w14, w17, w7 << 32          # w14 = prev_col1 (in bits 32..63)
    bn.xor w14, w14, w15 << 32         # w14 = (prev_col1 XOR col0) << 32

    # w13 = col2 = prev_col2 XOR col1
    bn.and w13, w17, w7 << 64          # w13 = prev_col2 (in bits 64..95)
    bn.xor w13, w13, w14 << 32         # w13 = (prev_col2 XOR col1) << 64

    # w12 = col3 = prev_col3 XOR col2
    bn.and w12, w17, w7 << 96          # w12 = prev_col3 (in bits 96..127)
    bn.xor w12, w12, w13 << 32         # w12 = (prev_col3 XOR col2) << 96

    # Pack 4 columns into next RK (w17)
    bn.or w17, w12, w13
    bn.or w17, w17, w14
    bn.or w17, w17, w15
    ret

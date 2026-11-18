/*
 * aes128 - dual-block AES-128 encryption (compute-AES via bn.gfmul.8).
 *
 * Single call = 1 dual-block (32 B output across both halves of w27).
 * Caller (publicmap_gf) calls in a tight inner loop, advancing w29 by
 * +2 (LE) between calls.
 *
 * Round keys live in WDRs across the whole publicmap (no stack buffer):
 *   w28          round 0 (initial key, dual-stored: K | K<<128)
 *   w5..w14      rounds 1..10 (dual-stored)
 *
 * Caller invariants:
 *   w17, w18..w22 free scratch
 *   w23 affine_value, w24 msb_mask (read-only)
 *   w25 shiftrow_mask + w31 zero self-loaded each call, not caller inputs
 *   w29 IV w/ counter at bytes 12 & 28 (LE), aes128 byte-swaps to BE-at-end
 *   w30 byte-swap mask (0xFF at bytes 12 & 28)
 *
 * Output:
 *   w27 ciphertext (dual-block, 32 B)
 *
 * Loop structure:
 *   round 0 prep (byte-swap of w29 -> w27, AddRoundKey w28)
 *   loopi 9, 91 (rounds 1..9: Sub + Shift + Mix + AddRoundKey)
 *   round 10 (Sub + Shift + AddRoundKey w14, no Mix)
 *
 * clob : x5, x6; w16-w22, w25 (shiftrow self-loaded), w26, w31 (rezeroed); FG0;
 *        sets mod0=0x11b, mod1=0
 * out  : w27 ciphertext (dual-block, 32B)
 * stack: none (leaf)
 */
.section .text
.balign 4
.global aes128
aes128:
    # GF(256) poly in mod0 = 0x11B
    li x5, 0x0000011b
    csrrw x0, mod0, x5

    # mod1 = 0: byte 0 of ws2 used as scalar in bn.gfmul.8
    csrrw x0, mod1, x0

    bn.xor w31,w31,w31

    la x5, shiftrow_mask
    li x6, 25
    bn.lid x6, 0(x5)

    # w26 = 0xff at bytes 0, 16; base for row-1/2/3 ShiftRow rotating masks
    bn.addi w26, w31, 0xff
    bn.or w26, w26, w26 << 128

    li x5, 5
    li x6, 18

    # byte-swap w29 (LE counter) -> w27 (BE-at-end AES input)
    bn.and w20, w29, w30
    bn.or  w27, w31, w20 << 24
    bn.and w20, w29, w30 << 8
    bn.or  w27, w27, w20 << 8
    bn.and w20, w29, w30 << 16
    bn.or  w27, w27, w20 >> 8
    bn.and w20, w29, w30 << 24
    bn.or  w27, w27, w20 >> 24

    # AddRoundKey 0
    bn.xor w27, w28, w27

    loopi 9, 91
        bn.gfmul.8.vv w21, w27, w27       # rounds 1..9 Substitute, Itoh-Tsujii x^254
        bn.gfmul.8.vv w20, w21, w21
        bn.gfmul.8.vv w21, w21, w20
        bn.gfmul.8.vv w20, w20, w20
        bn.gfmul.8.vv w21, w21, w20
        bn.gfmul.8.vv w20, w20, w20
        bn.gfmul.8.vv w21, w21, w20
        bn.gfmul.8.vv w20, w20, w20
        bn.gfmul.8.vv w21, w21, w20
        bn.gfmul.8.vv w20, w20, w20
        bn.gfmul.8.vv w21, w21, w20
        bn.gfmul.8.vv w20, w20, w20
        bn.gfmul.8.vv w17, w21, w20       # last gfmul -> w17 directly (skip bn.mov)
        bn.and w21, w17, w24
        bn.xor w20, w17, w21
        bn.rshi w21, w31, w21 >> 7
        bn.rshi w20, w20, w31 >> 255
        bn.xor w21, w20, w21
        bn.and w20, w21, w24
        bn.xor w19, w21, w20
        bn.rshi w20, w31, w20 >> 7
        bn.rshi w19, w19, w31 >> 255
        bn.xor w20, w19, w20
        bn.xor w21, w20, w21
        bn.and w19, w20, w24
        bn.xor w18, w20, w19
        bn.rshi w19, w31, w19 >> 7
        bn.rshi w18, w18, w31 >> 255
        bn.xor w20, w19, w18
        bn.xor w21, w20, w21
        bn.and w19, w20, w24
        bn.xor w18, w20, w19
        bn.rshi w19, w31, w19 >> 7
        bn.rshi w18, w18, w31 >> 255
        bn.xor w20, w19, w18
        bn.xor w21, w20, w21
        bn.xor w17, w17, w21
        bn.xor w17, w17, w23
        bn.and w20, w17, w25              # ShiftRow row 1, mask = w25 (shiftrow_mask)
        bn.xor w17, w20, w17
        bn.and w19, w20, w26 << 8         # rotating mask = w26 << 8 = 0xff at bytes 1, 17
        bn.xor w20, w20, w19
        bn.rshi w20, w31,w20 >> 32
        bn.or w19, w31, w19 << 96
        bn.or w20, w19, w20
        bn.or w17, w20, w17
        bn.or w18, w31, w25 << 8          # ShiftRow row 2, mask = w25 << 8
        bn.and w20, w18, w17
        bn.xor w17, w20, w17
        bn.or w19, w26, w26 << 32         # rotating mask base = bytes 0, 4, 16, 20
        bn.or w19, w31, w19 << 16         # bytes 2, 6, 18, 22
        bn.and w19, w20, w19
        bn.xor w20, w19, w20
        bn.rshi w20, w31, w20 >> 64
        bn.or w19, w31, w19 << 64
        bn.or w20, w19,w20
        bn.or w17, w20,w17
        bn.or w18, w31, w18 << 8          # ShiftRow row 3, mask = w25 << 16
        bn.and w20, w17, w18
        bn.xor w17, w20, w17
        bn.or w19, w31, w26 << 120        # rotating mask = bytes 15, 31
        bn.and w19, w20, w19
        bn.xor w20, w19, w20
        bn.rshi w20, w20, w31 >> 224
        bn.rshi w19, w31, w19 >> 96
        bn.or w20, w19,w20
        bn.or w17, w20,w17
        bn.addi w22, w31, 0x02            # MixCol; col_mask = w25 >> 8
        bn.gfmul.8 w16, w17, w22
        bn.xor w20, w16, w17
        bn.and w19, w20, w25 >> 8
        bn.xor w20, w20, w19
        bn.rshi w20, w31, w20 >> 8
        bn.or w20, w20, w19 << 24
        bn.xor w16, w16, w20
        bn.and w19, w17, w25 >> 8
        bn.xor w20, w17, w19
        bn.rshi w20, w31, w20 >> 8
        bn.or w20, w20, w19 << 24
        bn.and w19, w20, w25 >> 8
        bn.xor w20, w20, w19
        bn.rshi w20, w31, w20 >> 8
        bn.or w20, w20, w19 << 24
        bn.xor w16, w16, w20
        bn.and w19, w20, w25 >> 8
        bn.xor w20, w20, w19
        bn.rshi w20, w31, w20 >> 8
        bn.or w20, w20, w19 << 24
        bn.xor w16, w16, w20
        bn.movr x6, x5++                  # AddRoundKey: w18 = rk[i+1]
        bn.xor w27, w18, w16

    bn.gfmul.8.vv w21, w27, w27           # round 10 Substitute
    bn.gfmul.8.vv w20, w21, w21
    bn.gfmul.8.vv w21, w21, w20
    bn.gfmul.8.vv w20, w20, w20
    bn.gfmul.8.vv w21, w21, w20
    bn.gfmul.8.vv w20, w20, w20
    bn.gfmul.8.vv w21, w21, w20
    bn.gfmul.8.vv w20, w20, w20
    bn.gfmul.8.vv w21, w21, w20
    bn.gfmul.8.vv w20, w20, w20
    bn.gfmul.8.vv w21, w21, w20
    bn.gfmul.8.vv w20, w20, w20
    bn.gfmul.8.vv w17, w21, w20
    bn.and w21, w17, w24
    bn.xor w20, w17, w21
    bn.rshi w21, w31, w21 >> 7
    bn.rshi w20, w20, w31 >> 255
    bn.xor w21, w20, w21
    bn.and w20, w21, w24
    bn.xor w19, w21, w20
    bn.rshi w20, w31, w20 >> 7
    bn.rshi w19, w19, w31 >> 255
    bn.xor w20, w19, w20
    bn.xor w21, w20, w21
    bn.and w19, w20, w24
    bn.xor w18, w20, w19
    bn.rshi w19, w31, w19 >> 7
    bn.rshi w18, w18, w31 >> 255
    bn.xor w20, w19, w18
    bn.xor w21, w20, w21
    bn.and w19, w20, w24
    bn.xor w18, w20, w19
    bn.rshi w19, w31, w19 >> 7
    bn.rshi w18, w18, w31 >> 255
    bn.xor w20, w19, w18
    bn.xor w21, w20, w21
    bn.xor w17, w17, w21
    bn.xor w17, w17, w23
    bn.and w20, w17, w25                  # round 10 ShiftRow row 1
    bn.xor w17, w20, w17
    bn.and w19, w20, w26 << 8
    bn.xor w20, w20, w19
    bn.rshi w20, w31,w20 >> 32
    bn.or w19, w31, w19 << 96
    bn.or w20, w19, w20
    bn.or w17, w20, w17
    bn.or w18, w31, w25 << 8              # round 10 ShiftRow row 2
    bn.and w20, w18, w17
    bn.xor w17, w20, w17
    bn.or w19, w26, w26 << 32
    bn.or w19, w31, w19 << 16
    bn.and w19, w20, w19
    bn.xor w20, w19, w20
    bn.rshi w20, w31, w20 >> 64
    bn.or w19, w31, w19 << 64
    bn.or w20, w19,w20
    bn.or w17, w20,w17
    bn.or w18, w31, w18 << 8              # round 10 ShiftRow row 3
    bn.and w20, w17, w18
    bn.xor w17, w20, w17
    bn.or w19, w31, w26 << 120
    bn.and w19, w20, w19
    bn.xor w20, w19, w20
    bn.rshi w20, w20, w31 >> 224
    bn.rshi w19, w31, w19 >> 96
    bn.or w20, w19,w20
    bn.or w17, w20,w17
    bn.xor w27, w14, w17                  # AddRoundKey 10

    ret

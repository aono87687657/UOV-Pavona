/*
 * aes128_352 - dual-block AES-128-CTR, 11 dual-blocks output
 *
 * Sub + Shift + Mix + counter-inc all inlined into one nested loopi
 * (no jal to helpers).
 *
 * Caller invariants (publicmap_gf):
 *   w0..w8 caller-owned scratch, must not touch
 *   w27 affine_value (preserved)
 *   w28 msb_mask     (preserved)
 *   w29 LE-at-start counter
 *       bytes 0..3   = lo counter (LE) for block 0
 *       bytes 16..19 = hi counter (LE) for block 1
 *       other bytes  = 0 (zero nonce)
 *       aes128_352 byte-swaps to BE-at-end inside the loop, +=2 per outer iter
 *   w31 = 0
 *   x2  base of round-key buffer (forward push: rk[0] at +0, rk[10] at +320)
 *   mod0 = 0x11b (set by publicmap)
 *
 * Output:
 *   w9..w19 encrypted blocks (per-iter via bn.movr); post-loop rshi unpack
 *   into OV vinegar layout.
 *
 * Loop structure:
 *   outer loopi 11 (one dual-block per iter)
 *     round 0 prep + AddRoundKey
 *     inner loopi 9, 98 (rounds 1..9: Sub + Shift + Mix + AddRoundKey)
 *     round 10 (Sub + Shift + AddRoundKey, no Mix)
 *     w29 += 2; bn.movr stores block
 *
 * w19 = shiftrow_mask, reused as:
 *   - byte-isolation mask for LE<->BE swap (shifted variants)
 *   - row-1 ShiftRow base (row-2/3 derived via shifts into w26)
 *   - col_mask for MixCol (= w19 >> 8)
 * iter 10 bn.movr overwrites w19 with block 10 - this is the post-loop
 * unpack input (bn.rshi w24, w31, w19 >> 160).
 *
 * clob : x6, x24-x27, x30; w9-w26, w30; FG0 (w29 counter in-out, +22 total)
 * stack: none (x2 read-only rk base; no frame)
 */
.section .text
.balign 4
.global aes128_352
aes128_352:
    li x24, 24
    li x25, 9

    # w19 = shiftrow_mask, constant across loopi 11 body
    la x27, shiftrow_mask
    li x26, 19
    bn.lid x26, 0(x27)

    loopi 11, 191
        addi x6, x2, 0                    # reset rk cursor to &rk[0]
        li x30, 30                        # round 0
        bn.lid x30, 0(x6++)               # rk[0]
        bn.and w23, w29, w19 >> 8         # LE->BE byteswap; byte 0/16 (LE LSB)
        bn.or w24, w31, w23 << 120        # byte 15/31 (BE LSB)
        bn.and w23, w29, w19              # byte 1/17
        bn.or w24, w24, w23 << 104        # byte 14/30
        bn.and w23, w29, w19 << 8         # byte 2/18
        bn.or w24, w24, w23 << 88         # byte 13/29
        bn.and w23, w29, w19 << 16        # byte 3/19 (LE MSB)
        bn.or w24, w24, w23 << 72         # byte 12/28 (BE MSB)
        bn.xor w24, w30, w24              # AddRoundKey 0

        loopi 9, 98
            bn.gfmul.8.vv w21, w24, w24   # rounds 1..9 Substitute, Itoh-Tsujii x^254
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
            bn.gfmul.8.vv w22, w21, w20
            bn.and w21, w22, w28
            bn.xor w20, w22, w21
            bn.rshi w21, w31, w21 >> 7
            bn.rshi w20, w20, w31 >> 255
            bn.xor w21, w20, w21
            bn.and w20, w21, w28
            bn.xor w23, w21, w20
            bn.rshi w20, w31, w20 >> 7
            bn.rshi w23, w23, w31 >> 255
            bn.xor w20, w23, w20
            bn.xor w21, w20, w21
            bn.and w23, w20, w28
            bn.xor w25, w20, w23
            bn.rshi w23, w31, w23 >> 7
            bn.rshi w25, w25, w31 >> 255
            bn.xor w20, w23, w25
            bn.xor w21, w20, w21
            bn.and w23, w20, w28
            bn.xor w25, w20, w23
            bn.rshi w23, w31, w23 >> 7
            bn.rshi w25, w25, w31 >> 255
            bn.xor w20, w23, w25
            bn.xor w21, w20, w21
            bn.xor w22, w22, w21
            bn.xor w22, w22, w27
            bn.and w20, w22, w19          # ShiftRow row 1, w19 = row-1 mask
            bn.xor w22, w20, w22
            bn.addi w21, w31, 0xff
            bn.or w21, w21, w21 << 128
            bn.or w21, w31, w21 << 8
            bn.and w21, w21, w20
            bn.xor w20, w20, w21
            bn.rshi w20, w31, w20 >> 32
            bn.or w21, w31, w21 << 96
            bn.or w20, w21, w20
            bn.or w22, w20, w22
            bn.or w26, w31, w19 << 8      # ShiftRow row 2, mask = w19 << 8
            bn.and w20, w26, w22
            bn.xor w22, w20, w22
            bn.addi w21, w31, 0xff
            bn.or w21, w21, w21 << 32
            bn.or w21, w21, w21 << 128
            bn.or w21, w31, w21 << 16
            bn.and w21, w20, w21
            bn.xor w20, w21, w20
            bn.rshi w20, w31, w20 >> 64
            bn.or w21, w31, w21 << 64
            bn.or w20, w21, w20
            bn.or w22, w20, w22
            bn.or w26, w31, w19 << 16     # ShiftRow row 3, mask = w19 << 16
            bn.and w20, w22, w26
            bn.xor w22, w20, w22
            bn.addi w21, w31, 0xff
            bn.or w21, w21, w21 << 128
            bn.or w21, w31, w21 << 120
            bn.and w21, w20, w21
            bn.xor w20, w21, w20
            bn.rshi w20, w20, w31 >> 224
            bn.rshi w21, w31, w21 >> 96
            bn.or w20, w21, w20
            bn.or w25, w20, w22
            bn.addi w22, w31, 0x02        # MixCol; col_mask = w19 >> 8
            bn.gfmul.8 w20, w25, w22
            bn.xor w24, w20, w25
            bn.and w21, w24, w19 >> 8
            bn.xor w24, w24, w21
            bn.rshi w24, w31, w24 >> 8
            bn.or w24, w24, w21 << 24
            bn.xor w20, w20, w24
            bn.and w21, w25, w19 >> 8
            bn.xor w24, w25, w21
            bn.rshi w24, w31, w24 >> 8
            bn.or w24, w24, w21 << 24
            bn.and w21, w24, w19 >> 8
            bn.xor w24, w24, w21
            bn.rshi w24, w31, w24 >> 8
            bn.or w24, w24, w21 << 24
            bn.xor w20, w20, w24
            bn.and w21, w24, w19 >> 8
            bn.xor w24, w24, w21
            bn.rshi w24, w31, w24 >> 8
            bn.or w24, w24, w21 << 24
            bn.xor w20, w20, w24
            bn.lid x30, 0(x6++)           # rk[i+1]
            bn.xor w24, w20, w30          # AddRoundKey

        bn.gfmul.8.vv w21, w24, w24       # round 10 Substitute
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
        bn.gfmul.8.vv w22, w21, w20
        bn.and w21, w22, w28
        bn.xor w20, w22, w21
        bn.rshi w21, w31, w21 >> 7
        bn.rshi w20, w20, w31 >> 255
        bn.xor w21, w20, w21
        bn.and w20, w21, w28
        bn.xor w23, w21, w20
        bn.rshi w20, w31, w20 >> 7
        bn.rshi w23, w23, w31 >> 255
        bn.xor w20, w23, w20
        bn.xor w21, w20, w21
        bn.and w23, w20, w28
        bn.xor w25, w20, w23
        bn.rshi w23, w31, w23 >> 7
        bn.rshi w25, w25, w31 >> 255
        bn.xor w20, w23, w25
        bn.xor w21, w20, w21
        bn.and w23, w20, w28
        bn.xor w25, w20, w23
        bn.rshi w23, w31, w23 >> 7
        bn.rshi w25, w25, w31 >> 255
        bn.xor w20, w23, w25
        bn.xor w21, w20, w21
        bn.xor w22, w22, w21
        bn.xor w22, w22, w27
        bn.and w20, w22, w19              # round 10 ShiftRow row 1
        bn.xor w22, w20, w22
        bn.addi w21, w31, 0xff
        bn.or w21, w21, w21 << 128
        bn.or w21, w31, w21 << 8
        bn.and w21, w21, w20
        bn.xor w20, w20, w21
        bn.rshi w20, w31, w20 >> 32
        bn.or w21, w31, w21 << 96
        bn.or w20, w21, w20
        bn.or w22, w20, w22
        bn.or w26, w31, w19 << 8          # round 10 ShiftRow row 2
        bn.and w20, w26, w22
        bn.xor w22, w20, w22
        bn.addi w21, w31, 0xff
        bn.or w21, w21, w21 << 32
        bn.or w21, w21, w21 << 128
        bn.or w21, w31, w21 << 16
        bn.and w21, w20, w21
        bn.xor w20, w21, w20
        bn.rshi w20, w31, w20 >> 64
        bn.or w21, w31, w21 << 64
        bn.or w20, w21, w20
        bn.or w22, w20, w22
        bn.or w26, w31, w19 << 16         # round 10 ShiftRow row 3
        bn.and w20, w22, w26
        bn.xor w22, w20, w22
        bn.addi w21, w31, 0xff
        bn.or w21, w21, w21 << 128
        bn.or w21, w31, w21 << 120
        bn.and w21, w20, w21
        bn.xor w20, w21, w20
        bn.rshi w20, w20, w31 >> 224
        bn.rshi w21, w31, w21 >> 96
        bn.or w20, w21, w20
        bn.or w25, w20, w22
        bn.lid x30, 0(x6)                 # AddRoundKey 10; cursor at &rk[10]
        bn.xor w24, w25, w30
        bn.addi w20, w31, 0x02            # counter += 2 (LE)
        bn.or w20, w20, w20 << 128
        bn.add w29, w29, w20
        bn.movr x25++, x24                # store block

    # post-loop unpack: w9..w19 -> OV vinegar layout
    bn.rshi w24, w31, w19 >> 160
    bn.rshi w23, w19, w18 >> 160

    bn.rshi w22, w18, w31 >> 160
    bn.rshi w22, w31, w22 >> 160
    bn.rshi w21, w18, w17 >> 64

    bn.rshi w20, w17, w16 >> 64
    bn.rshi w20, w31, w20 >> 160
    bn.rshi w19, w16, w15 >> 224

    bn.rshi w18, w15, w31 >> 224
    bn.rshi w18, w31, w18 >> 160
    bn.rshi w17, w15, w14 >> 128

    bn.rshi w16, w14, w31 >> 128
    bn.rshi w16, w31, w16 >> 160
    bn.rshi w15, w14, w13 >> 32

    bn.rshi w14, w13, w12 >> 32
    bn.rshi w14, w31, w14 >> 160
    bn.rshi w13, w12, w11 >> 192

    bn.rshi w12, w11, w31 >> 192
    bn.rshi w12, w31, w12 >> 160
    bn.rshi w11, w11, w10 >> 96

    bn.rshi w10, w10, w31 >> 96
    bn.rshi w10, w31, w10 >> 160

    ret

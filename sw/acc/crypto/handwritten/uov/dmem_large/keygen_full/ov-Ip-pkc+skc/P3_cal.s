.section .text
.global P3_cal
.balign 4
/* P3_cal (Ip): P3 = Upper(O^T x (P1*O + P2)) over GF(256), V=68, O=44, M=44.
 *   -DGF_INSTRUCTIONS -> HW bn.gfmul.8: dense P3_full = O^T x inter, four output
 *     rows k0..k0+3 per pass, so each inter load feeds four O columns (row k0 in
 *     ACC/ACCH, rows k0+1..k0+3 in w22..w27 via plain gfmul + xor).
 *   no flag -> SW gf256_macc_dualvec_sw, one row at a time into P3_full.
 *   Both arms then fold P3_full into the packed upper output (Phase 3).
 * in:  x10 = P3 upper-tri out (990 x 64B = 63,360B, row-major packed)
 *      x11 = (P1*O+P2) (68x44 row-major, 191,488B)
 *      x12 = O matrix (col-major, 44 cols x 68B = 2,992B raw)
 * out: P3 at x10
 * stack: 128,160B = frame 32 + O aligned 4,224 + P3_full 123,904 (both arms).
 * loop counts (re-derive on any body edit): HW blocks 11,224 > cols 44,216 > rows
 *   (8,65)(8,65) + 4 inline; SW outer 44,31 > mid 44,22 > inner 68,10; extract 43,19 > x18,10.
 * clob (HW): x3-x13, x15-x19, x21, x22, x29-x31; w0-w28, w31; ACC, ACCH; FG0 (bn.xor);
 *   mod0; mod1=0 on exit. x1, x2 restored.
 * WDR (HW): w10..w21 O cols k0..k0+3, 3 segments each; w6/w7 inter lo/hi; w8/w9 ACC/ACCH
 *   copies; w22..w27 rows k0+1..k0+3 lo/hi; w28 product; w31 zero. Phase 1 uses w0..w17.
 *   sw adds: w21-w23 O backup, w16/w17 consts, w0/w1/w19 helper in, w20/w30 dualvec acc; FG1. */

P3_cal:
    # Phase 0: Prologue
    bn.xor w31, w31, w31            # w31 = 0
    li x31, 0x11b                   # GF(2^8) modulus
    csrrw x0, mod0, x31             # set mod0

    li x30, 128160                  # 32 ctrl + 4,224 O aligned + 123,904 P3_full
    sub x2, x2, x30
    add x3, x0, x2                  # x3 = frame pointer

    sw x10, 0(x3)                   # save P3 output addr
    sw x11, 4(x3)                   # save intermediate base
    sw x12, 8(x3)                   # save O matrix addr
    sw x1, 12(x3)                   # save return addr

    addi x15, x3, 32               # O aligned buf start
    sw x15, 16(x3)                  # save O aligned addr

    li x15, 4256
    add x15, x3, x15               # P3_full start
    sw x15, 20(x3)                  # save P3_full addr

    # Phase 1: O Matrix Alignment Copy
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    lw x11, 16(x3)                  # O aligned dest base
    li x9, 17                       # WDR idx for w17 (temp)
    li x29, 1                       # WDR idx for w1
    li x30, 2                       # WDR idx for w2

    loopi 5, 57                     # 5 full batches x 8 cols = 40 cols
        li x8, 0                    # WDR load idx
        loopi 17, 2                 # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)           # w0
        bn.sid x29, 32(x11)         # w1
        bn.sid x30, 64(x11)         # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96   # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96   # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96   # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128  # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224 # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224 # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224 # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                        # WDR load idx
    loopi 9, 2                      # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)               # w0
    bn.sid x29, 32(x11)             # w1
    bn.sid x30, 64(x11)             # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64       # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96       # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96       # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96       # hi
    bn.sid x9, 64(x11)

#ifdef GF_INSTRUCTIONS
    # Phase 2 (HW): P3_full = O^T x inter, four output rows k0..k0+3 per pass so each
    # inter[i][j] load feeds four O columns. Row k0 accumulates in ACC/ACCH, rows
    # k0+1..k0+3 in w22..w27 via plain gfmul + xor. One mod1 cursor walks all four
    # columns; .acch.inc is the last gfmul of each row, and each 32-row segment wraps
    # the cursor back to 0. Phase 3 then folds P3_full into the packed upper output.
    li x4, 6                        # WDR idx w6 (inter lo)
    li x5, 7                        # WDR idx w7 (inter hi)
    li x6, 8                        # WDR idx w8 (Phase 3)
    li x7, 9                        # WDR idx w9 (Phase 3)
    li x21, 11264                   # 4-row stride (4 x 2816), inter and P3_full
    lw x16, 16(x3)                  # O aligned read ptr
    lw x10, 20(x3)                  # P3_full row 0
    loopi 11, 224
        li x8, 10                       # O cols k0..k0+3 -> w10..w21
        loopi 12, 2
            bn.lid x8, 0(x16++)
            addi x8, x8, 1
        lw x13, 4(x3)                   # inter col 0
        add x17, x0, x10                # P3_full[k0][j]
        loopi 44, 216
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            bn.xor w22, w22, w22
            bn.xor w23, w23, w23
            bn.xor w24, w24, w24
            bn.xor w25, w25, w25
            bn.xor w26, w26, w26
            bn.xor w27, w27, w27
            add x11, x0, x13               # inter[0][j]
            csrrw x0, mod1, x0             # rows 0..31: O[0:31] (w10/w13/w16/w19)
            loopi 8, 65
                bn.lid x4, 0(x11)
                bn.lid x5, 32(x11)
                bn.gfmul.8 w28, w6, w13
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w13
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w16
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w16
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w19
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w19
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w10
                bn.gfmul.8.acch.inc w9, w7, w10
                bn.lid x4, 2816(x11)
                bn.lid x5, 2848(x11)
                bn.gfmul.8 w28, w6, w13
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w13
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w16
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w16
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w19
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w19
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w10
                bn.gfmul.8.acch.inc w9, w7, w10
                bn.lid x4, 5632(x11)
                bn.lid x5, 5664(x11)
                bn.gfmul.8 w28, w6, w13
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w13
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w16
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w16
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w19
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w19
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w10
                bn.gfmul.8.acch.inc w9, w7, w10
                bn.lid x4, 8448(x11)
                bn.lid x5, 8480(x11)
                bn.gfmul.8 w28, w6, w13
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w13
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w16
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w16
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w19
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w19
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w10
                bn.gfmul.8.acch.inc w9, w7, w10
                add x11, x11, x21
            loopi 8, 65                  # rows 32..63: O[32:63], cursor wrapped to 0
                bn.lid x4, 0(x11)
                bn.lid x5, 32(x11)
                bn.gfmul.8 w28, w6, w14
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w14
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w17
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w17
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w20
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w20
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w11
                bn.gfmul.8.acch.inc w9, w7, w11
                bn.lid x4, 2816(x11)
                bn.lid x5, 2848(x11)
                bn.gfmul.8 w28, w6, w14
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w14
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w17
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w17
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w20
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w20
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w11
                bn.gfmul.8.acch.inc w9, w7, w11
                bn.lid x4, 5632(x11)
                bn.lid x5, 5664(x11)
                bn.gfmul.8 w28, w6, w14
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w14
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w17
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w17
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w20
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w20
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w11
                bn.gfmul.8.acch.inc w9, w7, w11
                bn.lid x4, 8448(x11)
                bn.lid x5, 8480(x11)
                bn.gfmul.8 w28, w6, w14
                bn.xor w22, w22, w28
                bn.gfmul.8 w28, w7, w14
                bn.xor w23, w23, w28
                bn.gfmul.8 w28, w6, w17
                bn.xor w24, w24, w28
                bn.gfmul.8 w28, w7, w17
                bn.xor w25, w25, w28
                bn.gfmul.8 w28, w6, w20
                bn.xor w26, w26, w28
                bn.gfmul.8 w28, w7, w20
                bn.xor w27, w27, w28
                bn.gfmul.8.acc w8, w6, w11
                bn.gfmul.8.acch.inc w9, w7, w11
                add x11, x11, x21
            # rows 64..67: O[64:67] (w12/w15/w18/w21)
            bn.lid x4, 0(x11)
            bn.lid x5, 32(x11)
            bn.gfmul.8 w28, w6, w15
            bn.xor w22, w22, w28
            bn.gfmul.8 w28, w7, w15
            bn.xor w23, w23, w28
            bn.gfmul.8 w28, w6, w18
            bn.xor w24, w24, w28
            bn.gfmul.8 w28, w7, w18
            bn.xor w25, w25, w28
            bn.gfmul.8 w28, w6, w21
            bn.xor w26, w26, w28
            bn.gfmul.8 w28, w7, w21
            bn.xor w27, w27, w28
            bn.gfmul.8.acc w8, w6, w12
            bn.gfmul.8.acch.inc w9, w7, w12
            bn.lid x4, 2816(x11)
            bn.lid x5, 2848(x11)
            bn.gfmul.8 w28, w6, w15
            bn.xor w22, w22, w28
            bn.gfmul.8 w28, w7, w15
            bn.xor w23, w23, w28
            bn.gfmul.8 w28, w6, w18
            bn.xor w24, w24, w28
            bn.gfmul.8 w28, w7, w18
            bn.xor w25, w25, w28
            bn.gfmul.8 w28, w6, w21
            bn.xor w26, w26, w28
            bn.gfmul.8 w28, w7, w21
            bn.xor w27, w27, w28
            bn.gfmul.8.acc w8, w6, w12
            bn.gfmul.8.acch.inc w9, w7, w12
            bn.lid x4, 5632(x11)
            bn.lid x5, 5664(x11)
            bn.gfmul.8 w28, w6, w15
            bn.xor w22, w22, w28
            bn.gfmul.8 w28, w7, w15
            bn.xor w23, w23, w28
            bn.gfmul.8 w28, w6, w18
            bn.xor w24, w24, w28
            bn.gfmul.8 w28, w7, w18
            bn.xor w25, w25, w28
            bn.gfmul.8 w28, w6, w21
            bn.xor w26, w26, w28
            bn.gfmul.8 w28, w7, w21
            bn.xor w27, w27, w28
            bn.gfmul.8.acc w8, w6, w12
            bn.gfmul.8.acch.inc w9, w7, w12
            bn.lid x4, 8448(x11)
            bn.lid x5, 8480(x11)
            bn.gfmul.8 w28, w6, w15
            bn.xor w22, w22, w28
            bn.gfmul.8 w28, w7, w15
            bn.xor w23, w23, w28
            bn.gfmul.8 w28, w6, w18
            bn.xor w24, w24, w28
            bn.gfmul.8 w28, w7, w18
            bn.xor w25, w25, w28
            bn.gfmul.8 w28, w6, w21
            bn.xor w26, w26, w28
            bn.gfmul.8 w28, w7, w21
            bn.xor w27, w27, w28
            bn.gfmul.8.acc w8, w6, w12
            bn.gfmul.8.acch.inc w9, w7, w12
            bn.sd w8, 0(x17)
            bn.sd w9, 32(x17)
            bn.sd w22, 2816(x17)
            bn.sd w23, 2848(x17)
            bn.sd w24, 5632(x17)
            bn.sd w25, 5664(x17)
            bn.sd w26, 8448(x17)
            bn.sd w27, 8480(x17)
            addi x17, x17, 64
            addi x13, x13, 64
        add x10, x10, x21               # P3_full row k0+4
#else
    # Phase 2 (sw): P3_full = O^T x intermediate (dense; folded by Phase 3 below)

    li x4, 6                        # WDR idx for w6
    li x5, 7                        # WDR idx for w7
    li x6, 8                        # WDR idx for w8
    li x7, 9                        # WDR idx for w9
    li x21, 2816                    # row stride (44 entries x 64B)
    li x26, 3                       # WDR idx for w3
    li x27, 4                       # WDR idx for w4
    li x28, 5                       # WDR idx for w5
    li x31, 31                      # WDR idx for w31 (zero)

    # sw: gf256_macc_dualvec_sw constants -- w16 = msb_mask, w17.0 = 0x1b
    li x9, 16
    la x14, msb_mask
    bn.lid x9, 0(x14)
    bn.addi w17, w31, 0x1b

    lw x10, 20(x3)                  # x10 = P3_full output ptr
    lw x16, 16(x3)                  # x16 = O aligned read ptr

    loopi 44, 31
        # Load O col k (3 WDRs = 96B padded, 68 useful bytes)
        bn.lid x26, 0(x16++)        # w3 = O col [0:31]
        bn.lid x27, 0(x16++)        # w4 = O col [32:63]
        bn.lid x28, 0(x16++)        # w5 = O col [64:67+pad]
        # Backup O col k (sw rshi slides consume w3-w5)
        bn.mov w21, w3               # backup lo  (sw keeps w16/w17 for consts)
        bn.mov w22, w4               # backup mid
        bn.mov w23, w5               # backup hi
        # Reset intermediate base for this O column
        lw x13, 4(x3)               # intermediate base addr
        loopi 44, 22
            # Restore O col k from backup
            bn.mov w3, w21           # restore lo
            bn.mov w4, w22           # restore mid
            bn.mov w5, w23           # restore hi
            bn.xor w20, w20, w20    # sw: dualvec lo acc = 0
            bn.xor w30, w30, w30    # sw: dualvec hi acc = 0
            # Set intermediate pointer for column j
            add x11, x0, x13        # x11 = inter[0][j]
            loopi 68, 10            # 68-element dot product
                bn.lid x4, 0(x11)   # w6 = inter[i][j] lo
                bn.lid x5, 32(x11)  # w7 = inter[i][j] hi
                add x11, x11, x21   # advance to next row (+2816)
                bn.mov w0, w6       # sw: lo vec
                bn.mov w1, w7       # sw: hi vec
                bn.mov w19, w3      # sw: scalar
                jal x1, gf256_macc_dualvec_sw  # w20 ^= w0*s ; w30 ^= w1*s
                bn.rshi w3, w4, w3 >> 8    # advance O scalar
                bn.rshi w4, w5, w4 >> 8
                bn.rshi w5, w31, w5 >> 8
            bn.mov w8, w20           # sw: dualvec lo acc -> w8 for store
            bn.mov w9, w30           # sw: dualvec hi acc -> w9 for store
            # Store P3_full[k][j] (lo + hi)
            bn.sid x6, 0(x10++)      # store w8 (lo), advance 32
            bn.sid x7, 0(x10++)      # store w9 (hi), advance 32
            # Advance to next intermediate column
            addi x13, x13, 64       # next column (+64B)
        nop                              # separate outer/middle loop end addresses
#endif

    # Phase 3: Upper extraction
    # P3_full[r][c] at P3_full_base + r*2816 + c*64.
    # Diagonal stride = (44+1) x 64 = 2880 bytes.
    # Output: diagonal entry + off-diagonal XOR pairs per row.

    lw x10, 0(x3)                   # P3 output ptr
    lw x15, 20(x3)                  # P3_full base
    add x16, x0, x15               # x16 = diagonal tracker
    li x18, 43                      # off-diagonal count (row 0 has 43)
    li x19, 2880                    # diagonal stride
    li x21, 2816                    # row stride

    loopi 43, 19                    # rows 0..42
        # Load and store diagonal entry
        bn.lid x4, 0(x16)           # w6 = P3_full[r][r] lo
        bn.lid x5, 32(x16)          # w7 = P3_full[r][r] hi
        bn.sid x4, 0(x10++)         # store diagonal lo
        bn.sid x5, 0(x10++)         # store diagonal hi
        # Set up row and column pointers for off-diagonal
        addi x17, x16, 64           # x17 = P3_full[r][r+1]
        add x22, x16, x21           # x22 = P3_full[r+1][r]
        loop x18, 10                # off-diagonal entries
            bn.lid x4, 0(x17)       # w6 = P3_full[r][c] lo
            bn.lid x5, 32(x17)      # w7 = P3_full[r][c] hi
            addi x17, x17, 64       # next col in row
            bn.lid x6, 0(x22)       # w8 = P3_full[c][r] lo
            bn.lid x7, 32(x22)      # w9 = P3_full[c][r] hi
            add x22, x22, x21       # next row in col (+2816)
            bn.xor w6, w6, w8       # XOR lo
            bn.xor w7, w7, w9       # XOR hi
            bn.sid x4, 0(x10++)     # store lo (x4=6 -> w6)
            bn.sid x5, 0(x10++)     # store hi (x5=7 -> w7)
        # Advance diagonal and decrement count
        add x16, x16, x19           # next diagonal (+2880)
        addi x18, x18, -1           # one fewer off-diagonal entry

    # Row 43: diagonal only
    bn.lid x4, 0(x16)               # w6 = P3_full[43][43] lo
    bn.lid x5, 32(x16)              # w7 = P3_full[43][43] hi
    bn.sid x4, 0(x10++)             # store diagonal lo
    bn.sid x5, 0(x10++)             # store diagonal hi

    # Phase 4: Epilogue
    lw x1, 12(x3)                   # restore return addr
    li x30, 128160                  # deallocate stack
    add x2, x2, x30
#ifdef GF_INSTRUCTIONS
    csrrw x0, mod1, x0              # force mod1=0 on exit (HW cursor leaves mod1=4)
#endif
    ret

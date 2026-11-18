.section .text
.global P3_cal
.balign 4
/* P3_cal (Ip3, HW bn.gfmul.8): P3 = Upper(O^T x B) over GF(256), V=74, O=M=45.
 * Dense P3_full = O^T x B: four output rows k0..k0+3 per pass (k0 = 0..40), so
 * each B load feeds four O columns (row k0 in ACC/ACCH, rows k0+1..k0+3 in
 * w22..w27 via plain gfmul + xor), then one single-row pass for k = 44. The fold
 * writes the diagonal and the XOR of each off-diagonal pair into the packed tri.
 * in:  x10 = tri out (1,035 x 64B = 66,240B, row-major upper)
 *      x11 = B = P1*O + P2 (74x45 cells of 64B, row stride 2,880B)
 *      x12 = O, 45 cols x 96B (3 WDRs, rows 74..95 zero)
 * out: tri at the entry value of x10
 * stack: 129,632B = frame 32 + P3_full 45x45x64 (129,600).
 * clob: x3-x8, x10, x11, x13, x15-x19, x21, x22, x29-x31; w6-w28, w31; ACC, ACCH,
 *   FG0; mod0 = 0x11b, mod1 = 0 on exit. x2 restored. leaf.
 * wdr: w10..w21 O cols k0..k0+3 (3 segments each); w6/w7 B lo/hi; w8/w9 ACC/ACCH
 *   copies; w22..w27 rows k0+1..k0+3 lo/hi; w28 product; w31 zero.
 */
P3_cal:
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31

    li x30, 129632                  # 32 frame + 129,600 P3_full
    sub x2, x2, x30
    add x3, x0, x2

    sw x10, 0(x3)                   # tri out
    sw x11, 4(x3)                   # B
    sw x12, 16(x3)                  # O
    addi x15, x3, 32
    sw x15, 20(x3)                  # P3_full

    # P3_full = O^T x B. One mod1 cursor walks all four columns; .acch.inc is
    # the last gfmul of each row, and each 32-row segment wraps the cursor to 0.
    li x4, 6                        # w6 (B lo)
    li x5, 7                        # w7 (B hi)
    li x6, 8                        # w8 (fold)
    li x7, 9                        # w9 (fold)
    li x21, 11520                   # 4-row stride (4 x 2880), B and P3_full
    li x29, 2880                    # row stride
    lw x16, 16(x3)                  # O read ptr
    lw x10, 20(x3)                  # P3_full row 0
    loopi 11, 178
        li x8, 10                       # O cols k0..k0+3 -> w10..w21
        loopi 12, 2
            bn.lid x8, 0(x16++)
            addi x8, x8, 1
        lw x13, 4(x3)                   # B col 0
        add x17, x0, x10                # P3_full[k0][j]
        loopi 45, 170
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            bn.xor w22, w22, w22
            bn.xor w23, w23, w23
            bn.xor w24, w24, w24
            bn.xor w25, w25, w25
            bn.xor w26, w26, w26
            bn.xor w27, w27, w27
            add x11, x0, x13               # B[0][j]
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
                bn.lid x4, 2880(x11)
                bn.lid x5, 2912(x11)
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
                bn.lid x4, 5760(x11)
                bn.lid x5, 5792(x11)
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
                bn.lid x4, 8640(x11)
                bn.lid x5, 8672(x11)
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
                bn.lid x4, 2880(x11)
                bn.lid x5, 2912(x11)
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
                bn.lid x4, 5760(x11)
                bn.lid x5, 5792(x11)
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
                bn.lid x4, 8640(x11)
                bn.lid x5, 8672(x11)
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
            loopi 10, 17                 # rows 64..73: O[64:73] (w12/w15/w18/w21)
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
                add x11, x11, x29
            bn.sd w8, 0(x17)
            bn.sd w9, 32(x17)
            bn.sd w22, 2880(x17)
            bn.sd w23, 2912(x17)
            bn.sd w24, 5760(x17)
            bn.sd w25, 5792(x17)
            bn.sd w26, 8640(x17)
            bn.sd w27, 8672(x17)
            addi x17, x17, 64
            addi x13, x13, 64
        add x10, x10, x21               # P3_full row k0+4

    # k = 44: one output row, x16 = O col 44, x10 = P3_full row 44
    li x8, 10
    loopi 3, 2
        bn.lid x8, 0(x16++)
        addi x8, x8, 1
    lw x13, 4(x3)
    add x17, x0, x10
    loopi 45, 26
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x11, x0, x13
        csrrw x0, mod1, x0
        loopi 32, 5
            bn.lid x4, 0(x11)
            bn.lid x5, 32(x11)
            bn.gfmul.8.acc w8, w6, w10
            bn.gfmul.8.acch.inc w9, w7, w10
            add x11, x11, x29
        loopi 32, 5
            bn.lid x4, 0(x11)
            bn.lid x5, 32(x11)
            bn.gfmul.8.acc w8, w6, w11
            bn.gfmul.8.acch.inc w9, w7, w11
            add x11, x11, x29
        loopi 10, 5
            bn.lid x4, 0(x11)
            bn.lid x5, 32(x11)
            bn.gfmul.8.acc w8, w6, w12
            bn.gfmul.8.acch.inc w9, w7, w12
            add x11, x11, x29
        bn.sd w8, 0(x17)
        bn.sd w9, 32(x17)
        addi x17, x17, 64
        addi x13, x13, 64

    # fold: P3_full[r][c] at base + 2880r + 64c; diagonal stride 2944.
    # tri row r = diagonal, then P3_full[r][c] ^ P3_full[c][r] for c > r.
    lw x10, 0(x3)                   # tri out
    lw x15, 20(x3)                  # P3_full
    add x16, x0, x15                # diagonal
    li x18, 44                      # off-diagonal count of row 0
    li x19, 2944                    # diagonal stride
    li x21, 2880                    # row stride

    loopi 44, 19                    # rows 0..43
        bn.lid x4, 0(x16)
        bn.lid x5, 32(x16)
        bn.sid x4, 0(x10++)
        bn.sid x5, 0(x10++)
        addi x17, x16, 64           # P3_full[r][r+1]
        add x22, x16, x21           # P3_full[r+1][r]
        loop x18, 10
            bn.lid x4, 0(x17)
            bn.lid x5, 32(x17)
            addi x17, x17, 64
            bn.lid x6, 0(x22)
            bn.lid x7, 32(x22)
            add x22, x22, x21
            bn.xor w6, w6, w8
            bn.xor w7, w7, w9
            bn.sid x4, 0(x10++)
            bn.sid x5, 0(x10++)
        add x16, x16, x19
        addi x18, x18, -1

    # row 44: diagonal only
    bn.lid x4, 0(x16)
    bn.lid x5, 32(x16)
    bn.sid x4, 0(x10++)
    bn.sid x5, 0(x10++)

    li x30, 129632
    add x2, x2, x30
    csrrw x0, mod1, x0              # the k = 44 pass leaves mod1 = 10
    ret

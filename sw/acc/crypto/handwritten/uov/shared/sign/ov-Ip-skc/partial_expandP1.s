/* partial_expandP1 (Ip) - expand one column of P1 via streaming AES.
 *
 *   variant     cpp flag             body
 *   bngfonly    -DGF_INSTRUCTIONS    jal aes128_sign + stack scratch (with helper partial_expandP1_epilogue)
 *   bngfaes     -DAES_|GF_           inline bn.aes128.encz/encm/encf
 *
 * Swonly tier uses separately-named partial_expandP1_table (in partial_expandP1_table.s).
 */

.section .text
.balign 4
.global partial_expandP1

#if defined(AES_INSTRUCTIONS)

/* =============== bngfaes (inline bn.aes128.*) =============== */
partial_expandP1:

    li x23, 15
    bn.lid x23, 0(x2++)
    #Calculating IV
    bn.addi w16, w31, 22
    bn.mulqacc.wo.z w16, w16.0, w15.0, 0
    bn.addi w15, w16, 0x1
    bn.or w15, w16, w15 << 128
    bn.rshi w0, w15, w31 >> 160
    # IV chains reuse caller's w19 (= +2 broadcast).
    # Dispatch FIRST so each col<n> path computes only the IVs it needs.
    beq x0, x25, col0
    li x23, 1
    beq x23, x25, col1
    li x23, 2
    beq x23, x25, col2
    li x23, 3
    beq x23, x25, col3
    li x23, 4
    beq x23, x25, col4
    li x23, 5
    beq x23, x25, col5
    li x23, 6
    beq x23, x25, col6

    # col7 fall-through path: need w9, w10 -> 10 chained adds
    bn.add w1, w0, w19
    bn.add w2, w1, w19
    bn.add w3, w2, w19
    bn.add w4, w3, w19
    bn.add w5, w4, w19
    bn.add w6, w5, w19
    bn.add w7, w6, w19
    bn.add w8, w7, w19
    bn.add w9, w8, w19
    bn.add w10, w9, w19

    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encm w9, w9, w29
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w9, w9, w27
    bn.aes128.encm w9, w9, w26
    bn.aes128.encm w9, w9, w25
    bn.aes128.encm w9, w9, w24
    bn.aes128.encm w9, w9, w23
    bn.aes128.encm w9, w9, w22
    bn.aes128.encm w9, w9, w21
    bn.aes128.encf w9, w9, w20

    bn.aes128.encz.swap w10, w10, w30
    bn.aes128.encm w10, w10, w29
    bn.aes128.encm w10, w10, w28
    bn.aes128.encm w10, w10, w27
    bn.aes128.encm w10, w10, w26
    bn.aes128.encm w10, w10, w25
    bn.aes128.encm w10, w10, w24
    bn.aes128.encm w10, w10, w23
    bn.aes128.encm w10, w10, w22
    bn.aes128.encm w10, w10, w21
    bn.aes128.encf w10, w10, w20
    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    ret
    col6:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.add w3, w2, w19
        bn.add w4, w3, w19
        bn.add w5, w4, w19
        bn.add w6, w5, w19
        bn.add w7, w6, w19
        bn.add w8, w7, w19
        bn.add w9, w8, w19
        bn.aes128.encz.swap w8, w8, w30
        bn.aes128.encm w8, w8, w29
        bn.aes128.encm w8, w8, w28
        bn.aes128.encm w8, w8, w27
        bn.aes128.encm w8, w8, w26
        bn.aes128.encm w8, w8, w25
        bn.aes128.encm w8, w8, w24
        bn.aes128.encm w8, w8, w23
        bn.aes128.encm w8, w8, w22
        bn.aes128.encm w8, w8, w21
        bn.aes128.encf w8, w8, w20

        bn.aes128.encz.swap w9, w9, w30
        bn.aes128.encm w9, w9, w29
        bn.aes128.encm w9, w9, w28
        bn.aes128.encm w9, w9, w27
        bn.aes128.encm w9, w9, w26
        bn.aes128.encm w9, w9, w25
        bn.aes128.encm w9, w9, w24
        bn.aes128.encm w9, w9, w23
        bn.aes128.encm w9, w9, w22
        bn.aes128.encm w9, w9, w21
        bn.aes128.encf w9, w9, w20
        bn.rshi w13, w9, w31 >> 160
        bn.rshi w13, w31, w13 >> 160
        bn.rshi w12, w9, w8 >> 64
        ret
    col5:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.add w3, w2, w19
        bn.add w4, w3, w19
        bn.add w5, w4, w19
        bn.add w6, w5, w19
        bn.add w7, w6, w19
        bn.add w8, w7, w19
        bn.aes128.encz.swap w6, w6, w30
        bn.aes128.encm w6, w6, w29
        bn.aes128.encm w6, w6, w28
        bn.aes128.encm w6, w6, w27
        bn.aes128.encm w6, w6, w26
        bn.aes128.encm w6, w6, w25
        bn.aes128.encm w6, w6, w24
        bn.aes128.encm w6, w6, w23
        bn.aes128.encm w6, w6, w22
        bn.aes128.encm w6, w6, w21
        bn.aes128.encf w6, w6, w20

        bn.aes128.encz.swap w7, w7, w30
        bn.aes128.encm w7, w7, w29
        bn.aes128.encm w7, w7, w28
        bn.aes128.encm w7, w7, w27
        bn.aes128.encm w7, w7, w26
        bn.aes128.encm w7, w7, w25
        bn.aes128.encm w7, w7, w24
        bn.aes128.encm w7, w7, w23
        bn.aes128.encm w7, w7, w22
        bn.aes128.encm w7, w7, w21
        bn.aes128.encf w7, w7, w20

        bn.aes128.encz.swap w8, w8, w30
        bn.aes128.encm w8, w8, w29
        bn.aes128.encm w8, w8, w28
        bn.aes128.encm w8, w8, w27
        bn.aes128.encm w8, w8, w26
        bn.aes128.encm w8, w8, w25
        bn.aes128.encm w8, w8, w24
        bn.aes128.encm w8, w8, w23
        bn.aes128.encm w8, w8, w22
        bn.aes128.encm w8, w8, w21
        bn.aes128.encf w8, w8, w20
        bn.rshi w11, w8, w7 >> 64
        bn.rshi w11, w31, w11 >> 160
        bn.rshi w10, w7, w6 >> 224
        ret
    col4:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.add w3, w2, w19
        bn.add w4, w3, w19
        bn.add w5, w4, w19
        bn.add w6, w5, w19
        bn.aes128.encz.swap w5, w5, w30
        bn.aes128.encm w5, w5, w29
        bn.aes128.encm w5, w5, w28
        bn.aes128.encm w5, w5, w27
        bn.aes128.encm w5, w5, w26
        bn.aes128.encm w5, w5, w25
        bn.aes128.encm w5, w5, w24
        bn.aes128.encm w5, w5, w23
        bn.aes128.encm w5, w5, w22
        bn.aes128.encm w5, w5, w21
        bn.aes128.encf w5, w5, w20

        bn.aes128.encz.swap w6, w6, w30
        bn.aes128.encm w6, w6, w29
        bn.aes128.encm w6, w6, w28
        bn.aes128.encm w6, w6, w27
        bn.aes128.encm w6, w6, w26
        bn.aes128.encm w6, w6, w25
        bn.aes128.encm w6, w6, w24
        bn.aes128.encm w6, w6, w23
        bn.aes128.encm w6, w6, w22
        bn.aes128.encm w6, w6, w21
        bn.aes128.encf w6, w6, w20
        bn.rshi w9, w6, w31 >> 224
        bn.rshi w9, w31, w9 >> 160
        bn.rshi w8, w6, w5 >> 128
        ret
    col3:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.add w3, w2, w19
        bn.add w4, w3, w19
        bn.add w5, w4, w19
        bn.aes128.encz.swap w4, w4, w30
        bn.aes128.encm w4, w4, w29
        bn.aes128.encm w4, w4, w28
        bn.aes128.encm w4, w4, w27
        bn.aes128.encm w4, w4, w26
        bn.aes128.encm w4, w4, w25
        bn.aes128.encm w4, w4, w24
        bn.aes128.encm w4, w4, w23
        bn.aes128.encm w4, w4, w22
        bn.aes128.encm w4, w4, w21
        bn.aes128.encf w4, w4, w20

        bn.aes128.encz.swap w5, w5, w30
        bn.aes128.encm w5, w5, w29
        bn.aes128.encm w5, w5, w28
        bn.aes128.encm w5, w5, w27
        bn.aes128.encm w5, w5, w26
        bn.aes128.encm w5, w5, w25
        bn.aes128.encm w5, w5, w24
        bn.aes128.encm w5, w5, w23
        bn.aes128.encm w5, w5, w22
        bn.aes128.encm w5, w5, w21
        bn.aes128.encf w5, w5, w20
        bn.rshi w7, w5, w31 >> 128
        bn.rshi w7, w31, w7 >> 160
        bn.rshi w6, w5, w4 >> 32
        ret
    col2:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.add w3, w2, w19
        bn.add w4, w3, w19
        bn.aes128.encz.swap w2, w2, w30
        bn.aes128.encm w2, w2, w29
        bn.aes128.encm w2, w2, w28
        bn.aes128.encm w2, w2, w27
        bn.aes128.encm w2, w2, w26
        bn.aes128.encm w2, w2, w25
        bn.aes128.encm w2, w2, w24
        bn.aes128.encm w2, w2, w23
        bn.aes128.encm w2, w2, w22
        bn.aes128.encm w2, w2, w21
        bn.aes128.encf w2, w2, w20

        bn.aes128.encz.swap w3, w3, w30
        bn.aes128.encm w3, w3, w29
        bn.aes128.encm w3, w3, w28
        bn.aes128.encm w3, w3, w27
        bn.aes128.encm w3, w3, w26
        bn.aes128.encm w3, w3, w25
        bn.aes128.encm w3, w3, w24
        bn.aes128.encm w3, w3, w23
        bn.aes128.encm w3, w3, w22
        bn.aes128.encm w3, w3, w21
        bn.aes128.encf w3, w3, w20

        bn.aes128.encz.swap w4, w4, w30
        bn.aes128.encm w4, w4, w29
        bn.aes128.encm w4, w4, w28
        bn.aes128.encm w4, w4, w27
        bn.aes128.encm w4, w4, w26
        bn.aes128.encm w4, w4, w25
        bn.aes128.encm w4, w4, w24
        bn.aes128.encm w4, w4, w23
        bn.aes128.encm w4, w4, w22
        bn.aes128.encm w4, w4, w21
        bn.aes128.encf w4, w4, w20

        bn.rshi w5, w4, w3 >> 32
        bn.rshi w5, w31, w5 >> 160
        bn.rshi w4, w3, w2 >> 192
        ret
    col1:
        bn.add w1, w0, w19
        bn.add w2, w1, w19
        bn.aes128.encz.swap w1, w1, w30
        bn.aes128.encm w1, w1, w29
        bn.aes128.encm w1, w1, w28
        bn.aes128.encm w1, w1, w27
        bn.aes128.encm w1, w1, w26
        bn.aes128.encm w1, w1, w25
        bn.aes128.encm w1, w1, w24
        bn.aes128.encm w1, w1, w23
        bn.aes128.encm w1, w1, w22
        bn.aes128.encm w1, w1, w21
        bn.aes128.encf w1, w1, w20

        bn.aes128.encz.swap w2, w2, w30
        bn.aes128.encm w2, w2, w29
        bn.aes128.encm w2, w2, w28
        bn.aes128.encm w2, w2, w27
        bn.aes128.encm w2, w2, w26
        bn.aes128.encm w2, w2, w25
        bn.aes128.encm w2, w2, w24
        bn.aes128.encm w2, w2, w23
        bn.aes128.encm w2, w2, w22
        bn.aes128.encm w2, w2, w21
        bn.aes128.encf w2, w2, w20
        bn.rshi w3, w2, w31 >> 192
        bn.rshi w3, w31, w3 >> 160
        bn.rshi w2, w2, w1 >> 96
        ret
    col0:
        bn.add w1, w0, w19
        bn.aes128.encz.swap w0, w0, w30
        bn.aes128.encm w0, w0, w29
        bn.aes128.encm w0, w0, w28
        bn.aes128.encm w0, w0, w27
        bn.aes128.encm w0, w0, w26
        bn.aes128.encm w0, w0, w25
        bn.aes128.encm w0, w0, w24
        bn.aes128.encm w0, w0, w23
        bn.aes128.encm w0, w0, w22
        bn.aes128.encm w0, w0, w21
        bn.aes128.encf w0, w0, w20

        bn.aes128.encz.swap w1, w1, w30
        bn.aes128.encm w1, w1, w29
        bn.aes128.encm w1, w1, w28
        bn.aes128.encm w1, w1, w27
        bn.aes128.encm w1, w1, w26
        bn.aes128.encm w1, w1, w25
        bn.aes128.encm w1, w1, w24
        bn.aes128.encm w1, w1, w23
        bn.aes128.encm w1, w1, w22
        bn.aes128.encm w1, w1, w21
        bn.aes128.encf w1, w1, w20
        bn.rshi w1, w1, w31 >> 96
        bn.rshi w1, w31, w1 >> 160
        ret

#else

/* =============== bngfonly (jal aes128_sign + epilogue helper) =============== */
partial_expandP1:
    # Caller-state preservation: caller's x5, x6 must survive (gf256trimat
    # uses x5 as P1+P1T cursor, x6 as base). The la/li sequences below
    # clobber both, so we save them on stack.
    # Stack frame plan: caller pre-decremented x2 by 32 and stashed the col
    # arg at offset 0. We allocate ANOTHER 32 bytes below (the extra 24 are
    # wasted padding bn.lid requires 32-byte aligned offsets, so we can't
    # use a smaller frame and still reach the col arg via bn.lid).
    addi x2, x2, -32
    sw x5, 0(x2)
    sw x6, 4(x2)

    li x23, 15
    bn.lid x23, 32(x2)              # w15 = col-index arg at original x2
    # Compute IV(0) (uses w15 stack arg)
    bn.addi w16, w31, 22
    bn.mulqacc.wo.z w16, w16.0, w15.0, 0
    bn.addi w15, w16, 0x1
    bn.or w15, w16, w15 << 128
    bn.rshi w0, w15, w31 >> 160

    # Reload AES constants caller's w7/w8/w9 may hold P1 data from prior
    # expand_352 / partial_expandP1 calls. Function-side reload is the same
    # pattern as expand_352.
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)

    # Branch dispatch
    beq x0, x25, col0
    li x23, 1
    beq x23, x25, col1
    li x23, 2
    beq x23, x25, col2
    li x23, 3
    beq x23, x25, col3
    li x23, 4
    beq x23, x25, col4
    li x23, 5
    beq x23, x25, col5
    li x23, 6
    beq x23, x25, col6

    # col7 fall-through: encrypt IV(9), IV(10) to output w14, w15
    bn.mov w18, w0
    bn.add w18, w18, w19            # IV(1)
    bn.add w18, w18, w19            # IV(2)
    bn.add w18, w18, w19            # IV(3)
    bn.add w18, w18, w19            # IV(4)
    bn.add w18, w18, w19            # IV(5)
    bn.add w18, w18, w19            # IV(6)
    bn.add w18, w18, w19            # IV(7)
    bn.add w18, w18, w19            # IV(8)
    bn.add w18, w18, w19            # IV(9)
    jal x1, aes128_sign             # w2 = ct(9)
    bn.mov w3, w2                   # temp: ct(9)
    bn.add w18, w18, w19            # IV(10)
    jal x1, aes128_sign             # w2 = ct(10)
    bn.mov w10, w2                  # w10 = ct(10)
    bn.mov w9, w3                   # w9 = ct(9) (clobbers msb_mask)
    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    jal x0, partial_expandP1_epilogue

col6:
    # Encrypt IV(8), IV(9) to output w12, w13
    bn.mov w18, w0
    bn.add w18, w18, w19            # 1
    bn.add w18, w18, w19            # 2
    bn.add w18, w18, w19            # 3
    bn.add w18, w18, w19            # 4
    bn.add w18, w18, w19            # 5
    bn.add w18, w18, w19            # 6
    bn.add w18, w18, w19            # 7
    bn.add w18, w18, w19            # IV(8)
    jal x1, aes128_sign             # w2 = ct(8)
    bn.mov w3, w2                   # temp: ct(8)
    bn.add w18, w18, w19            # IV(9)
    jal x1, aes128_sign             # w2 = ct(9)
    bn.mov w9, w2                   # w9 = ct(9) (clobbers msb_mask)
    bn.mov w8, w3                   # w8 = ct(8) (clobbers affine)
    bn.rshi w13, w9, w31 >> 160
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w9, w8 >> 64
    jal x0, partial_expandP1_epilogue

col5:
    # Encrypt IV(6), IV(7), IV(8) to output w10, w11
    bn.mov w18, w0
    bn.add w18, w18, w19            # 1
    bn.add w18, w18, w19            # 2
    bn.add w18, w18, w19            # 3
    bn.add w18, w18, w19            # 4
    bn.add w18, w18, w19            # 5
    bn.add w18, w18, w19            # IV(6)
    jal x1, aes128_sign             # w2 = ct(6)
    bn.mov w3, w2                   # temp ct(6)
    bn.add w18, w18, w19            # IV(7)
    jal x1, aes128_sign             # w2 = ct(7)
    bn.mov w4, w2                   # temp ct(7)
    bn.add w18, w18, w19            # IV(8)
    jal x1, aes128_sign             # w2 = ct(8)
    bn.mov w8, w2                   # w8 = ct(8) (clobbers affine)
    bn.mov w7, w4                   # w7 = ct(7) (clobbers byte_swap_mask)
    bn.mov w6, w3                   # w6 = ct(6)
    bn.rshi w11, w8, w7 >> 64
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w7, w6 >> 224
    jal x0, partial_expandP1_epilogue

col4:
    # Encrypt IV(5), IV(6) to output w8, w9
    bn.mov w18, w0
    bn.add w18, w18, w19            # 1
    bn.add w18, w18, w19            # 2
    bn.add w18, w18, w19            # 3
    bn.add w18, w18, w19            # 4
    bn.add w18, w18, w19            # IV(5)
    jal x1, aes128_sign             # w2 = ct(5)
    bn.mov w3, w2                   # temp ct(5)
    bn.add w18, w18, w19            # IV(6)
    jal x1, aes128_sign             # w2 = ct(6)
    bn.mov w6, w2                   # w6 = ct(6)
    bn.mov w5, w3                   # w5 = ct(5)
    bn.rshi w9, w6, w31 >> 224
    bn.rshi w9, w31, w9 >> 160
    bn.rshi w8, w6, w5 >> 128
    jal x0, partial_expandP1_epilogue

col3:
    # Encrypt IV(4), IV(5) to output w6, w7
    bn.mov w18, w0
    bn.add w18, w18, w19            # 1
    bn.add w18, w18, w19            # 2
    bn.add w18, w18, w19            # 3
    bn.add w18, w18, w19            # IV(4)
    jal x1, aes128_sign             # w2 = ct(4)
    bn.mov w3, w2                   # temp ct(4)
    bn.add w18, w18, w19            # IV(5)
    jal x1, aes128_sign             # w2 = ct(5)
    bn.mov w5, w2                   # w5 = ct(5)
    bn.mov w4, w3                   # w4 = ct(4)
    bn.rshi w7, w5, w31 >> 128
    bn.rshi w7, w31, w7 >> 160
    bn.rshi w6, w5, w4 >> 32
    jal x0, partial_expandP1_epilogue

col2:
    # Encrypt IV(2), IV(3), IV(4) to output w4, w5
    bn.mov w18, w0
    bn.add w18, w18, w19            # 1
    bn.add w18, w18, w19            # IV(2)
    jal x1, aes128_sign             # w2 = ct(2)
    bn.mov w3, w2                   # temp ct(2)
    bn.add w18, w18, w19            # IV(3)
    jal x1, aes128_sign             # w2 = ct(3)
    bn.mov w5, w2                   # temp ct(3) (we'll move later)
    bn.add w18, w18, w19            # IV(4)
    jal x1, aes128_sign             # w2 = ct(4)
    bn.mov w4, w2                   # w4 = ct(4)
    # Now: w3=ct(2), w5=ct(3), w4=ct(4). Need final: w2=ct(2), w3=ct(3), w4=ct(4).
    bn.mov w2, w3                   # w2 = ct(2)
    bn.mov w3, w5                   # w3 = ct(3)
    bn.rshi w5, w4, w3 >> 32
    bn.rshi w5, w31, w5 >> 160
    bn.rshi w4, w3, w2 >> 192
    jal x0, partial_expandP1_epilogue

col1:
    # Encrypt IV(1), IV(2) to output w2, w3
    bn.mov w18, w0
    bn.add w18, w18, w19            # IV(1)
    jal x1, aes128_sign             # w2 = ct(1)
    bn.mov w3, w2                   # temp ct(1)
    bn.add w18, w18, w19            # IV(2)
    jal x1, aes128_sign             # w2 = ct(2)
    # w2 = ct(2), w3 = ct(1). Need final: w1 = ct(1), w2 = ct(2).
    bn.mov w1, w3                   # w1 = ct(1)
    bn.rshi w3, w2, w31 >> 192
    bn.rshi w3, w31, w3 >> 160
    bn.rshi w2, w2, w1 >> 96
    jal x0, partial_expandP1_epilogue

col0:
    # Encrypt IV(0), IV(1) to output w1
    bn.mov w18, w0
    jal x1, aes128_sign             # w2 = ct(0)
    bn.mov w0, w2                   # w0 = ct(0) used by rshi-reorder
    bn.add w18, w18, w19            # IV(1)
    jal x1, aes128_sign             # w2 = ct(1)
    bn.mov w1, w2                   # w1 = ct(1)
    bn.rshi w1, w1, w31 >> 96
    bn.rshi w1, w31, w1 >> 160
    jal x0, partial_expandP1_epilogue

partial_expandP1_epilogue:
    lw x5, 0(x2)
    lw x6, 4(x2)
    addi x2, x2, 64                 # 32 internal + 32 caller arg (consumed)
    ret

#endif

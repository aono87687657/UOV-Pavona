/* gf256trimat_2trimat_madd_68_68_44_44 (Ip) - orchestrator for P1+P1T mat-mat-add.
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW path; calls row_mul_O, partial_expandP1_table
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8 + jal aes128_sign + row_mul_O
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8 + inline bn.aes128.* + row_mul_O
 */

.section .text
.balign 4
.global gf256trimat_2trimat_madd_68_68_44_44

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.8 + inline bn.aes128.*) =============== */
gf256trimat_2trimat_madd_68_68_44_44:

    bn.xor w31, w31, w31
    
  
    li x7, 0x11b   # load GF(256) reduction polynomial x^8 + x^4 + x^3 + x + 1
    csrrw x0, mod0, x7  # set mod register to GF(256) reduction polynomial 
 
    # Save x10, x11, x12 into stack
    addi x2, x2, -32
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    add x7, x0, x2 #x7 point at argument
    add x18, x0, x13       # x18 = P1 cache base (immutable; survives row_mul_O + expand_352)
    add x22, x0, x18       # x22 = cache fill cursor (q-order, advances over diag+upper)
    # allocate 4352 byte for one column/row of P1+P1^T
    # 68 * 64 bytes
    li  x5, 4352
    sub x2, x2, x5 
    add x5, x0, x2 
    add x6, x0, x5

    li x30, 30
    bn.lid x30, 0(x10)
    bn.or w30, w30, w30 << 128
    # Pre-compute AES-128 key schedule into w20-w29
    bn.aes128.kf w29, w30, 1
    bn.aes128.kf w28, w29, 2
    bn.aes128.kf w27, w28, 3
    bn.aes128.kf w26, w27, 4
    bn.aes128.kf w25, w26, 5
    bn.aes128.kf w24, w25, 6
    bn.aes128.kf w23, w24, 7
    bn.aes128.kf w22, w23, 8
    bn.aes128.kf w21, w22, 9
    bn.aes128.kf w20, w21, 10
    # IV increment constant (w19 = +2 per counter step)
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160
    #Setup IV
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    li x31, 31              # Start generating row 0 of P1+P1T
    bn.sid x31, 0(x5++)
    bn.sid x31, 0(x5++)
    # Inc 2: fill diag cache slot q(r,r) = raw P1[r][r] via partial_expandP1
    # (byte-identical to expand_352). q derived from cursor (before advance).
    sub  x24, x22, x18      # q(r,r)*64 (cursor offset from cache base)
    srli x25, x24, 6        # q(r,r)
    andi x25, x25, 7        # col_index = q & 7
    srli x24, x24, 9        # col_arg = q >> 3
    addi x2, x2, -32
    bn.sid x31, 0(x2)       # zero arg slot (w31), then write col_arg low
    sw x24, 0(x2)
    jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops the arg slot
    slli x25, x25, 1        # WDR index = 2*col_index
    bn.sid x25, 0(x22++)    # cache diag low half  (x22 += 32)
    addi x25, x25, 1
    bn.sid x25, 0(x22++)    # cache diag high half (x22 += 32)
    li x8, 2
    li x9, 16
    jal x1, expand_352
    loopi 67, 8
        bn.sid x8, 0(x22++)     # cache upper entry (low half), advance cursor +32
        bn.sid x8++, 0(x5)
        bn.sid x8, 0(x22++)     # cache upper entry (high half), advance cursor +32
        bn.sid x8++, 32(x5)
        bne x8, x9, skip_expandp1
        li x8, 0
        jal x1, expand_352
        skip_expandp1:
        addi x5, x5, 64
    # # Start Multiply First Row with Matrix O
    li x19, 1
    li x28, 19 
    li x29, 20

    jal x1, row_mul_O

    # Restore w19, w20 clobbered by row_mul_O
    bn.aes128.kf w20, w21, 10
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    add x5, x0, x6              #Reset x5
    lw x11, 4(x7)               #Reset Matrix O address
    # Start Compute row1 of P1+p1T
    li x21, 66 # Upper triangler row lenthg
    li x27, 1 #current row
    loopi 66, 67
        add x26, x0, x27 #index
        li x9, 67
        loop x27, 8
            slli x24, x26, 6        # q(k,r)*64 byte offset
            add x24, x18, x24       # cache addr of transpose entry P1[k][r]
            bn.lid x0, 0(x24)
            bn.sid x0, 0(x5++)
            bn.lid x0, 32(x24)
            bn.sid x0, 0(x5++)
            add x26, x26, x9
            addi x9, x9, -1
        bn.sid x31, 0(x5++)     #Skip diagonal
        bn.sid x31, 0(x5++)     #Skip diagonal
        # Inc 2: fill diag cache slot q(r,r) = raw P1[r][r] via partial_expandP1
        # (byte-identical to expand_352). q from cursor; placed BEFORE the IV math
        # so partial_expandP1's w0-w16 clobber is harmless (recomputed below).
        sub  x24, x22, x18      # q(r,r)*64 (cursor offset from cache base)
        srli x25, x24, 6        # q(r,r)
        andi x25, x25, 7        # col_index = q & 7
        srli x24, x24, 9        # col_arg = q >> 3
        addi x2, x2, -32
        bn.sid x31, 0(x2)       # zero arg slot (w31), then write col_arg low
        sw x24, 0(x2)
        jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops the arg slot
        slli x25, x25, 1        # WDR index = 2*col_index
        bn.sid x25, 0(x22++)    # cache diag low half  (x22 += 32)
        addi x25, x25, 1
        bn.sid x25, 0(x22++)    # cache diag high half (x22 += 32)
        addi x2, x2, -32        # Upper Triangle Part
        bn.sid x31, 0(x2)
        sw x27, 0(x2)           #Pass current row index to wdr
        bn.lid x0, 0(x2)
        bn.addi w1, w0, 1
        bn.addi w2, w31, 68
        bn.mulqacc.wo.z w2, w0.0, w2.0, 0
        bn.mulqacc.wo.z w3, w0.0, w1.0, 0
        bn.rshi w3, w31, w3 >> 1
        bn.sub w0, w2, w3
        bn.add w0, w0, w1
        bn.sid x0, 0(x2)
        lw x20, 0(x2) #index
        addi x2, x2, 32
        bn.rshi w18, w31, w0 >> 3 #calculate IV: row_idx * V - row_idx * (row_idx + 1) // 2 + col
        bn.addi w1, w31, 22       #col: always will be row + 1 because skip diagonal
        bn.mulqacc.wo.z w18, w18.0, w1.0, 0
        bn.addi w0, w18, 1
        bn.or w18, w18, w0 << 128
        bn.rshi w18, w18, w31 >> 160
        jal x1, expand_352
        andi x20, x20, 0x7 #Index % 8 
        slli x20, x20, 1
        li x9, 16
        loop x21, 8
            bn.sid x20, 0(x22++)    # cache upper entry (low half)
            bn.sid x20++, 0(x5)
            bn.sid x20, 0(x22++)    # cache upper entry (high half)
            bn.sid x20++, 32(x5)
            bne x9, x20, skip_expandp1_mid
                jal x1, expand_352
                li x20, 0
            skip_expandp1_mid:  addi x5, x5, 64
        jal x1, row_mul_O
        # Restore w19, w20 clobbered by row_mul_O
        bn.aes128.kf w20, w21, 10
        bn.addi w19, w31, 2
        bn.or w19, w19, w19 << 128
        bn.rshi w19, w19, w31 >> 160
        add x5, x0, x6          #Reset x5
        lw x11, 4(x7)               #Reset Matrix O address
        addi x27, x27, 1
        addi x21, x21, -1

        li x27, 67 #Last Row
        add x26, x0, x27 #index
        li x9, 67
        loop x27, 8
            slli x24, x26, 6        # q(k,r)*64 byte offset
            add x24, x18, x24       # cache addr of transpose entry P1[k][r]
            bn.lid x0, 0(x24)
            bn.sid x0, 0(x5++)
            bn.lid x0, 32(x24)
            bn.sid x0, 0(x5++)
            add x26, x26, x9
            addi x9, x9, -1
        bn.sid x31, 0(x5++)     #Skip diagonal
        bn.sid x31, 0(x5++)     #Skip diagonal
        # Inc 2: fill last diag cache slot q(67,67) = raw P1[67][67] via partial_expandP1.
        sub  x24, x22, x18      # q(67,67)*64
        srli x25, x24, 6        # q(67,67)
        andi x25, x25, 7        # col_index = q & 7
        srli x24, x24, 9        # col_arg = q >> 3
        addi x2, x2, -32
        bn.sid x31, 0(x2)       # zero arg slot (w31), then write col_arg low
        sw x24, 0(x2)
        jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops the arg slot
        slli x25, x25, 1        # WDR index = 2*col_index
        bn.sid x25, 0(x22++)    # cache diag low half
        addi x25, x25, 1
        bn.sid x25, 0(x22++)    # cache diag high half
        jal x1, row_mul_O
        # Restore w19, w20 clobbered by row_mul_O
        bn.aes128.kf w20, w21, 10
        bn.addi w19, w31, 2
        bn.or w19, w19, w19 << 128
        bn.rshi w19, w19, w31 >> 160
        add x5, x0, x6          #Reset x5
        lw x11, 4(x7)           #Reset Matrix O address
        lw x12, 8(x7)
        
        bn.addi w0, w31, 22
        bn.addi w1, w31, 293
        bn.mulqacc.wo.z w0, w0.0, w1.0, 0
        bn.addi w1, w0, 1
        bn.or w18, w0, w1 << 128
        bn.rshi w18, w18, w31 >> 160
        jal x1, expand_352
        li x8, 4
        li x9, 1
        li x28, 16 
        li x29, 17
        loopi 34, 627
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
    # Restore stack pointer before returning
    # x7 points to original x2 - 32, so restore: x2 = x7 + 32
    addi x2, x7, 32

    ret

#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.8 + aes128_sign) =============== */
gf256trimat_2trimat_madd_68_68_44_44:

    bn.xor w31, w31, w31

    li x7, 0x11b   # GF(256) reduction polynomial
    csrrw x0, mod0, x7

    # Save x10, x11, x12 AND x13..x16 (caller's). We hoist AES-constant
    # addresses into x13..x16 below; the orchestrator (ov-Ip-skc-sign.s)
    # relies on x13..x16 holding msg_len/pk_seed/O/S addresses on return,
    # so we must restore them at exit.
    addi x2, x2, -32
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)
    sw x14, 16(x2)
    sw x15, 20(x2)
    sw x16, 24(x2)
    add x7, x0, x2  # x7 points at argument
    add x18, x0, x13       # x18 = P1 cache base survivor (x13 reused for AES const addr below)
    add x22, x0, x18       # x22 = cache fill cursor (q-order); survives KS/expand/partial/row_mul_O

    # Pre-resolve AES constant addresses (hoisted out of refresh loops)
    la x13, byte_swap_mask
    la x14, affine_value
    la x15, msb_mask
    la x16, rcon

    # Pre-load AES constants
    li x4, 8
    bn.lid x4, 0(x14)               # w8 = affine_value
    li x4, 9
    bn.lid x4, 0(x15)               # w9 = msb_mask
    li x4, 11
    bn.lid x4, 0(x16)               # w11 = rcon

    # Allocate 4352 byte for one column/row of P1+P1^T (68 * 64 bytes)
    li  x5, 4352
    sub x2, x2, x5
    # (x5 = P1+P1T base will be set AFTER the KS chain KS_sign clobbers x5
    #  with the GF(256) reduction polynomial 0x11B, which is misaligned for
    #  bn.sid/lid use.)

    # Load AES key into w30, derive key schedule via KS_sign chain
    li x30, 30
    bn.lid x30, 0(x10)              # w30 = pk_seed | 0 (expandsk stored it zero-extended)
    bn.mov w17, w30                 # prime w17 = key | 0 BEFORE dual-store
    bn.or w30, w30, w30 << 128      # NOW dual-store w30 = key | key

    jal x1, KeySchedule_sign
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_sign
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_sign
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_sign
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_sign
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_sign
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_sign
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_sign
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_sign
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_sign
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128

    # IV increment constant (w19 = +2 per counter step)
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    # Initial IV
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    # NOW set x5 = P1+P1T base (KS chain done; x5 was clobbered to 0x11B
    # by the last KS_sign call's internal mod0 setup).
    add x5, x0, x2
    add x6, x0, x5

    li x31, 31                      # Start generating row 0 of P1+P1T
    bn.sid x31, 0(x5++)
    bn.sid x31, 0(x5++)
    # Inc 2: fill diag cache slot q(r,r) = raw P1[r][r] via partial_expandP1
    sub  x24, x22, x18      # q(r,r)*64
    srli x25, x24, 6        # q(r,r)
    andi x25, x25, 7        # col_index = q & 7
    srli x24, x24, 9        # col_arg = q >> 3
    addi x2, x2, -32
    bn.sid x31, 0(x2)       # zero arg slot (w31), then col_arg low
    sw x24, 0(x2)
    jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops arg slot
    slli x25, x25, 1        # WDR index = 2*col_index
    bn.sid x25, 0(x22++)    # cache diag low half
    addi x25, x25, 1
    bn.sid x25, 0(x22++)    # cache diag high half
    # partial_expandP1 (aes128_sign) clobbered w18; restore row-0 initial IV for expand_352
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32
    li x8, 2
    li x9, 16
    jal x1, expand_352
    loopi 67, 8
        bn.sid x8, 0(x22++)     # cache upper entry (low half)
        bn.sid x8++, 0(x5)
        bn.sid x8, 0(x22++)     # cache upper entry (high half)
        bn.sid x8++, 32(x5)
        bne x8, x9, skip_expandp1
        li x8, 0
        jal x1, expand_352
        skip_expandp1:
        addi x5, x5, 64

    # Start Multiply First Row with Matrix O
    li x19, 1
    li x28, 19
    li x29, 20

    jal x1, row_mul_O

    # --- Restore AES state after row_mul_O ---
    # row_mul_O clobbered w0..w20: w7/w8/w9 (AES consts), w17 (KS I/O),
    # w18 (IV), w19 (IV step), w20 (RK1 in FORWARD layout).
    # w11 (rcon) and w21..w29 (RK2..RK10) preserved.
    li x4, 8
    bn.lid x4, 0(x14)               # w8 = affine_value
    li x4, 9
    bn.lid x4, 0(x15)               # w9 = msb_mask
    li x4, 11
    bn.lid x4, 0(x16)               # w11 = rcon (reset to start of stream)
    bn.rshi w17, w31, w30 >> 128    # prime w17 = RK0 | 0
    jal x1, KeySchedule_sign        # w17 = RK1
    bn.mov w20, w17                 # w20 = RK1 (FORWARD)
    bn.or  w20, w20, w20 << 128
    bn.addi w19, w31, 2             # restore IV step
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    add x5, x0, x6                  # Reset x5 = P1+P1T base (x6 preserved across row_mul_O + restore)
    lw x11, 4(x7)                   # Reload O matrix addr from saved arg frame
    # Start Compute row1 of P1+p1T
    li x21, 66                      # Upper triangle row length
    li x27, 1                       # current row
    loopi 66, 76
        add x26, x0, x27            #index
        li x9, 67
        loop x27, 8
            slli x24, x26, 6        # q(k,r)*64 byte offset
            add x24, x18, x24       # cache addr of transpose entry P1[k][r]
            bn.lid x0, 0(x24)
            bn.sid x0, 0(x5++)
            bn.lid x0, 32(x24)
            bn.sid x0, 0(x5++)
            add x26, x26, x9
            addi x9, x9, -1
        bn.sid x31, 0(x5++)         #Skip diagonal
        bn.sid x31, 0(x5++)         #Skip diagonal
        # Inc 2: fill diag cache slot q(r,r) = raw P1[r][r] via partial_expandP1
        sub  x24, x22, x18      # q(r,r)*64
        srli x25, x24, 6        # q(r,r)
        andi x25, x25, 7        # col_index = q & 7
        srli x24, x24, 9        # col_arg = q >> 3
        addi x2, x2, -32
        bn.sid x31, 0(x2)       # zero arg slot (w31), then col_arg low
        sw x24, 0(x2)
        jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops arg slot
        slli x25, x25, 1        # WDR index = 2*col_index
        bn.sid x25, 0(x22++)    # cache diag low half
        addi x25, x25, 1
        bn.sid x25, 0(x22++)    # cache diag high half
        addi x2, x2, -32            # Upper Triangle Part
        bn.sid x31, 0(x2)
        sw x27, 0(x2)               #Pass current row index to wdr
        bn.lid x0, 0(x2)
        bn.addi w1, w0, 1
        bn.addi w2, w31, 68
        bn.mulqacc.wo.z w2, w0.0, w2.0, 0
        bn.mulqacc.wo.z w3, w0.0, w1.0, 0
        bn.rshi w3, w31, w3 >> 1
        bn.sub w0, w2, w3
        bn.add w0, w0, w1
        bn.sid x0, 0(x2)
        lw x20, 0(x2)               #index
        addi x2, x2, 32
        bn.rshi w18, w31, w0 >> 3   #calculate IV: row_idx * V - row_idx * (row_idx + 1) // 2 + col
        bn.addi w1, w31, 22         #col: always will be row + 1 because skip diagonal
        bn.mulqacc.wo.z w18, w18.0, w1.0, 0
        bn.addi w0, w18, 1
        bn.or w18, w18, w0 << 128
        bn.rshi w18, w18, w31 >> 160
        jal x1, expand_352
        andi x20, x20, 0x7          #Index % 8
        slli x20, x20, 1
        li x9, 16
        loop x21, 8
            bn.sid x20, 0(x22++)    # cache upper entry (low half)
            bn.sid x20++, 0(x5)
            bn.sid x20, 0(x22++)    # cache upper entry (high half)
            bn.sid x20++, 32(x5)
            bne x9, x20, skip_expandp1_mid
                jal x1, expand_352
                li x20, 0
            skip_expandp1_mid:  addi x5, x5, 64
        jal x1, row_mul_O
        # --- Restore AES state after row_mul_O ---
        li x4, 8
        bn.lid x4, 0(x14)
        li x4, 9
        bn.lid x4, 0(x15)
        li x4, 11
        bn.lid x4, 0(x16)
        bn.rshi w17, w31, w30 >> 128
        jal x1, KeySchedule_sign
        bn.mov w20, w17
        bn.or  w20, w20, w20 << 128
        bn.addi w19, w31, 2
        bn.or w19, w19, w19 << 128
        bn.rshi w19, w19, w31 >> 160
        add x5, x0, x6              # Reset x5 = P1+P1T base
        lw x11, 4(x7)
        addi x27, x27, 1
        addi x21, x21, -1

        li x27, 67                  #Last Row
        add x26, x0, x27            #index
        li x9, 67
        loop x27, 8
            slli x24, x26, 6        # q(k,r)*64 byte offset
            add x24, x18, x24       # cache addr of transpose entry P1[k][r]
            bn.lid x0, 0(x24)
            bn.sid x0, 0(x5++)
            bn.lid x0, 32(x24)
            bn.sid x0, 0(x5++)
            add x26, x26, x9
            addi x9, x9, -1
        bn.sid x31, 0(x5++)         #Skip diagonal
        bn.sid x31, 0(x5++)         #Skip diagonal
        # Inc 2: fill last diag cache slot q(67,67) = raw P1[67][67] via partial_expandP1
        sub  x24, x22, x18      # q(67,67)*64
        srli x25, x24, 6        # q(67,67)
        andi x25, x25, 7        # col_index = q & 7
        srli x24, x24, 9        # col_arg = q >> 3
        addi x2, x2, -32
        bn.sid x31, 0(x2)       # zero arg slot (w31), then col_arg low
        sw x24, 0(x2)
        jal x1, partial_expandP1   # entry -> w[2*ci]/w[2*ci+1]; pops arg slot
        slli x25, x25, 1        # WDR index = 2*col_index
        bn.sid x25, 0(x22++)    # cache diag low half
        addi x25, x25, 1
        bn.sid x25, 0(x22++)    # cache diag high half
        jal x1, row_mul_O
        # --- Restore AES state after row_mul_O ---
        li x4, 8
        bn.lid x4, 0(x14)
        li x4, 9
        bn.lid x4, 0(x15)
        li x4, 11
        bn.lid x4, 0(x16)
        bn.rshi w17, w31, w30 >> 128
        jal x1, KeySchedule_sign
        bn.mov w20, w17
        bn.or  w20, w20, w20 << 128
        bn.addi w19, w31, 2
        bn.or w19, w19, w19 << 128
        bn.rshi w19, w19, w31 >> 160
        add x5, x0, x6              # Reset x5 = P1+P1T base
        lw x11, 4(x7)
        lw x12, 8(x7)

        bn.addi w0, w31, 22
        bn.addi w1, w31, 293
        bn.mulqacc.wo.z w0, w0.0, w1.0, 0
        bn.addi w1, w0, 1
        bn.or w18, w0, w1 << 128
        bn.rshi w18, w18, w31 >> 160
        jal x1, expand_352
        li x8, 4
        li x9, 1
        li x28, 16
        li x29, 17
        loopi 34, 627
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w4
            bn.xor w17, w17, w5
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w6
            bn.xor w17, w17, w7
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w8
            bn.xor w17, w17, w9
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w10
            bn.xor w17, w17, w11
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w12
            bn.xor w17, w17, w13
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w14
            bn.xor w17, w17, w15
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            jal x1, expand_352
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.lid x28, 0(x12)
            bn.lid x29, 32(x12)
            bn.xor w16, w16, w2
            bn.xor w17, w17, w3
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64

    # Restore caller's x13..x16 (we clobbered them with AES-constant addresses)
    lw x13, 12(x7)
    lw x14, 16(x7)
    lw x15, 20(x7)
    lw x16, 24(x7)
    # Restore stack pointer before returning
    addi x2, x7, 32

    ret

#else

/* =============== sw (SW gf256 + AES via partial_expandP1_table) =============== */
gf256trimat_2trimat_madd_68_68_44_44:

    bn.xor w31, w31, w31

    li x7, 0x11b                    /* GF(256) reduction polynomial */
    csrrw x0, mod0, x7

    /* 224 B frame: 0..175 RK output, 176..191 pad, 192..223 saved args. */
    addi x2, x2, -224
    sw x10, 192(x2)
    sw x11, 196(x2)
    sw x12, 200(x2)
    sw x13, 204(x2)
    sw x14, 208(x2)
    sw x15, 212(x2)
    sw x16, 216(x2)

    /* Derive AES round keys into top of frame. AES_128_keyschedule:
     *   x10 = key input (= pk_seed ptr, already in x10 from caller)
     *   x11 = RK output base
     * Clobbers x5..x8, x12..x18, x29..x31. */
    add x11, x0, x2                 /* RK dst = x2 (offset 0) */
    jal x1, AES_128_keyschedule
    add x18, x0, x2                 /* x18 = RK base (survivor) */
    addi x7, x2, 192                /* x7 = saved-arg ptr */
    lw x11, 4(x7)                   /* restore x11 = O ptr */
    lw x12, 8(x7)                   /* restore x12 = result ptr */
    lw x17, 12(x7)                  /* x17 = P1 cache base (passed in x13; KS clobbered x17) */
    add x23, x0, x17                /* x23 = cache fill cursor (q-order) */

    /* Allocate 4352 B buffer for one row of P1+P1^T (68 * 64 bytes) */
    li x5, 4352
    sub x2, x2, x5

    /* AES setup (aestable native):
     *   x18 = rk-base survivor (preserved across row_mul_O / AES calls)
     *   x13 = LE counter (starts at 0; advanced by AES kernels) */
    li x13, 0

    /* P1+P1^T row base/cursor */
    add x5, x0, x2
    add x6, x0, x5

    /* ---- Generate row 0 of P1+P1^T ---- */
    li x31, 31
    bn.sid x31, 0(x5++)             /* row 0 diag region: zero 64 B */
    bn.sid x31, 0(x5++)
    /* Fill diag cache slot q(0,0) = raw P1[0][0] via partial_expandP1_table */
    sub  x24, x23, x17             /* q(r,r)*64 */
    srli x25, x24, 6              /* q(r,r) */
    andi x25, x25, 7             /* col_index = q & 7 */
    srli x24, x24, 9             /* col_arg = q >> 3 */
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x24, 0(x2)                /* pass col_arg via stack */
    jal x1, partial_expandP1_table
    slli x25, x25, 1            /* WDR index = 2*col_index */
    bn.sid x25, 0(x23++)        /* cache diag low half */
    addi x25, x25, 1
    bn.sid x25, 0(x23++)        /* cache diag high half */
    li x13, 0                   /* partial_expandP1_table mutated x13; reset LE counter */
    li x8, 2
    li x9, 16
    addi x10, x18, 0                /* x10 = rk base */
    jal x1, expand_352_table        /* x13: 0 -> 22 */
    loopi 67, 9
        bn.sid x8, 0(x23++)         /* cache upper entry (low half) */
        bn.sid x8++, 0(x5)
        bn.sid x8, 0(x23++)         /* cache upper entry (high half) */
        bn.sid x8++, 32(x5)
        bne x8, x9, skip_expandp1
        li x8, 0
        addi x10, x18, 0
        jal x1, expand_352_table
        skip_expandp1:
        addi x5, x5, 64

    /* ---- First row_mul_O ---- */
    li x19, 1
    li x28, 19
    li x29, 20

    jal x1, row_mul_O

    /* No AES state refresh — round_keys in DMEM, x13/x18 GPR-preserved. */
    add x5, x0, x6
    lw x11, 4(x7)

    /* ---- Outer loop: rows 1..66 ---- */
    li x21, 66                      /* upper-triangle row length */
    li x27, 1                       /* current row */
    loopi 66, 68
        add x26, x0, x27            /* Index = current_row */
        li x9, 67
        loop x27, 8
            slli x24, x26, 6        /* q(k,r)*64 byte offset */
            add x24, x17, x24       /* cache addr of transpose entry P1[k][r] */
            bn.lid x0, 0(x24)
            bn.sid x0, 0(x5++)
            bn.lid x0, 32(x24)
            bn.sid x0, 0(x5++)
            add x26, x26, x9
            addi x9, x9, -1
        bn.sid x31, 0(x5++)         /* skip diagonal: zero 64 B */
        bn.sid x31, 0(x5++)
        /* Fill diag cache slot q(r,r) = raw P1[r][r] via partial_expandP1_table */
        sub  x24, x23, x17
        srli x25, x24, 6
        andi x25, x25, 7
        srli x24, x24, 9
        addi x2, x2, -32
        bn.sid x31, 0(x2)
        sw x24, 0(x2)
        jal x1, partial_expandP1_table
        slli x25, x25, 1
        bn.sid x25, 0(x23++)        /* cache diag low half */
        addi x25, x25, 1
        bn.sid x25, 0(x23++)        /* cache diag high half */

        /* ---- Upper-triangle expand for current row ----
         * Compute Index = row_idx*68 - row_idx*(row_idx+1)/2 + (row_idx+1).
         * counter = (Index >> 3) * 22 = col_arg * 22.
         * Math in WDRs (cheap for *68 + /2); extract values to x20/x13. */
        addi x2, x2, -32
        bn.sid x31, 0(x2)
        sw x27, 0(x2)
        bn.lid x0, 0(x2)            /* w0 = row_idx */
        bn.addi w1, w0, 1
        bn.addi w2, w31, 68
        bn.mulqacc.wo.z w2, w0.0, w2.0, 0      /* w2 = row_idx * 68 */
        bn.mulqacc.wo.z w3, w0.0, w1.0, 0      /* w3 = row_idx*(row_idx+1) */
        bn.rshi w3, w31, w3 >> 1                /* w3 /= 2 */
        bn.sub w0, w2, w3
        bn.add w0, w0, w1                       /* w0 = Index */
        bn.sid x0, 0(x2)            /* spill w0 (Index) */
        lw x20, 0(x2)               /* x20 = Index (low 32) — used for col_index */
        bn.rshi w18, w31, w0 >> 3   /* w18 = Index // 8 = col_arg */
        bn.addi w1, w31, 22
        bn.mulqacc.wo.z w18, w18.0, w1.0, 0    /* w18 = col_arg * 22 = counter */
        li x4, 18
        bn.sid x4, 0(x2)            /* spill w18 (counter) — overwrites Index slot, x20 already cached */
        lw x13, 0(x2)               /* x13 = LE counter for next expand_352_table */
        addi x2, x2, 32

        addi x10, x18, 0            /* x10 = rk base */
        jal x1, expand_352_table

        andi x20, x20, 0x7          /* x20 = Index % 8 = starting col_index */
        slli x20, x20, 1
        li x9, 16
        loop x21, 9
            bn.sid x20, 0(x23++)    /* cache upper entry (low half) */
            bn.sid x20++, 0(x5)
            bn.sid x20, 0(x23++)    /* cache upper entry (high half) */
            bn.sid x20++, 32(x5)
            bne x9, x20, skip_expandp1_mid
                addi x10, x18, 0
                jal x1, expand_352_table
                li x20, 0
            skip_expandp1_mid:  addi x5, x5, 64

        /* AES clobbers x19, x29 (and partial_expandP1_table clobbers x28 via
         * aes128_dualblock); re-set WDR-index regs before row_mul_O. */
        li x19, 1
        li x28, 19
        li x29, 20
        jal x1, row_mul_O
        /* round_keys in DMEM survives row_mul_O — no AES state refresh */
        add x5, x0, x6
        lw x11, 4(x7)
        addi x27, x27, 1
        addi x21, x21, -1

    /* ---- Last row (row 67) ---- */
    li x27, 67
    add x26, x0, x27
    li x9, 67
    loop x27, 8
        slli x24, x26, 6           /* q(k,r)*64 byte offset */
        add x24, x17, x24          /* cache addr of transpose entry P1[k][67] */
        bn.lid x0, 0(x24)
        bn.sid x0, 0(x5++)
        bn.lid x0, 32(x24)
        bn.sid x0, 0(x5++)
        add x26, x26, x9
        addi x9, x9, -1
    bn.sid x31, 0(x5++)             /* skip diagonal */
    bn.sid x31, 0(x5++)
    /* Fill last diag cache slot q(67,67) = raw P1[67][67] via partial_expandP1_table */
    sub  x24, x23, x17
    srli x25, x24, 6
    andi x25, x25, 7
    srli x24, x24, 9
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x24, 0(x2)
    jal x1, partial_expandP1_table
    slli x25, x25, 1
    bn.sid x25, 0(x23++)
    addi x25, x25, 1
    bn.sid x25, 0(x23++)
    /* AES-clobber recovery (see outer loop comment) */
    li x19, 1
    li x28, 19
    li x29, 20
    jal x1, row_mul_O
    add x5, x0, x6
    lw x11, 4(x7)
    lw x12, 8(x7)

    /* ---- P2 expansion ----
     * P2 starts at AES counter = 22 * 293 (per bngfonly math). */
    addi x2, x2, -32
    bn.addi w0, w31, 22
    bn.addi w1, w31, 293
    bn.mulqacc.wo.z w0, w0.0, w1.0, 0       /* w0 = 22 * 293 */
    li x4, 0
    bn.sid x4, 0(x2)
    lw x13, 0(x2)                            /* x13 = P2 starting counter */
    addi x2, x2, 32
    addi x10, x18, 0
    jal x1, expand_352_table

    li x8, 4
    li x9, 1
    li x28, 16
    li x29, 17
    loopi 68, 15
        loopi 44, 13
            bn.lid x28, 0(x12)              /* w16 = result row low 32B */
            bn.lid x29, 32(x12)             /* w17 = result row high 32B */
            bn.movr x0, x8++                /* move col data into w0/w1 */
            bn.movr x9, x8++
            bn.xor w16, w16, w0
            bn.xor w17, w17, w1
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            bne x8, x28, skip_expandp2
                li x8, 0
                addi x10, x18, 0
                jal x1, expand_352_table
            skip_expandp2: addi x12, x12, 64
        NOP

    /* Restore caller's x13..x16 (orchestrator depends on these) */
    lw x13, 12(x7)
    lw x14, 16(x7)
    lw x15, 20(x7)
    lw x16, 24(x7)
    addi x2, x7, 32

    ret

#endif

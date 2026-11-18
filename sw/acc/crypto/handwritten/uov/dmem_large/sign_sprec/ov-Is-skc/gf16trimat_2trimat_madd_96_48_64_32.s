/* gf16trimat_2trimat_madd_96_48_64_32 (Is) - orchestrator for P1+P1T mat-mat-add.
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW gf16 + AES_128_keyschedule + aes128_dual_table
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.4 + jal aes128_sign
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.4 + inline bn.aes128.*
 */

.global gf16trimat_2trimat_madd_96_48_64_32

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* =============== bngfaes (HW bn.gfmul.4 + inline bn.aes128.*) =============== */
.section .text
.balign 4
gf16trimat_2trimat_madd_96_48_64_32:
    bn.xor w31, w31, w31
    bn.xor w0, w0, w0
    addi x2, x2, -32 
    #x8 point at the argument in stack
    add x8, x0, x2

    sw x10, 0(x8)    #copy of AES128 Key address
    sw x11, 4(x8)    #copy of O starting Address
    sw x12, 8(x8)    #copy of Result starting Address

    #allocate 3072 byte for in stack P1_P1T
    li x9, 3072
    sub x9, x2, x9
    #Store x9 (P1+P1T stack address to x2/x8 + 12)
    sw x9, 12(x8)
    add x2, x0, x9

    li x31, 30
    bn.lid x31, 0(x10) 
    bn.or w30, w30, w30 << 128
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

    add x6, x0, x13                 # x6 = P1 cache fill cursor (base = caller arg x13)
    #First Row
    li x31, 31
    li x30, 2
    bn.sid x31, 0(x9++) # First Row first element is zero
    bn.addi w0, w0, 1
    bn.rshi w0, w0, w31 >> 32
    /* cache raw P1[0][0] diagonal (counter still (0,1)); S buffer keeps 0 */
    bn.aes128.encz.swap w2, w0, w30
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
    bn.sid x30, 0(x6++)
    bn.or w1, w0, w0 >> 128
    bn.add w1, w1, w1
    bn.add w0, w0, w1 #Skip diagonal
    
    loopi 95, 14
        bn.aes128.encz.swap w2, w0, w30
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
        bn.sid x30, 0(x9++)
        bn.sid x30, 0(x6++)
        bn.add w0, w0, w1

    #reduction polynomial into mod0
    li x28, 0x13
    csrrw x0, mod0, x28 
    li x29, 3
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 7
    li x30, 8
    loopi 32, 34
        lw x9, 12(x8)   #load P1_P1T address 
        bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
        bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
        bn.lid x27, 0(x11++) #w5: col_i+1
        bn.wsrw acc, w31
        csrrw x0, mod1, x0   
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w3
            bn.gfmul.4.acc.inc w8, w7, w3
        csrrw x0, mod1, x0
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w4
            bn.gfmul.4.acc.inc w8, w7, w4
        bn.sid x30, 0(x12++)
        bn.wsrw acc, w31
        li x9, 32
        csrrw x0, mod1, x9          /* x9=32, start at nibble 32 */
        lw x9, 12(x8)
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w4
            bn.gfmul.4.acc.inc w8, w7, w4
        csrrw x0, mod1, x0
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w8, w6, w5
            bn.gfmul.4.acc.inc w8, w7, w5
        bn.sid x30, 0(x12++)
        csrrw x0, mod1, x0
        lw x11, 4(x8)    #Reset O Address, x12 already pointing at resut next row
        lw x9, 12(x8)   #Reset P1+P1T address
        li x24, 1 # current row
        li x23, 2
        li x22, 94
        loopi 94, 77             # body=77: li x7,3040 is 2 words (lui+addi)
            /* lower-tri (transpose): read cached P1[k][r] = cache[q(k,r)]
             * instead of re-AES. x4 = cache + 32*r (k=0); stride 32*(95-k). */
            slli x5, x24, 5
            add x4, x13, x5
            li x7, 3040
            loop x24, 4
                bn.lid x29, 0(x4)
                bn.sid x29, 0(x9++)
                add x4, x4, x7
                addi x7, x7, -32
            bn.sid x31, 0(x9++) # Skip diagonal (S buffer = 0)
            /* cache raw P1[r][r] diagonal (counter at (2q,2q+1)); buffer keeps 0 */
            bn.aes128.encz.swap w2, w0, w30
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
            bn.sid x23, 0(x6++)
            bn.add w0, w0, w1   # Skip diagonal
            loop x22, 14
                bn.aes128.encz.swap w2, w0, w30
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
                bn.sid x23, 0(x9++)
                bn.sid x23, 0(x6++)
                bn.add w0, w0, w1
            loopi 32, 34        # Multiply with Matrix O
                lw x9, 12(x8)   #load P1_P1T address
                bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
                bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
                bn.lid x27, 0(x11++) #w5: col_i+1
                bn.wsrw acc, w31
                csrrw x0, mod1, x0
                loopi 32, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w8, w6, w3
                    bn.gfmul.4.acc.inc w8, w7, w3
                csrrw x0, mod1, x0
                loopi 16, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w8, w6, w4
                    bn.gfmul.4.acc.inc w8, w7, w4
                bn.sid x30, 0(x12++)
                bn.wsrw acc, w31
                li x9, 32
                csrrw x0, mod1, x9
                lw x9, 12(x8)
                loopi 16, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w8, w6, w4
                    bn.gfmul.4.acc.inc w8, w7, w4
                csrrw x0, mod1, x0
                loopi 32, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w8, w6, w5
                    bn.gfmul.4.acc.inc w8, w7, w5
                bn.sid x30, 0(x12++)
            lw x11, 4(x8)    #Reset O Address, x12 already pointing at resut next row
            lw x9, 12(x8)   #Reset P1+P1T address
            addi x24, x24, 1
            addi x22, x22, -1
        #Last Row
        /* last-row lower-tri (transpose) from cache: P1[k][95] = cache[q(k,95)]. */
        slli x5, x24, 5
        add x4, x13, x5
        li x7, 3040
        loop x24, 4
            bn.lid x29, 0(x4)
            bn.sid x29, 0(x9++)
            add x4, x4, x7
            addi x7, x7, -32
        bn.sid x31, 0(x9++) # Skip diagonal (S buffer = 0)
        /* cache raw P1[95][95] diagonal (counter at (2q,2q+1)); buffer keeps 0.
         * w0 untouched -> P2 IV stream below is unchanged. */
        bn.aes128.encz.swap w2, w0, w30
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
        bn.sid x23, 0(x6++)
        bn.add w0, w0, w1   # Skip diagonal
        loopi 32, 34
            lw x9, 12(x8)   #load P1_P1T address
            bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
            bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
            bn.lid x27, 0(x11++) #w5: col_i+1
            bn.wsrw acc, w31
            csrrw x0, mod1, x0
            loopi 32, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w8, w6, w3
                bn.gfmul.4.acc.inc w8, w7, w3
            csrrw x0, mod1, x0
            loopi 16, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w8, w6, w4
                bn.gfmul.4.acc.inc w8, w7, w4
            bn.sid x30, 0(x12++)
            bn.wsrw acc, w31
            li x9, 32
            csrrw x0, mod1, x9
            lw x9, 12(x8)
            loopi 16, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w8, w6, w4
                bn.gfmul.4.acc.inc w8, w7, w4
            csrrw x0, mod1, x0
            loopi 32, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w8, w6, w5
                bn.gfmul.4.acc.inc w8, w7, w5
            bn.sid x30, 0(x12++)
        
        lw x12, 8(x8)

        loopi 96, 17
            loopi 64, 15
                bn.lid x26, 0(x12)         #load result into w6 to add P2
                bn.aes128.encz.swap w3, w0, w30
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
                bn.xor w6, w6, w3
                bn.add w0, w0, w1           #IV increment
                bn.sid x26, 0(x12++)         #stored added result back to original address
            nop

        addi x2, x8, 32

        csrrw x0, mod1, x0   # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
    ret
#elif defined(GF_INSTRUCTIONS)

/* =============== bngfonly (HW bn.gfmul.4 + aes128_sign) =============== */
.section .text
.balign 4
gf16trimat_2trimat_madd_96_48_64_32:
    bn.xor w31, w31, w31
    bn.xor w0, w0, w0
    addi x2, x2, -32 
    #x8 point at the argument in stack
    add x8, x0, x2

    sw x10, 0(x8)    #copy of AES128 Key address
    sw x11, 4(x8)    #copy of O starting Address
    sw x12, 8(x8)    #copy of Result starting Address

    #allocate 3072 byte for in stack P1_P1T
    li x9, 3072
    sub x9, x2, x9
    #Store x9 (P1+P1T stack address to x2/x8 + 12)
    sw x9, 12(x8)
    add x2, x0, x9

    /* ---- bngfonly: pre-load SW-AES constants + SW key schedule ---- */
    /* Pre-load AES consts BEFORE loading key (we need x5, x6 as scratch) */
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)
    la x5, rcon
    li x6, 11
    bn.lid x6, 0(x5)

    li x31, 30
    bn.lid x31, 0(x10)

    /* Prime w17 (KS I/O) BEFORE dual-storing w30 KS reads w17 bits 96..255
       so its high half must be zero. */
    bn.mov w17, w30
    bn.or w30, w30, w30 << 128

    /* 10 SW key schedule calls produce RK1..RK10 in w20..w29 (forward layout),
       each dual-stored. */
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

    /* Re-load byte_swap_mask into w7 (KS clobbered it as scratch) */
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)

    add x6, x0, x13                 # x6 = P1 cache fill cursor (preserved across aes128_sign)
    #First Row
    li x31, 31
    li x30, 2
    bn.sid x31, 0(x9++) # First Row first element is zero
    bn.addi w0, w0, 1
    bn.rshi w0, w0, w31 >> 32
    /* cache raw P1[0][0] diagonal (counter (0,1)); S buffer keeps 0 */
    bn.mov w18, w0
    jal x1, aes128_sign
    bn.sid x30, 0(x6++)
    bn.or w19, w0, w0 >> 128   /* IV increment; aes128_sign clobbers w1 */
    bn.add w19, w19, w19
    bn.add w0, w0, w19 #Skip diagonal
    
    loopi 95, 5
        bn.mov w18, w0                 /* IV input to aes128_sign */
        jal x1, aes128_sign            /* output in w2 */
        bn.sid x30, 0(x9++)
        bn.sid x30, 0(x6++)
        bn.add w0, w0, w19

    #reduction polynomial into mod0; x21 stays resident (aes128_sign leaves 0x11B)
    li x21, 0x13
    csrrw x0, mod0, x21
    li x29, 3
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 17        /* WDR index 17; w7 reserved as byte_swap_mask for aes128_sign */
    li x30, 1         /* WDR index 1; w8 reserved as affine_value for aes128_sign */
    loopi 32, 35
        lw x9, 12(x8)   #load P1_P1T address
        bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
        bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
        bn.lid x27, 0(x11++) #w5: col_i+1
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        bn.gfmul.4.acc.z.inc w1, w6, w3
        bn.gfmul.4.acc.inc w1, w17, w3
        loopi 31, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w3
            bn.gfmul.4.acc.inc w1, w17, w3
        loopi 16, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w4
            bn.gfmul.4.acc.inc w1, w17, w4
        bn.sid x30, 0(x12++)
        lw x9, 12(x8)
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        bn.gfmul.4.acc.z.inc w1, w6, w4
        bn.gfmul.4.acc.inc w1, w17, w4
        loopi 15, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w4
            bn.gfmul.4.acc.inc w1, w17, w4
        loopi 32, 4
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.inc w1, w6, w5
            bn.gfmul.4.acc.inc w1, w17, w5
        bn.sid x30, 0(x12++)
        lw x11, 4(x8)    #Reset O Address, x12 already pointing at resut next row
        lw x9, 12(x8)   #Reset P1+P1T address
        li x24, 1 # current row
        li x23, 2
        li x22, 94
        loopi 94, 61             # body=61: li x7,3040 is 2 words (lui+addi); +1 mod0 restore
            /* lower-tri (transpose): read cached P1[k][r] = cache[q(k,r)]
             * instead of re-AES. x4 = cache + 32*r (k=0); stride 32*(95-k). */
            slli x5, x24, 5
            add x4, x13, x5
            li x7, 3040
            loop x24, 4
                bn.lid x29, 0(x4)
                bn.sid x29, 0(x9++)
                add x4, x4, x7
                addi x7, x7, -32
            bn.sid x31, 0(x9++) # Skip diagonal (S buffer = 0)
            /* cache raw P1[r][r] diagonal (counter (2q,2q+1)); buffer keeps 0 */
            bn.mov w18, w0
            jal x1, aes128_sign
            bn.sid x23, 0(x6++)
            bn.add w0, w0, w19   # Skip diagonal
            loop x22, 5
                bn.mov w18, w0
                jal x1, aes128_sign            /* output in w2 */
                bn.sid x23, 0(x9++)
                bn.sid x23, 0(x6++)
                bn.add w0, w0, w19
            csrrw x0, mod0, x21                /* AES cluster done -> GF(16) */
            loopi 32, 35        # Multiply with Matrix O
                lw x9, 12(x8)   #load P1_P1T address
                bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
                bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
                bn.lid x27, 0(x11++) #w5: col_i+1
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.z.inc w1, w6, w3
                bn.gfmul.4.acc.inc w1, w17, w3
                loopi 31, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w1, w6, w3
                    bn.gfmul.4.acc.inc w1, w17, w3
                loopi 16, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w1, w6, w4
                    bn.gfmul.4.acc.inc w1, w17, w4
                bn.sid x30, 0(x12++)
                lw x9, 12(x8)
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.z.inc w1, w6, w4
                bn.gfmul.4.acc.inc w1, w17, w4
                loopi 15, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w1, w6, w4
                    bn.gfmul.4.acc.inc w1, w17, w4
                loopi 32, 4
                    bn.lid x26, 0(x9++)
                    bn.lid x25, 0(x9++)
                    bn.gfmul.4.acc.inc w1, w6, w5
                    bn.gfmul.4.acc.inc w1, w17, w5
                bn.sid x30, 0(x12++)
            lw x11, 4(x8)    #Reset O Address, x12 already pointing at resut next row
            lw x9, 12(x8)   #Reset P1+P1T address
            addi x24, x24, 1
            addi x22, x22, -1
        #Last Row
        /* last-row lower-tri (transpose) from cache: P1[k][95] = cache[q(k,95)]. */
        slli x5, x24, 5
        add x4, x13, x5
        li x7, 3040
        loop x24, 4
            bn.lid x29, 0(x4)
            bn.sid x29, 0(x9++)
            add x4, x4, x7
            addi x7, x7, -32
        bn.sid x31, 0(x9++) # Skip diagonal (S buffer = 0)
        /* cache raw P1[95][95] diagonal; w0 untouched -> P2 IV stream unchanged */
        bn.mov w18, w0
        jal x1, aes128_sign
        bn.sid x23, 0(x6++)
        bn.add w0, w0, w19   # Skip diagonal
        csrrw x0, mod0, x21  # AES done -> GF(16)
        loopi 32, 35
            lw x9, 12(x8)   #load P1_P1T address
            bn.lid x29, 0(x11++) #load Matrix O 2 col 96 bytes; w3: col_i
            bn.lid x28, 0(x11++) #w4: col_i+1 || col_i
            bn.lid x27, 0(x11++) #w5: col_i+1
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.z.inc w1, w6, w3
            bn.gfmul.4.acc.inc w1, w17, w3
            loopi 31, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w1, w6, w3
                bn.gfmul.4.acc.inc w1, w17, w3
            loopi 16, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w1, w6, w4
                bn.gfmul.4.acc.inc w1, w17, w4
            bn.sid x30, 0(x12++)
            lw x9, 12(x8)
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.gfmul.4.acc.z.inc w1, w6, w4
            bn.gfmul.4.acc.inc w1, w17, w4
            loopi 15, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w1, w6, w4
                bn.gfmul.4.acc.inc w1, w17, w4
            loopi 32, 4
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.gfmul.4.acc.inc w1, w6, w5
                bn.gfmul.4.acc.inc w1, w17, w5
            bn.sid x30, 0(x12++)
        
        lw x12, 8(x8)

        loopi 96, 9
            loopi 64, 7
                bn.lid x26, 0(x12)         #load result into w6 to add P2
                bn.mov w18, w0                /* IV input */
                jal x1, aes128_sign            /* output in w2 */
                bn.mov w3, w2                  /* kernel expects output in w3 */
                bn.xor w6, w6, w3
                bn.add w0, w0, w19           #IV increment
                bn.sid x26, 0(x12++)         #stored added result back to original address
            nop

        addi x2, x8, 32

        csrrw x0, mod0, x21  # exit contract: leave mod0 = 0x13 (GF(16))
        csrrw x0, mod1, x0   # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
    ret
#else

/* =============== sw (SW gf16 + AES_128_keyschedule + aes128_dual_table) =============== */
/*
 * gf16trimat_2trimat_madd_96_48_64_32_sw — sw.
 *
 * No bn.gfmul.4/8. No bn.aes128.*.
 * AES uses AES_128_keyschedule + aes128_dual_table T-table helpers.
 * GF16 multiply uses gf16_macc_sw (clobbers w0, w18, w19, w20).
 *
 * Entry x2 = stack_end. Frame:
 *   stack_end - 32   .. stack_end       : x8 save area
 *     0(x8)=caller x10, 4=x11, 8=x12, 12=P1+P1^T base, 16=mid-call x12, 20=caller x3
 *   stack_end - 224  .. stack_end - 32  : 192 B AES round key region (176 B keys + pad), x18 base
 *   stack_end - 3296 .. stack_end - 224 : 3072 B P1+P1^T scratch (x9)
 *
 * w16 = gf16 msb_mask 0x88..88. Built once, live whole kernel.
 * x3 = x8 mirror (x8 reload across wrapper clobbers).
 * AES_128_keyschedule clobbers x5..x8,x12..x18,x29..x31; kernel rederives x18 after KS.
 * aes128_dual_table: w18=IV, w2=CT out. Preserve x1..x4,x9,x17,x18,x23..x28,x30.
 *   Clobber x5..x8,x10..x16,x19..x22,x29,x31. Trimat uses x17 for WDR-3 ptr,
 *   x4 for WDR-31 ptr, reloads x11 from 4(x8), saves x12 to 16(x8) around calls.
 */
.section .text
.balign 4
gf16trimat_2trimat_madd_96_48_64_32:
    bn.xor w31, w31, w31
    bn.xor w0, w0, w0

    /* Allocate 32 B arg-save frame. RK slot lives between args and P1_P1T
     * (allocated below; x18 set after KS). */
    addi x2, x2, -32
    add x8, x0, x2

    sw x10, 0(x8)    /* save caller x10 = pk_seed ptr */
    sw x11, 4(x8)    /* save caller x11 = O ptr */
    sw x12, 8(x8)    /* save caller x12 = result ptr */
    sw x3,  20(x8)   /* save caller x3 — we use x3 as x8 mirror below */
    /* P1 cache homing (x13 = cache base from orchestrator; KS clobbers x13).
     * 24(x8)=write cursor (q-order fill), 28(x8)=base (lower-tri reads).
     * Both accessed via x3 (= x8 mirror) which survives every wrapper call. */
    sw x13, 24(x8)   /* cache write cursor = base initially */
    sw x13, 28(x8)   /* cache base (immutable) */

    /* Allocate 192 B for round keys + 3072 B for P1+P1^T scratch. */
    li x9, 3264                  /* 192 + 3072 */
    sub x9, x2, x9
    sw x9, 12(x8)                /* save P1+P1^T base */
    add x2, x0, x9               /* x2 = P1+P1^T base */

    /* x18 = round-key base (= x8 - 192). */
    addi x18, x8, -192

    /* Build msb_mask in w16 once. Stays valid across the kernel since
     * aes128_dual_table is GPR-only. */
    bn.addi w16, w31, 0x88
    bn.rshi w15, w16, w31 >> 248
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 240
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 224
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 192
    bn.or   w16, w16, w15
    bn.rshi w15, w16, w31 >> 128
    bn.or   w16, w16, w15

    /* AES key schedule via T-table.
     *   AES_128_keyschedule: x10 = pk_seed ptr (16 B preserved), x11 = rk dest
     *   (advanced by KS by 160 B). Clobbers x5..x8, x12..x18, x29..x31.
     *
     * x3 = permanent x8 (frame ptr) mirror. KS doesn't touch x3 (not in
     * clobber list); AES_128_encrypt doesn't either. So x3 holds the frame
     * ptr across the entire kernel, and we restore x8 from x3 after every
     * wrapper-call region (where the wrapper clobbers x5..x8).
     */
    addi x3, x8, 0
    addi x11, x18, 0
    jal x1, AES_128_keyschedule
    addi x8, x3, 0               /* restore x8 = frame base after KS */

    /* Re-set GPRs from saved copies (KS clobbers x11, x12, x18). */
    lw x11, 4(x8)
    lw x12, 8(x8)
    lw x9,  12(x8)               /* x9 = P1+P1^T base */
    addi x18, x8, -192           /* x18 = rk base (re-derive after KS clobber) */

    /* IV state setup — matches bngfonly counter format:
     *   w0 = dual-block IV (LE counters at bytes 12 and 28).
     *   w19 = +2 increment (at bytes 12 and 28).
     * Initial w0 counter = 1 (bit 224), then add w19 to skip diagonal of (0,0)
     * → final (2 at byte 12 = block1 counter 2, 3 at byte 28 = block2 counter 3).
     */
    bn.addi w0, w0, 1
    bn.rshi w0, w0, w31 >> 32           /* w0 = (0,0) diagonal counter (bit 224) */

    /* First row: 95 elements via dual-block AES + 1 diagonal-zero placeholder.
     * WDR-31 carrier in x4 (preserved by wrapper); WDR-2 carrier in x30 temp. */
    li x4, 31                           /* WDR-31 ptr — preserved across wrapper */
    li x30, 2
    bn.sid x4, 0(x9++)                  /* S buffer: diagonal (0,0) = 0 */

    /* gen + cache raw P1[0][0] diagonal at its counter (S buffer keeps 0).
     * x26 = cache cursor (preserved by aes128_dual_table); freed before P3. */
    lw x26, 24(x3)                      /* x26 = cache write cursor */
    bn.mov w18, w0
    jal x1, aes128_dual_table
    bn.sid x30, 0(x26)                  /* cache raw P1[0][0] */
    addi x26, x26, 32
    bn.or w19, w0, w0 >> 128            /* +2 increment (byte 12 | byte 28) */
    bn.add w19, w19, w19
    bn.add w0, w0, w19                  /* skip diagonal of (0,0) */

    loopi 95, 6
        bn.mov w18, w0                  /* IV input to aes128_dual_table */
        jal x1, aes128_dual_table       /* w2 = 32 B CT (dual block) */
        bn.sid x30, 0(x9++)             /* S buffer: store w2 (P1+P1^T element) */
        bn.sid x30, 0(x26)             /* cache raw P1 upper entry */
        addi x26, x26, 32
        bn.add w0, w0, w19              /* advance IV by +2 (dual-block step) */
    sw x26, 24(x3)                      /* save cache cursor after first row */

    addi x8, x3, 0                       /* restore x8 from x3 (wrapper clobbered it) */
    lw x11, 4(x8)                        /* restore x11 (wrapper clobbered) */
    lw x12, 8(x8)                        /* restore x12 (wrapper clobbered) */

    li x28, 0x13
    csrrw x0, mod0, x28
    li x17, 3                            /* WDR-3 ptr — preserved across wrapper */
    li x28, 4
    li x27, 5
    li x26, 6
    li x25, 17
    li x30, 1

    /* Save AES IV state (w0) + +2 increment (w19) to w7/w8 before GF-mul
     * phase. SW gfmul helper destroys w0 (vec arg) and w19 (scalar arg, shifted).
     * Restore after first loopi 32 finishes (before loopi 94, which needs
     * w0+w19 for upper-tri AES calls and for P2 add later). */
    bn.mov w7, w0                        /* save w0 */
    bn.mov w8, w19                       /* save w19 */

    /* ------- First col_pair of (P1+P1^T)*O+P2 (row 0) — gfmul-only, no AES inside. ------- */
    loopi 32, 74
        lw x9, 12(x8)
        bn.lid x17, 0(x11++)
        bn.lid x28, 0(x11++)
        bn.lid x27, 0(x11++)
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        bn.mov w19, w3                  /* prime w19 = w3 (R1 scalar) */
        /* R1 peel 1 (.acc.z): w1 = w6 * w3[nib0]. */
        bn.mov w0, w6
        bn.xor w20, w20, w20
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        /* R1 peel 2: w1 += w17 * w3[nib1]. */
        bn.mov w0, w17
        bn.mov w20, w1
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        loopi 31, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w4                  /* prime w19 = w4 (R2 scalar) */
        loopi 16, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sid x30, 0(x12++)            /* store col_i result */
        lw x9, 12(x8)
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        /* R3 peel 1 (.acc.z, w4 high half = col_i+1 low half; w19 auto-advance
         * from loopi 16 ended at w4 nib 32). */
        bn.mov w0, w6
        bn.xor w20, w20, w20
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        bn.mov w0, w17
        bn.mov w20, w1
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        loopi 15, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w5                  /* prime w19 = w5 (R4 scalar) */
        loopi 32, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sid x30, 0(x12++)            /* store col_i+1 result */

    /* Restore w0 (AES IV) + w19 (+2 incr) — helper destroyed them inside loopi 32. */
    bn.mov w0, w7
    bn.mov w19, w8

    lw x11, 4(x8)                       /* reset O cursor */
    lw x9,  12(x8)                      /* reset P1+P1^T cursor */
    li x24, 1                           /* current row index */
    li x23, 2

    /* ------- Main rows loop — rows 1..94. ------- */
    /* body 118: lower-tri −3 (cache reads), diagonal +5 (gen+cache), upper +4. */
    loopi 94, 118
        sw x12, 16(x8)                  /* save x12 (wrapper clobbers it) */
        bn.addi w6, w31, 95             /* loop x24 counter (decreases per iter) */
        addi x2, x2, -32
        bn.sid x4, 0(x2)
        sw x24, 0(x2)
        bn.lid x23, 0(x2++)             /* w2 = row index in bytes 0..3, rest 0 */
        /* Lower-tri (cols 0..K-1): re-encrypt entries (k, K) at counters
         * matching row k's original generation of (k, K).  */
        /* lower-tri (transpose): read cached P1[k][r] = cache[q(k,r)] instead
         * of re-AES. x5 = cache + 32*r (k=0); stride 32*(95-k), decreasing. */
        lw x5, 28(x3)                   /* x5 = cache base */
        slli x6, x24, 5                 /* x6 = 32*r */
        add x5, x5, x6                  /* x5 = &cache[q(0,r)] = P1[0][r] */
        li x7, 3040                     /* stride = 32*95 (2 words) */
        loop x24, 4
            bn.lid x17, 0(x5)           /* w3 = cached P1[k][r] (x17 = WDR-3) */
            bn.sid x17, 0(x9++)         /* store to P1+P1^T buffer */
            add x5, x5, x7
            addi x7, x7, -32
        bn.sid x4, 0(x9++)             /* S buffer: diagonal = 0 */
        /* gen + cache raw P1[r][r] diagonal at counter w0 (S buffer keeps 0) */
        lw x26, 24(x3)                  /* x26 = cache cursor */
        bn.mov w18, w0
        jal x1, aes128_dual_table
        bn.sid x23, 0(x26)            /* cache diagonal (x23 = WDR-2) */
        addi x26, x26, 32
        bn.add w0, w0, w19              /* skip diagonal counter */
        /* Upper-tri (cols K+1..95): generate + cache entries (K, j), j > K.
         * Iter count = 95 - x24 (row idx). Use x5 as throwaway (AES-clobbered). */
        addi x5, x0, 95
        sub  x5, x5, x24
        loop x5, 6
            bn.mov w18, w0
            jal x1, aes128_dual_table
            bn.sid x23, 0(x9++)         /* S buffer upper entry */
            bn.sid x23, 0(x26)         /* cache upper entry */
            addi x26, x26, 32
            bn.add w0, w0, w19
        sw x26, 24(x3)                  /* save cache cursor */
        li x26, 6                       /* restore WDR-6 index for P3 */
        addi x8, x3, 0                  /* restore x8 (wrapper clobbered it) */
        bn.mov w7, w0                   /* save AES IV state before GF-mul phase */
        bn.mov w8, w19                  /* save +2 increment */
        /* Restore x11 (O cursor) and x12 (result cursor) before loopi 32. */
        lw x11, 4(x8)
        lw x12, 16(x8)
        /* Inner P3 calc for row K (32 outer col pairs of O). */
        loopi 32, 74
            lw x9, 12(x8)
            bn.lid x17, 0(x11++)
            bn.lid x28, 0(x11++)
            bn.lid x27, 0(x11++)
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w19, w3
            bn.mov w0, w6
            bn.xor w20, w20, w20
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            loopi 31, 10
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.mov w0, w6
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
                bn.mov w0, w17
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
            bn.mov w19, w4
            loopi 16, 10
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.mov w0, w6
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
                bn.mov w0, w17
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
            bn.sid x30, 0(x12++)
            lw x9, 12(x8)
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.xor w20, w20, w20
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            loopi 15, 10
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.mov w0, w6
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
                bn.mov w0, w17
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
            bn.mov w19, w5
            loopi 32, 10
                bn.lid x26, 0(x9++)
                bn.lid x25, 0(x9++)
                bn.mov w0, w6
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
                bn.mov w0, w17
                bn.mov w20, w1
                jal x1, gf16_macc_sw
                bn.mov w1, w20
            bn.sid x30, 0(x12++)
        bn.mov w0, w7                   /* restore AES IV state (helper destroyed it) */
        bn.mov w19, w8                  /* restore +2 increment */
        lw x9,  12(x8)
        addi x24, x24, 1

    /* ------- Last row (row 95) gen + P3. ------- */
    sw x12, 16(x8)                       /* save x12 (wrapper clobbers it) */
    bn.addi w6, w31, 95
    addi x2, x2, -32
    bn.sid x4, 0(x2)
    sw x24, 0(x2)
    bn.lid x23, 0(x2++)
    /* last-row lower-tri (transpose): read cached P1[k][95] = cache[q(k,95)]. */
    lw x5, 28(x3)                      /* x5 = cache base */
    slli x6, x24, 5                    /* x6 = 32*95 */
    add x5, x5, x6                     /* x5 = &cache[q(0,95)] = P1[0][95] */
    li x7, 3040                        /* stride = 32*95 (2 words) */
    loop x24, 4
        bn.lid x17, 0(x5)             /* w3 = cached P1[k][95] (x17 = WDR-3) */
        bn.sid x17, 0(x9++)           /* store to P1+P1^T buffer */
        add x5, x5, x7
        addi x7, x7, -32
    bn.sid x4, 0(x9++)                 /* S buffer: diagonal = 0 */
    /* gen + cache raw P1[95][95] diagonal; w0 untouched -> P2 stream unchanged */
    lw x26, 24(x3)                     /* x26 = cache cursor */
    bn.mov w18, w0
    jal x1, aes128_dual_table
    bn.sid x23, 0(x26)                /* cache last diagonal (cache now full) */
    addi x26, x26, 32
    sw x26, 24(x3)
    li x26, 6                          /* restore WDR-6 index for P3 */
    bn.add w0, w0, w19
    /* No upper-tri for last row (95-95=0). */

    addi x8, x3, 0                     /* restore x8 (wrapper clobbered it) */
    bn.mov w7, w0                      /* save AES IV state before GF-mul phase */
    bn.mov w8, w19                     /* save +2 increment */
    /* Restore x11 (O cursor) and x12 (result cursor) before loopi 32. */
    lw x11, 4(x8)
    lw x12, 16(x8)
    loopi 32, 74
        lw x9, 12(x8)
        bn.lid x17, 0(x11++)
        bn.lid x28, 0(x11++)
        bn.lid x27, 0(x11++)
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        bn.mov w19, w3
        bn.mov w0, w6
        bn.xor w20, w20, w20
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        bn.mov w0, w17
        bn.mov w20, w1
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        loopi 31, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w4
        loopi 16, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sid x30, 0(x12++)
        lw x9, 12(x8)
        bn.lid x26, 0(x9++)
        bn.lid x25, 0(x9++)
        bn.mov w0, w6
        bn.xor w20, w20, w20
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        bn.mov w0, w17
        bn.mov w20, w1
        jal x1, gf16_macc_sw
        bn.mov w1, w20
        loopi 15, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.mov w19, w5
        loopi 32, 10
            bn.lid x26, 0(x9++)
            bn.lid x25, 0(x9++)
            bn.mov w0, w6
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
            bn.mov w0, w17
            bn.mov w20, w1
            jal x1, gf16_macc_sw
            bn.mov w1, w20
        bn.sid x30, 0(x12++)

    /* Restore AES IV state + +2 incr (helper destroyed them in tail loopi 32). */
    bn.mov w0, w7
    bn.mov w19, w8

    /* ------- P2 add: add AES-CTR P2 stream to result rows 0..95. ------- */
    lw x12, 8(x8)

    /* x12 is wrapper-clobbered; use x24 (dead after loopi 94) as a register
     * save slot to avoid touching the stack inside the hot inner loop. */
    loopi 96, 11
        loopi 64, 9
            bn.lid x26, 0(x12)
            addi x24, x12, 0          /* save x12 → x24 */
            bn.mov w18, w0
            jal x1, aes128_dual_table
            addi x12, x24, 0          /* restore x12 */
            bn.mov w3, w2
            bn.xor w6, w6, w3
            bn.add w0, w0, w19
            bn.sid x26, 0(x12++)
        nop

    addi x8, x3, 0                       /* restore x8 (wrapper clobbered it) */
    addi x2, x8, 32

    /* Restore x14/x15/x16 (KS / AES_128_encrypt clobber them; caller needs them live). */
    lw x14, 0(x8)
    lw x15, 4(x8)
    lw x16, 8(x8)
    lw x3, 20(x8)
    csrrw x0, mod1, x0
    ret

#endif

/* P1O_P2 (Is keygen) - compute P1*O + P2 over GF(16), V=96, O=64, M=64.
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW gf16 multiply + SW T-table AES
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.4 + SW AES via bn.gfmul
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.4 + inline bn.aes128.*
 *
 * HW arms: ONE P1 walk per O column pair - col_i chain -> ACC (w8), col_i+1
 * realigned to nibble 0 (w9/w10) -> ACCH (w12), shared mod1 cursor.
 * in   : x10 out (advanced +196,608), x11 pk_seed, x12 O (advanced/reset)
 * clob (bngfaes) : x3, x7-x9, x20, x22-x31; w0-w10, w12, w19-w31; ACC, ACCH; FG0
 * clob (bngfonly): x3, x5-x7, x9, x13-x31; w0-w31; ACC, ACCH; FG0
 * both HW arms leave mod0=0x13, mod1=0; x2 restored (32B frame + 3,072B P1 row temp)
 * stack: 3,104B
 */

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* bngfaes (HW bn.gfmul.4 + inline bn.aes128.*) */
.section .text
.global P1O_P2 
.balign 4
P1O_P2:
    # x10 = output addr (96x64, 196,608B), x11 = pk_seed addr, x12 = O matrix addr
    bn.xor w31, w31, w31
    li x31, 0x13
    csrrw x0, mod0, x31
    addi x2, x2, -32
    add x3, x0, x2
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)

    #AES-128 key expansion from sk_seed (w30..w20 = round keys 0..10)
    li x31, 30
    bn.lid x31, 0(x11)
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

    #Setup W1 for P1
    bn.addi w1, w31, 1
    bn.rshi w1, w1, w31 >> 32

    #Setup W2 for P2 AES-CTR counter
    bn.addi w2, w31, 291
    bn.rshi w2, w2, w31 >> 155
    bn.or w2, w2, w2 << 128
    bn.add w2, w2, w1
    #Setup IV increment
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    li x23, 6       # load row element of expanded p1
    li x24, 7       # load row element of expanded p1
    li x25, 8       # for store P1*O result (col_i, ACC)
    li x8,  12      # for store P1*O result (col_i+1, ACCH readback w12)
    li x26, 3       # load column of O
    li x27, 4       # load column of O
    li x28, 5       # load column of O
    li x29, 3072    # 96 elements x 32B = expanded P1 row temp
    li x31, 31      # for zero wdr w31
    sub x2, x2, x29 #allocate 3072 bytes on stack
    add x9, x0, x2  #x9 point at expand P1 row tmp address
    sw x9, 12(x3)   #store x9 into stack next other arguement
    add x22, x0, x9 #x22 = resident P1 tmp base (hoisted; nothing clobbers it)
    #Row 0: expand all 96 P1 elements via AES-CTR
    loopi 96, 13
        bn.aes128.encz.swap w0, w1, w30 
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
        bn.sid x0, 0(x9++)
        bn.add w1, w1, w19
    #Row 0: dot product with 32 O column pairs, ONE P1 walk per pair:
    # col_i chain -> ACC (w8), col_i+1 chain -> ACCH (w12). col_i+1 realigned to
    # nibble 0 (w9 = w4[32:]||w5[0:31], w10 = w5[32:63]) so one mod1 cursor serves
    # both chains. Order load-bearing: .acc reads the cursor BEFORE .acch.inc
    # advances it - never reorder, never put .inc on both.
    loopi 32, 51
        add x9, x0, x22     #reset P1 row tmp walker (x22 hoisted base)
        bn.wsrw acc, w31    #clear ACC  (col_i chain)
        bn.wsrw acch, w31   #clear ACCH (col_i+1 chain)
        bn.lid x26, 0(x12++)    #w3: O col_i low
        bn.lid x27, 0(x12++)    #w4: O col_i high | col_i+1 low
        bn.lid x28, 0(x12++)    #w5: O col_i+1 high
        bn.rshi w9, w5, w4 >> 128   #col_i+1 nib[0:63] aligned
        bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned
        csrrw x0, mod1, x0          #seg1: mod1=0 (col_i w3 | col_i+1 w9)
        loopi 32, 6                  #O[0:63] (64 nib, 2 P1 elems/iter)
            bn.lid x23, 0(x9++) #w6: p1 row element
            bn.lid x24, 0(x9++) #w7: p1 row element+1
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
        loopi 16, 6                  #O[64:95] (32 nib; cursor wrapped 64->0)
            bn.lid x23, 0(x9++)
            bn.lid x24, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
        #expand P2[0][col_i] via AES-CTR, XOR with dot product
        bn.aes128.encz.swap w0, w2, w30
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
        bn.add w2, w2, w19
        bn.xor w8, w8, w0          #result[0][col_i] = P1*O XOR P2
        bn.sid x25, 0(x10++)
        #expand P2[0][col_i+1] via AES-CTR, XOR with dot product (ACCH readback in w12)
        bn.aes128.encz.swap w0, w2, w30
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
        bn.add w2, w2, w19
        bn.xor w12, w12, w0        #result[0][col_i+1] = P1*O XOR P2
        bn.sid x8, 0(x10++)
    #Rows 1-94: P1 upper-triangular, row r has (96-r) elements. ONE P1 walk per pair:
    # col_i -> ACC (w8), col_i+1 -> ACCH (w12); col_i+1 realigned to nibble 0 in
    # w9/w10 so the shared mod1 cursor serves both chains. 2 row-bands:
    #   band1+2 r=1..63: cursor=r,  col_i w3[r:]->w4[0:31];  col_i+1 w9[r:]->w10[0:31]
    #   band3   r=64..94: cursor=r-64, col_i w4[r-64:31];    col_i+1 w10[r-64:31]
    # per-row P1 expand moved to p1op2_rows1_94_setup. x7(row)/x30(96-r) carry across bands.
    li x7, 1        # current row
    li x30, 95      # 96-r element count

    # Band 1+2: r = 1..63 (merged: shared cursor=r serves col_i via w3/w4 and the
    # realigned col_i+1 via w9/w10 - segment boundaries coincide)
    loopi 63, 50
        jal x1, p1op2_rows1_94_setup
        addi x20, x30, -32        # 64-r  (seg1 length, w3|w9)
        loopi 32, 45
            add x9, x0, x22
            bn.wsrw acc, w31        #clear ACC  (col_i chain)
            bn.wsrw acch, w31       #clear ACCH (col_i+1 chain)
            bn.lid x26, 0(x12++)    #w3: O col_i low
            bn.lid x27, 0(x12++)    #w4: O col_i high | col_i+1 low
            bn.lid x28, 0(x12++)    #w5: O col_i+1 high
            bn.rshi w9, w5, w4 >> 128   #col_i+1 nib[0:63] aligned
            bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned
            csrrw x0, mod1, x7      #seg1: cursor=r (col_i w3 | col_i+1 w9)
            loop x20, 3             #O[r..63] (64-r elems)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
            loopi 32, 3             #O[64..95] (cursor wrapped 64->0)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
            bn.aes128.encz.swap w0, w2, w30
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
            bn.add w2, w2, w19
            bn.xor w8, w8, w0
            bn.sid x25, 0(x10++)
            bn.aes128.encz.swap w0, w2, w30   #P2 col_i+1 (ACCH readback in w12)
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
            bn.add w2, w2, w19
            bn.xor w12, w12, w0
            bn.sid x8, 0(x10++)
        addi x7, x7, 1
        addi x30, x30, -1

    # Band 3: r = 64..94 (shared cursor=r-64 serves col_i w4-window and col_i+1
    # w10-window, same 96-r length)
    loopi 31, 45
        jal x1, p1op2_rows1_94_setup
        addi x20, x7, -64         # r-64  (shared start cursor)
        loopi 32, 40
            add x9, x0, x22
            bn.wsrw acc, w31        #clear ACC  (col_i chain)
            bn.wsrw acch, w31       #clear ACCH (col_i+1 chain)
            bn.lid x26, 0(x12++)
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned (rows>=64 need only w10)
            csrrw x0, mod1, x20     #cursor=r-64 (col_i w4 | col_i+1 w10)
            loop x30, 3             #(96-r elems)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
            bn.aes128.encz.swap w0, w2, w30
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
            bn.add w2, w2, w19
            bn.xor w8, w8, w0
            bn.sid x25, 0(x10++)
            bn.aes128.encz.swap w0, w2, w30   #P2 col_i+1 (ACCH readback in w12)
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
            bn.add w2, w2, w19
            bn.xor w12, w12, w0
            bn.sid x8, 0(x10++)
        addi x7, x7, 1
        addi x30, x30, -1
    #Row 95 (last): only 1 P1 element, special-case O extraction
    add x9, x0, x22
    bn.aes128.encz.swap w0, w1, w30
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
    bn.sid x0, 0(x9)
    csrrw x0, mod1, x0   #rows1-94 used mod1 cursor; reset for row95 byte0-indexed gfmul
    lw x12, 8(x3)   #Reset Matrix O address
    loopi 32, 38
        bn.wsrw acc, w31    #clear ACC  (col_i)
        bn.wsrw acch, w31   #clear ACCH (col_i+1)
        bn.lid x26, 0(x12++)    #load Matrix O 2 col 96 bytes; w3: col_i
        bn.lid x27, 0(x12++)    #w4: col_i+1 || col_i
        bn.lid x28, 0(x12++)    #w5: col_i+1
        bn.rshi w3, w31, w4 >> 124  #extract O[95][col_i] nibble from w4
        bn.rshi w9, w31, w5 >> 252  #extract O[95][col_i+1] nibble from w5
        bn.lid x23, 0(x9)
        bn.gfmul.4.acc  w8,  w6, w3 #both dots non-inc: mod1 stays 0 for the epilogue
        bn.gfmul.4.acch w12, w6, w9
        bn.aes128.encz.swap w0, w2, w30
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
        bn.add w2, w2, w19
        bn.xor w8, w8, w0
        bn.sid x25, 0(x10++)
        bn.aes128.encz.swap w0, w2, w30   #P2 col_i+1 (ACCH readback in w12)
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
        bn.add w2, w2, w19
        bn.xor w12, w12, w0
        bn.sid x8, 0(x10++)

    # restore caller's x2 (kernel allocated 32 + 3072 B; x3 = orig_x2 - 32)
    addi x3, x3, 32
    add  x2, x0, x3
    ret

# p1op2_rows1_94_setup (bngfaes): per-row P1 expand (inline AES-CTR) + O ptr reset.
#   In: x7=row r, x30=96-r. Out: 96-r P1 elems in temp, x12=O base. Preserves x7,x30.
p1op2_rows1_94_setup:
    add x9, x0, x22
    loop x30, 13
        bn.aes128.encz.swap w0, w1, w30
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
        bn.sid x0, 0(x9++)
        bn.add w1, w1, w19
    lw x12, 8(x3)
    ret
#elif defined(GF_INSTRUCTIONS)

/* bngfonly (HW bn.gfmul.4 + aes128_keygen jal) */
.section .text
.global P1O_P2 
.balign 4
P1O_P2:
    # x10 = output addr (96x64, 196,608B), x11 = pk_seed addr, x12 = O matrix addr
    bn.xor w31, w31, w31
    li x31, 0x13
    csrrw x0, mod0, x31
    addi x2, x2, -32
    add x3, x0, x2
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)

    # BNGFONLY: SW KS via 10x KeySchedule_keygen producing RK1..RK10 in w20..w29 (FORWARD)
    li x31, 30
    bn.lid x31, 0(x11)                # w30 = AES key

    # Load AES constants (aes_constants_keygen provides .data labels)
    la x13, affine_value
    li x6, 8
    bn.lid x6, 0(x13)                 # w8 = affine_value (0x63..63)
    la x14, msb_mask
    li x6, 9
    bn.lid x6, 0(x14)                 # w9 = msb_mask (0x80..80)
    la x15, rcon
    li x6, 11
    bn.lid x6, 0(x15)                 # w11 = rcon (KS only)
    la x13, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x13)                 # w7 = byte_swap_mask (aes128_keygen input)

    # Prime w17 then dual-store w30
    bn.mov w17, w30                   # w17 = key | 0
    bn.or w30, w30, w30 << 128        # w30 = key | key (dual-stored RK0)

    # 10 SW KeySchedule_keygen calls produce RK1..RK10 in w20..w29 (FORWARD layout)
    jal x1, KeySchedule_keygen
    bn.mov w20, w17
    bn.or  w20, w20, w20 << 128
    jal x1, KeySchedule_keygen
    bn.mov w21, w17
    bn.or  w21, w21, w21 << 128
    jal x1, KeySchedule_keygen
    bn.mov w22, w17
    bn.or  w22, w22, w22 << 128
    jal x1, KeySchedule_keygen
    bn.mov w23, w17
    bn.or  w23, w23, w23 << 128
    jal x1, KeySchedule_keygen
    bn.mov w24, w17
    bn.or  w24, w24, w24 << 128
    jal x1, KeySchedule_keygen
    bn.mov w25, w17
    bn.or  w25, w25, w25 << 128
    jal x1, KeySchedule_keygen
    bn.mov w26, w17
    bn.or  w26, w26, w26 << 128
    jal x1, KeySchedule_keygen
    bn.mov w27, w17
    bn.or  w27, w27, w27 << 128
    jal x1, KeySchedule_keygen
    bn.mov w28, w17
    bn.or  w28, w28, w28 << 128
    jal x1, KeySchedule_keygen
    bn.mov w29, w17
    bn.or  w29, w29, w29 << 128       # RK10 dual-store

    # Restore mod0=0x13 (GF16) - KeySchedule_keygen leaves mod0=0x11B (AES poly)
    li x31, 0x13
    csrrw x0, mod0, x31

    # Setup P1 IV in w18 (ACTIVE - counters [1 | 0])
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    # Setup P2 IV in w0 (INACTIVE - counter starts at 9312 = 291<<5; dual-block layout)
    bn.addi w0, w31, 291
    bn.rshi w0, w0, w31 >> 155
    bn.or w0, w0, w0 << 128
    bn.add w0, w0, w18

    # Setup IV increment w19 = +2 per dual-block step
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    # Pre-hoist AES constant addresses (used inside loop bodies for w7/w8/w9 reload)
    la x13, byte_swap_mask
    la x14, affine_value
    la x15, msb_mask
    li x5,  7                         # WDR idx for w7 (= byte_swap_mask)
    li x6,  8                         # WDR idx for w8 (= affine_value)
    li x16, 9                         # WDR idx for w9 (= msb_mask)
    li x17, 2                         # WDR idx for w2 (aes128_keygen output)
    li x31, 31                        # WDR idx for w31 (used by bn.wsrw acc, w31)

    li x23, 6       # load row element of expanded p1
    li x24, 7       # load row element of expanded p1    
    li x25, 8       # for store P1*O result
    li x26, 3       # load column of O
    li x27, 4       # load column of O
    li x28, 5       # load column of O
    li x29, 3072    # 96 elements x 32B = expanded P1 row temp
    li x31, 31      # for zero wdr w31
    sub x2, x2, x29 #allocate 3072 bytes on stack
    add x9, x0, x2  #x9 point at expand P1 row tmp address
    sw x9, 12(x3)   #store x9 into stack next other arguement
    add x22, x0, x9 #x22 = resident P1 tmp base (hoisted; aes128_keygen preserves it)
    #Row 0: expand all 96 P1 elements via AES-CTR (BNGFONLY: jal aes128_keygen per call)
    # w18 = P1 IV active (set in prologue).
    # Reload w7 (KS clobbers w7); w8/w9 preserved by KS, reloaded too
    bn.lid x5,  0(x13)
    bn.lid x6,  0(x14)
    bn.lid x16, 0(x15)
    li x21, 0x13    # resident: aes128_keygen leaves mod0=0x11B; re-set after clusters
    loopi 96, 3
        jal x1, aes128_keygen
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    csrrw x0, mod0, x21
    # Swap w18 <-> w0: P1 IV -> w0, P2 IV -> w18 (active for column loop)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    #Row 0: dot product with 32 O column pairs (BNGFONLY: w18 = P2 IV after swap above)
    # ONE P1 walk per pair: col_i -> ACC (w8), realigned col_i+1 (w9/w10) -> ACCH (w12).
    # .acc reads the cursor BEFORE .acch.inc advances it - never reorder.
    loopi 32, 37
        add x9, x0, x22
        bn.wsrw acc, w31        #clear ACC  (col_i chain)
        bn.wsrw acch, w31       #clear ACCH (col_i+1 chain)
        bn.lid x26, 0(x12++)    #w3: O col_i low
        bn.lid x27, 0(x12++)    #w4: O col_i high | col_i+1 low
        bn.lid x28, 0(x12++)    #w5: O col_i+1 high
        bn.rshi w9, w5, w4 >> 128   #col_i+1 nib[0:63] aligned (w9 reloaded as msb_mask below)
        bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned
        csrrw x0, mod1, x0          #seg1: mod1=0 (col_i w3 | col_i+1 w9)
        loopi 32, 6                  #O[0:63] (64 nib, 2 P1 elems/iter)
            bn.lid x23, 0(x9++)
            bn.lid x24, 0(x9++)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
        loopi 16, 6                  #O[64:95] (32 nib; cursor wrapped 64->0)
            bn.lid x23, 0(x9++)
            bn.lid x24, 0(x9++)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
        # P2 via jal aes128_keygen x2: park both dots (w8 = affine input, w12 aes-clobbered),
        # reload w7/w8/w9 consts (walk consumed them); w8 stays affine across jal#2.
        bn.mov w6, w8
        bn.mov w3, w12
        bn.lid x5,  0(x13)
        bn.lid x6,  0(x14)
        bn.lid x16, 0(x15)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w6, w6, w2          #result[0][col_i]
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2          #result[0][col_i+1]
        bn.sid x26, 0(x10++)
        csrrw x0, mod0, x21
    # (No swap here; the outer-loop start-of-iter swap handles the Row0->iter1 transition.)
    #Rows 1-94: mod1 cursor + .acc.inc (no rshi), 3 row-bands by start register (dual-col).
    #   band1 r=1..31 : col_i w3[r:]->w4;   col_i+1 w4[32+r:]->w5
    #   band2 r=32..63: col_i w3[r:]->w4;   col_i+1 w5[r-32:]
    #   band3 r=64..94: col_i w4[r-64:];    col_i+1 w5[r-32:]
    # per-row P1 expand + IV swaps moved to p1op2_rows1_94_setup. x7/x30 carry across bands.
    li x7, 1        # current row
    li x30, 95      # 96-r element count

    # Band 1+2: r = 1..63 (merged: shared cursor=r serves col_i via w3/w4 and the
    # realigned col_i+1 via w9/w10 - segment boundaries coincide)
    loopi 63, 36
        jal x1, p1op2_rows1_94_setup
        addi x20, x30, -32        # 64-r  (seg1 length, w3|w9)
        loopi 32, 31
            add x9, x0, x22
            bn.wsrw acc, w31        #clear ACC  (col_i chain)
            bn.wsrw acch, w31       #clear ACCH (col_i+1 chain)
            bn.lid x26, 0(x12++)
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.rshi w9, w5, w4 >> 128   #col_i+1 nib[0:63] aligned
            bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned
            csrrw x0, mod1, x7      #seg1: cursor=r (col_i w3 | col_i+1 w9)
            loop x20, 3             #O[r..63] (64-r elems)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
            loopi 32, 3             #O[64..95] (cursor wrapped 64->0)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
            bn.mov w6, w8           #park col_i dot (w8 = affine input to aes)
            bn.mov w3, w12          #park col_i+1 dot (aes clobbers w12)
            bn.lid x5,  0(x13)
            bn.lid x6,  0(x14)
            bn.lid x16, 0(x15)
            jal x1, aes128_keygen
            bn.add w18, w18, w19
            bn.xor w6, w6, w2
            bn.sid x23, 0(x10++)
            jal x1, aes128_keygen
            bn.add w18, w18, w19
            bn.xor w3, w3, w2
            bn.sid x26, 0(x10++)
            csrrw x0, mod0, x21
        addi x7, x7, 1
        addi x30, x30, -1

    # Band 3: r = 64..94 (shared cursor=r-64 serves col_i w4-window and col_i+1
    # w10-window, same 96-r length)
    loopi 31, 31
        jal x1, p1op2_rows1_94_setup
        addi x20, x7, -64         # r-64  (shared start cursor)
        loopi 32, 26
            add x9, x0, x22
            bn.wsrw acc, w31        #clear ACC  (col_i chain)
            bn.wsrw acch, w31       #clear ACCH (col_i+1 chain)
            bn.lid x26, 0(x12++)
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.rshi w10, w31, w5 >> 128 #col_i+1 nib[64:95] aligned (rows>=64 need only w10)
            csrrw x0, mod1, x20     #cursor=r-64 (col_i w4 | col_i+1 w10)
            loop x30, 3             #(96-r elems)
                bn.lid x23, 0(x9++)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
            bn.mov w6, w8           #park col_i dot
            bn.mov w3, w12          #park col_i+1 dot
            bn.lid x5,  0(x13)
            bn.lid x6,  0(x14)
            bn.lid x16, 0(x15)
            jal x1, aes128_keygen
            bn.add w18, w18, w19
            bn.xor w6, w6, w2
            bn.sid x23, 0(x10++)
            jal x1, aes128_keygen
            bn.add w18, w18, w19
            bn.xor w3, w3, w2
            bn.sid x26, 0(x10++)
            csrrw x0, mod0, x21
        addi x7, x7, 1
        addi x30, x30, -1
    # Swap w18 <-> w0 -> w18 = P1 IV for Row 95 P1 (after outer loop, w18 = P2 last column iter)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    #Row 95 (last): only 1 P1 element, special-case O extraction
    add x9, x0, x22
    # Single P1 AES via jal aes128_keygen (w18 = P1 IV from swap above)
    bn.lid x5,  0(x13)
    bn.lid x6,  0(x14)
    bn.lid x16, 0(x15)
    jal x1, aes128_keygen
    bn.sid x17, 0(x9)
    bn.add w18, w18, w19
    csrrw x0, mod0, x21
    # Swap w18 <-> w0 -> w18 = P2 IV active for Row 95 column loop
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x12, 8(x3)
    loopi 32, 24
        bn.wsrw acc, w31        #clear ACC  (col_i)
        bn.wsrw acch, w31       #clear ACCH (col_i+1)
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w3, w31, w4 >> 124  #extract O[95][col_i] nibble
        bn.rshi w9, w31, w5 >> 252  #extract O[95][col_i+1] nibble
        bn.lid x23, 0(x9)
        bn.gfmul.4.acc  w8,  w6, w3 #both dots non-inc: mod1 untouched
        bn.gfmul.4.acch w12, w6, w9
        # P2 AES x2: park both dots, reload consts (walk consumed w3/w9; w8 was acc)
        bn.mov w6, w8
        bn.mov w3, w12
        bn.lid x5,  0(x13)
        bn.lid x6,  0(x14)
        bn.lid x16, 0(x15)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w6, w6, w2
        bn.sid x23, 0(x10++)
        jal x1, aes128_keygen
        bn.add w18, w18, w19
        bn.xor w3, w3, w2
        bn.sid x26, 0(x10++)
        csrrw x0, mod0, x21

    # restore caller's x2 (kernel allocated 32 + 3072 B; x3 = orig_x2 - 32)
    addi x3, x3, 32
    add  x2, x0, x3
    ret

# p1op2_rows1_94_setup (bngfonly): per-row IV swaps + P1 expand (jal aes128_keygen) + O ptr.
#   In: x7=row r, x30=96-r. Out: 96-r P1 elems in temp, x12=O base, w18=P2 IV. Preserves x7,x30.
p1op2_rows1_94_setup:
    bn.mov w10, w18              # swap w18<->w0 -> w18 = P1 IV
    bn.mov w18, w0
    bn.mov w0,  w10
    add x9, x0, x22
    bn.lid x5,  0(x13)
    bn.lid x6,  0(x14)
    bn.lid x16, 0(x15)
    loop x30, 3
        jal x1, aes128_keygen
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    csrrw x0, mod0, x21
    bn.mov w10, w18             # swap back -> w18 = P2 IV for column loop
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x12, 8(x3)
    ret
#else

/* sw (SW gf16 + T-table AES) */
.section .text
.global P1O_P2 
.balign 4
P1O_P2:
    # x10 = output addr (96x64, 196,608B), x11 = pk_seed addr, x12 = O matrix addr
    bn.xor w31, w31, w31
    li x31, 0x13
    csrrw x0, mod0, x31
    addi x2, x2, -32                  # frame: slots 0..28 (kept at 32; slot 28 reused for cursor saves around AES)
    add x3, x0, x2
    sw x10, 0(x2)                     # save result base
    sw x11, 4(x2)                     # save pk_seed addr
    sw x12, 8(x2)                     # save O matrix base

    # SW: AES_128_keyschedule expands pk_seed -> 11 RKs (176 B) in DMEM.
    li x30, 192                       # pad 176 B -> 192 (= 6x32) for 32-byte stack alignment
    sub x2, x2, x30
    sw x2, 16(x3)                     # save RK buf addr to slot 16

    lw x10, 4(x3)                     # x10 = pk_seed addr (KS input)
    lw x11, 16(x3)                    # x11 = RK buf base (KS output)
    jal x1, AES_128_keyschedule       # expand pk_seed into 11 RKs (clobbers x5..x8,x12..x18,x29..x31)

    # Reload caller's input args clobbered by KS
    lw x10, 0(x3)                     # restore result base
    lw x12, 8(x3)                     # restore O matrix base

    # Restore mod0=0x13 (GF16) - AES_128_keyschedule may have changed mod state
    li x31, 0x13
    csrrw x0, mod0, x31

    # SW: build w16 = 0x8888..88 nibble-MSB mask for gf16_macc_sw (built ONCE;
    # aes128_dual_table is GPR/DMEM T-table: preserves all WDRs except its w2
    # output, so w16 survives every AES call).
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

    # Setup P1 IV in w18 (ACTIVE - counters [1 | 0])
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    # Setup P2 IV in w0 (INACTIVE - counter starts at 9312 = 291<<5; dual-block layout)
    bn.addi w0, w31, 291
    bn.rshi w0, w0, w31 >> 155
    bn.or w0, w0, w0 << 128
    bn.add w0, w0, w18

    # Setup IV increment w19 = +2 per dual-block step
    bn.addi w19, w31, 2
    bn.or w19, w19, w19 << 128
    bn.rshi w19, w19, w31 >> 160

    # x18 = RK buf base addr (aes128_dual_table reads from x18; preserved by helper)
    lw x18, 16(x3)

    li x17, 2                         # WDR idx for w2 (aes128_dual_table output; preserved by helper)
    li x31, 31                        # WDR idx for w31 (zero; SW acc cleared via bn.xor w20)

    li x23, 6       # load row element of expanded p1
    li x24, 7       # load row element of expanded p1    
    li x25, 8       # for store P1*O result
    li x26, 3       # load column of O
    li x27, 4       # load column of O
    li x28, 5       # load column of O
    li x29, 3072    # 96 elements x 32B = expanded P1 row temp
    li x31, 31      # for zero wdr w31
    sub x2, x2, x29 #allocate 3072 bytes on stack
    add x9, x0, x2  #x9 point at expand P1 row tmp address
    sw x9, 12(x3)   #store x9 into stack next other arguement
    # SW: aes128_dual_table clobbers x10. Save current result cursor in slot 4
    # (slot 4 is free after KS; reusing for result cursor).
    sw x10, 4(x3)
    #Row 0: expand all 96 P1 elements via AES-CTR (SW: jal aes128_dual_table per call)
    # w18 = P1 IV active (set in prologue). aes128_dual_table preserves x9 + x17.
    loopi 96, 3
        jal x1, aes128_dual_table
        bn.sid x17, 0(x9++)
        bn.add w18, w18, w19
    # Swap w18 <-> w0: P1 IV -> w0, P2 IV -> w18 (active for column loop)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    # SW: aes128_dual_table clobbered x10/x12. Reload before col loop.
    lw x10, 4(x3)
    lw x12, 8(x3)
    #Row 0: dot product with 32 O column pairs (SW: w18 = P2 IV after swap above)
    loopi 32, 65
        lw x9, 12(x3)
        # SW: save IVs (w0/w18/w19) + clear SW acc w20 (replaces bn.wsrw acc,w31)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)    #w3: O col_i low
        bn.lid x27, 0(x12++)    #w4: O col_i high | col_i+1 low
        bn.lid x28, 0(x12++)    #w5: O col_i+1 high
        loopi 48, 14
            bn.lid x23, 0(x9++)
            bn.lid x24, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
            bn.mov w0, w7
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w5, w4 >> 4
            bn.rshi w5, w31, w5 >> 4
        # SW: SW acc w20 -> w8, restore IVs before AES
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        # P2[0][col_i] via jal aes128_dual_table; save x10/x12 (helper clobbers them); w8 preserved
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        # col_i+1: 2-reg rshi
        # SW: save IVs + clear SW acc w20
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        lw x9, 12(x3)
        loopi 48, 12
            bn.lid x23, 0(x9++)
            bn.lid x24, 0(x9++)
            bn.mov w0, w6
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
            bn.mov w0, w7
            bn.mov w19, w3
            jal x1, gf16_macc_sw
            bn.rshi w3, w4, w3 >> 4
            bn.rshi w4, w31, w4 >> 4
        # SW: SW acc w20 -> w8, restore IVs
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        # P2[0][col_i+1] via jal aes128_dual_table
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
    # SW: save advanced x10 (result cursor at end of Row 0 col) for next row's reload.
    sw x10, 4(x3)
    #Rows 1-94: P1 is upper-triangular, row r has (96-r) elements
    li x7, 1        # current row
    li x30, 95      # num of element in current row
    loopi 94, 86
        # Start of iter: swap w18 <-> w0 -> w18 = P1 IV active
        # (At entry: w18 = P2 IV from previous phase/iter column loop end.)
        bn.mov w10, w18
        bn.mov w18, w0
        bn.mov w0,  w10
        lw x9, 12(x3)   # Reset P1 row buffer write ptr
        # SW: save x7 to slot 28 (aes128_dual_table clobbers x7).
        sw x7, 28(x3)
        loop x30, 3                  # (96-r) P1 elements via jal aes128_dual_table
            jal x1, aes128_dual_table
            bn.sid x17, 0(x9++)
            bn.add w18, w18, w19
        # Restore x7 (clobbered by aes128_dual_table)
        lw x7, 28(x3)
        # Swap w18 <-> w0 -> w18 = P2 IV active for column loop
        bn.mov w10, w18
        bn.mov w18, w0
        bn.mov w0,  w10
        lw x12, 8(x3)
        # SW: reload x10 result cursor (aes128_dual_table clobbered it)
        lw x10, 4(x3)
        loopi 32, 67
            lw x9, 12(x3)
            # SW: save IVs (w0/w18/w19) + clear SW acc w20 (replaces bn.wsrw acc,w31)
            bn.mov w21, w0
            bn.mov w22, w18
            bn.mov w23, w19
            bn.xor w20, w20, w20
            bn.lid x26, 0(x12++)
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            loop x7, 3
                bn.rshi w3, w4, w3 >> 4
                bn.rshi w4, w5, w4 >> 4
                bn.rshi w5, w31, w5 >> 4
            li x8, 96
            sub x8, x8, x7
            loop x8, 7
                bn.lid x23, 0(x9++)
                bn.mov w0, w6
                bn.mov w19, w3
                jal x1, gf16_macc_sw
                bn.rshi w3, w4, w3 >> 4
                bn.rshi w4, w5, w4 >> 4
                bn.rshi w5, w31, w5 >> 4
            # SW: SW acc w20 -> w8, restore IVs before AES
            bn.mov w8, w20
            bn.mov w0, w21
            bn.mov w18, w22
            bn.mov w19, w23
            # P2 AES for col_i (sw: save x10/x12/x7; w8 acc preserved by helper)
            sw x10, 20(x3)
            sw x12, 24(x3)
            sw x7,  28(x3)
            jal x1, aes128_dual_table
            lw x10, 20(x3)
            lw x12, 24(x3)
            lw x7,  28(x3)
            bn.add w18, w18, w19
            bn.xor w8, w8, w2
            bn.sid x25, 0(x10++)
            # SW: save IVs + clear SW acc w20
            bn.mov w21, w0
            bn.mov w22, w18
            bn.mov w23, w19
            bn.xor w20, w20, w20
            lw x9, 12(x3)
            loop x7, 2
                bn.rshi w3, w4, w3 >> 4
                bn.rshi w4, w31, w4 >> 4
            li x8, 96
            sub x8, x8, x7
            loop x8, 6
                bn.lid x23, 0(x9++)
                bn.mov w0, w6
                bn.mov w19, w3
                jal x1, gf16_macc_sw
                bn.rshi w3, w4, w3 >> 4
                bn.rshi w4, w31, w4 >> 4
            # SW: SW acc w20 -> w8, restore IVs
            bn.mov w8, w20
            bn.mov w0, w21
            bn.mov w18, w22
            bn.mov w19, w23
            # P2 AES for col_i+1
            sw x10, 20(x3)
            sw x12, 24(x3)
            sw x7,  28(x3)
            jal x1, aes128_dual_table
            lw x10, 20(x3)
            lw x12, 24(x3)
            lw x7,  28(x3)
            bn.add w18, w18, w19
            bn.xor w8, w8, w2
            bn.sid x25, 0(x10++)
        # SW: save advanced x10 for next iter's col loop
        sw x10, 4(x3)
        addi x7, x7, 1
        addi x30, x30, -1
    # Swap w18 <-> w0 -> w18 = P1 IV for Row 95 P1 (after outer loop, w18 = P2 last column iter)
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    #Row 95 (last): only 1 P1 element, special-case O extraction
    lw x9, 12(x3)
    # Single P1 AES via jal aes128_dual_table (w18 = P1 IV from swap above)
    jal x1, aes128_dual_table
    bn.sid x17, 0(x9)
    bn.add w18, w18, w19
    # Swap w18 <-> w0 -> w18 = P2 IV active for Row 95 column loop
    bn.mov w10, w18
    bn.mov w18, w0
    bn.mov w0,  w10
    lw x12, 8(x3)
    # SW: reload x10 result cursor (helper call clobbered it)
    lw x10, 4(x3)
    loopi 32, 45
        # SW: save IVs + clear SW acc w20 (replaces bn.wsrw acc,w31)
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.lid x26, 0(x12++)
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.rshi w3, w31, w4 >> 124
        bn.lid x23, 0(x9)
        bn.mov w0, w6
        bn.mov w19, w3
        jal x1, gf16_macc_sw
        # SW: SW acc w20 -> w8, restore IVs
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        # P2 AES for col_i (sw: save x10/x12 around helper)
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)
        # SW: save IVs + clear SW acc w20
        bn.mov w21, w0
        bn.mov w22, w18
        bn.mov w23, w19
        bn.xor w20, w20, w20
        bn.rshi w3, w31, w5 >> 252
        bn.lid x23, 0(x9)
        bn.mov w0, w6
        bn.mov w19, w3
        jal x1, gf16_macc_sw
        # SW: SW acc w20 -> w8, restore IVs
        bn.mov w8, w20
        bn.mov w0, w21
        bn.mov w18, w22
        bn.mov w19, w23
        # P2 AES for col_i+1
        sw x10, 20(x3)
        sw x12, 24(x3)
        jal x1, aes128_dual_table
        lw x10, 20(x3)
        lw x12, 24(x3)
        bn.add w18, w18, w19
        bn.xor w8, w8, w2
        bn.sid x25, 0(x10++)

    # restore caller's x2 (kernel allocated 32 + 3072 B; x3 = orig_x2 - 32)
    addi x3, x3, 32
    add  x2, x0, x3
    ret
#endif

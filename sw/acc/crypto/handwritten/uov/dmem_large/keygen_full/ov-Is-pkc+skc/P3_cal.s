/* P3_cal (Is): P3 = Upper(O^T x (P1*O + P2)) over GF(16), m=64.
 *   -DGF_INSTRUCTIONS -> HW bn.gfmul.4.acc/.acch pair chains + WRITE-TIME FOLD:
 *     zero-init packed output, then uniform RMW-XOR per (pair,j); both pair-row
 *     targets share one transpose delta schedule ((63-j)*32) that hands each
 *     pointer into its contiguous run at its diagonal. No P3_full, no extract.
 *     First pair peeled (zero-trip region-A guard).
 *   no flag -> SW gf16_macc_sw + dense P3_full + STEP-2 extract.
 * in:  x10 = P3 upper-tri out (2080 x 32B = 66,560B, row-major packed)
 *      x11 = (P1*O+P2) buffer (96x64 row-major, stride 2048/i)
 *      x12 = O matrix (col-major, 64 cols x 48B = 3,072B)
 * out: P3 at x10
 * stack: HW 32B frame only; SW 131,104B (+ P3_full temp).
 * loop counts (objdump-verify on any body edit): HW zero-init 2080,1; pair-0 peel
 *   C-loop x22,65; pair loop 31,210 with A-loop x21,66 + j=k inline + C-loop x22,65;
 *   inner = 2 mod1 .4 segs (8,25)(4,25), 8 buffer rows per x29 = 16384 step; seg2
 *   needs no mod1 reset (seg1's 64 .inc wrap it to 0). SW outer 32,56 / mid 64,43 / inner 48,32.
 * clob (HW): x3, x8, x10, x11, x13, x16-x31; w3-w10, w12, w31; ACC, ACCH; FG0; mod0;
 *   mod1=0 on exit. x1, x2 restored.
 * WDR: w3/w4 col-k cursor; w9/w10 col-k+1 aligned; w6/w7 buf vecs + RMW temps;
 *   w8 col-k acc; w12 col-k+1 acc; w31 zero. sw adds: w21-w24 O backup, w16 mask,
 *   w0/w18/w19/w20 gf16_macc_sw scratch.
 */
.section .text
.global P3_cal
.balign 4
P3_cal:
    bn.xor w31, w31, w31
    li x31, 0x13                   # GF(2^4): x^4+x+1
    csrrw x0, mod0, x31
#ifndef GF_INSTRUCTIONS
    # sw: build w16 = 0x8888...8 (MSB of every nibble) for gf16_macc_sw
    bn.addi w16, w31, 0x8
    bn.rshi w20, w16, w31 >> 252
    bn.or   w16, w16, w20
    bn.rshi w20, w16, w31 >> 248
    bn.or   w16, w16, w20
    bn.rshi w20, w16, w31 >> 240
    bn.or   w16, w16, w20
    bn.rshi w20, w16, w31 >> 224
    bn.or   w16, w16, w20
    bn.rshi w20, w16, w31 >> 192
    bn.or   w16, w16, w20
    bn.rshi w20, w16, w31 >> 128
    bn.or   w16, w16, w20          # w16 = 0x8888...8 (64 nibbles)
#endif

#ifdef GF_INSTRUCTIONS
    li x30, 32                     # 32B frame (write-time fold, no P3_full temp)
#else
    li x30, 131104                 # 32B frame + 131072B P3_full temp
#endif
    sub x2, x2, x30
    add x3, x0, x2                # x3 = frame ptr
    sw x10, 0(x3)                  # P3 upper output addr
    sw x11, 4(x3)                  # buffer base addr
    sw x12, 8(x3)                  # O matrix base addr
    sw x1, 12(x3)                  # return address
#ifndef GF_INSTRUCTIONS
    addi x15, x3, 32              # x15 = P3_full temp buffer start (sw only)
    sw x15, 16(x3)                 # save temp buffer addr
#endif

    li x23, 6                     # WDR idx w6 (buffer even)
    li x24, 7                     # WDR idx w7 (buffer odd)
    li x25, 8                     # WDR idx w8 (col k result store)
    li x17, 12                    # WDR idx w12 (col k+1 result store)
    li x26, 3                     # WDR idx w3 (O pair load)
    li x27, 4                     # WDR idx w4
    li x28, 5                     # WDR idx w5
    li x31, 31                    # WDR idx w31
    li x29, 2048                  # buffer column stride (per i)

#ifdef GF_INSTRUCTIONS
    # STEP 1 (HW): P3 folded at WRITE time into the packed upper output (zero-init
    # + uniform RMW-XOR, order-free). Per pair (k,k+1) both row targets walk the
    # SAME transpose delta schedule ((63-j)*32, -32/j): ptrA lands on diag (k,k)
    # after its last transpose step (j=k, peeled), ptrB one j later - then both
    # advance +32 (contiguous packed rows).
    add x16, x0, x12              # O running ptr
    li x29, 16384                 # 8 buffer rows per pointer step

    # zero-init packed output (2,080 x 32B; loopi caps at 1023 -> GPR-count loop)
    lw x10, 0(x3)
    li x22, 2080
    loop x22, 1
        bn.sd w31, 0(x10++)

    # first pair (k=0) peel: no transpose region (zero-trip guard)
    lw x10, 0(x3)
    add x18, x0, x10              # ptrA = (0,0) diag
    addi x19, x10, 32             # ptrB = (0,1)
    li x20, 2016                  # delta (63-j)*32 at j=0
    li x22, 63                    # region-C count (= 63-k)
    bn.lid x26, 0(x16++)          # w3 = O pair WDR0
    bn.lid x27, 0(x16++)          # w4 = O pair WDR1
    bn.lid x28, 0(x16++)          # w5 = O pair WDR2
    bn.rshi w10, w31, w5 >> 128   # col k+1 nib 64-95 (before w5 clobbered)
    bn.rshi w9, w5, w4 >> 128     # col k+1 nib 0-63
    lw x13, 4(x3)                 # buffer col-j base
    # j=0 (peel): row0 -> diag then contiguous; row1 -> last transpose step
    bn.wsrw acc, w31
    bn.wsrw acch, w31
    add x11, x0, x13
    csrrw x0, mod1, x0            # seg1 (rows 0..63; cols w3/w9)
    loopi 8, 25
        bn.lid x23, 0(x11)
        bn.gfmul.4.acc w8, w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.lid x24, 2048(x11)
        bn.gfmul.4.acc w8, w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        bn.lid x23, 4096(x11)
        bn.gfmul.4.acc w8, w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.lid x24, 6144(x11)
        bn.gfmul.4.acc w8, w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        bn.lid x23, 8192(x11)
        bn.gfmul.4.acc w8, w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.lid x24, 10240(x11)
        bn.gfmul.4.acc w8, w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        bn.lid x23, 12288(x11)
        bn.gfmul.4.acc w8, w6, w3
        bn.gfmul.4.acch.inc w12, w6, w9
        bn.lid x24, 14336(x11)
        bn.gfmul.4.acc w8, w7, w3
        bn.gfmul.4.acch.inc w12, w7, w9
        add x11, x11, x29
    loopi 4, 25
        bn.lid x23, 0(x11)
        bn.gfmul.4.acc w8, w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.lid x24, 2048(x11)
        bn.gfmul.4.acc w8, w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        bn.lid x23, 4096(x11)
        bn.gfmul.4.acc w8, w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.lid x24, 6144(x11)
        bn.gfmul.4.acc w8, w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        bn.lid x23, 8192(x11)
        bn.gfmul.4.acc w8, w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.lid x24, 10240(x11)
        bn.gfmul.4.acc w8, w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        bn.lid x23, 12288(x11)
        bn.gfmul.4.acc w8, w6, w4
        bn.gfmul.4.acch.inc w12, w6, w10
        bn.lid x24, 14336(x11)
        bn.gfmul.4.acc w8, w7, w4
        bn.gfmul.4.acch.inc w12, w7, w10
        add x11, x11, x29
    addi x13, x13, 32
    bn.lid x23, 0(x18)            # RMW row k
    bn.xor w8, w8, w6
    bn.sd w8, 0(x18)
    addi x18, x18, 32             # ptrA contiguous from here
    bn.lid x23, 0(x19)            # RMW row k+1
    bn.xor w12, w12, w6
    bn.sd w12, 0(x19)
    add x19, x19, x20             # ptrB last transpose step -> its diag
    # j=1..63: both contiguous
    loop x22, 65
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x11, x0, x13
        csrrw x0, mod1, x0        # seg1
        loopi 8, 25
            bn.lid x23, 0(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 2048(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 4096(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 6144(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 8192(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 10240(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 12288(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 14336(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            add x11, x11, x29
        loopi 4, 25
            bn.lid x23, 0(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 2048(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 4096(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 6144(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 8192(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 10240(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 12288(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 14336(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            add x11, x11, x29
        addi x13, x13, 32
        bn.lid x23, 0(x18)        # RMW row k
        bn.xor w8, w8, w6
        bn.sd w8, 0(x18)
        addi x18, x18, 32
        bn.lid x23, 0(x19)        # RMW row k+1
        bn.xor w12, w12, w6
        bn.sd w12, 0(x19)
        addi x19, x19, 32
    # pairs k = 2,4,..,62
    lw x10, 0(x3)
    addi x8, x10, 64              # x8 = (0,k) col top for k=2 (+64/pair)
    li x21, 2                     # region-A count = k
    li x22, 61                    # region-C count = 63-k
    loopi 31, 210
        bn.lid x26, 0(x16++)      # w3 = O pair WDR0
        bn.lid x27, 0(x16++)      # w4 = O pair WDR1
        bn.lid x28, 0(x16++)      # w5 = O pair WDR2
        bn.rshi w10, w31, w5 >> 128
        bn.rshi w9, w5, w4 >> 128
        lw x13, 4(x3)             # buffer col-j base
        add x18, x0, x8           # ptrA = (0,k)
        addi x19, x8, 32          # ptrB = (0,k+1)
        li x20, 2016              # delta (63-j)*32, j=0
        loop x21, 66              # region A: j=0..k-1, both transpose
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            add x11, x0, x13
            csrrw x0, mod1, x0    # seg1
            loopi 8, 25
                bn.lid x23, 0(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 2048(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 4096(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 6144(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 8192(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 10240(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 12288(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 14336(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                add x11, x11, x29
            loopi 4, 25
                bn.lid x23, 0(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 2048(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 4096(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 6144(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 8192(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 10240(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 12288(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 14336(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                add x11, x11, x29
            addi x13, x13, 32
            bn.lid x23, 0(x18)    # RMW row k -> (j,k)
            bn.xor w8, w8, w6
            bn.sd w8, 0(x18)
            add x18, x18, x20
            bn.lid x23, 0(x19)    # RMW row k+1 -> (j,k+1)
            bn.xor w12, w12, w6
            bn.sd w12, 0(x19)
            add x19, x19, x20
            addi x20, x20, -32
        # j=k (peel): row k hits diag; row k+1 last transpose step
        bn.wsrw acc, w31
        bn.wsrw acch, w31
        add x11, x0, x13
        csrrw x0, mod1, x0        # seg1
        loopi 8, 25
            bn.lid x23, 0(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 2048(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 4096(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 6144(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 8192(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 10240(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            bn.lid x23, 12288(x11)
            bn.gfmul.4.acc w8, w6, w3
            bn.gfmul.4.acch.inc w12, w6, w9
            bn.lid x24, 14336(x11)
            bn.gfmul.4.acc w8, w7, w3
            bn.gfmul.4.acch.inc w12, w7, w9
            add x11, x11, x29
        loopi 4, 25
            bn.lid x23, 0(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 2048(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 4096(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 6144(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 8192(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 10240(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            bn.lid x23, 12288(x11)
            bn.gfmul.4.acc w8, w6, w4
            bn.gfmul.4.acch.inc w12, w6, w10
            bn.lid x24, 14336(x11)
            bn.gfmul.4.acc w8, w7, w4
            bn.gfmul.4.acch.inc w12, w7, w10
            add x11, x11, x29
        addi x13, x13, 32
        bn.lid x23, 0(x18)        # RMW row k -> diag (k,k)
        bn.xor w8, w8, w6
        bn.sd w8, 0(x18)
        addi x18, x18, 32         # ptrA contiguous from here
        bn.lid x23, 0(x19)        # RMW row k+1 -> (k,k+1)
        bn.xor w12, w12, w6
        bn.sd w12, 0(x19)
        add x19, x19, x20         # ptrB -> its diag (k+1,k+1)
        loop x22, 65              # region C: j=k+1..63, both contiguous
            bn.wsrw acc, w31
            bn.wsrw acch, w31
            add x11, x0, x13
            csrrw x0, mod1, x0    # seg1
            loopi 8, 25
                bn.lid x23, 0(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 2048(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 4096(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 6144(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 8192(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 10240(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                bn.lid x23, 12288(x11)
                bn.gfmul.4.acc w8, w6, w3
                bn.gfmul.4.acch.inc w12, w6, w9
                bn.lid x24, 14336(x11)
                bn.gfmul.4.acc w8, w7, w3
                bn.gfmul.4.acch.inc w12, w7, w9
                add x11, x11, x29
            loopi 4, 25
                bn.lid x23, 0(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 2048(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 4096(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 6144(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 8192(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 10240(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                bn.lid x23, 12288(x11)
                bn.gfmul.4.acc w8, w6, w4
                bn.gfmul.4.acch.inc w12, w6, w10
                bn.lid x24, 14336(x11)
                bn.gfmul.4.acc w8, w7, w4
                bn.gfmul.4.acch.inc w12, w7, w10
                add x11, x11, x29
            addi x13, x13, 32
            bn.lid x23, 0(x18)    # RMW row k -> (k,j)
            bn.xor w8, w8, w6
            bn.sd w8, 0(x18)
            addi x18, x18, 32
            bn.lid x23, 0(x19)    # RMW row k+1 -> (k+1,j)
            bn.xor w12, w12, w6
            bn.sd w12, 0(x19)
            addi x19, x19, 32
        addi x8, x8, 64           # next pair col top (0,k+2)
        addi x21, x21, 2          # A count = k+2
        addi x22, x22, -2         # C count = 63-(k+2)
#else
    add x10, x0, x15              # P3_full row k out ptr
    add x14, x15, x29             # P3_full row k+1 out ptr (x15 + 2048)
    add x16, x0, x12              # O running ptr

    # STEP 1 (sw): P3_full = O^T x buffer (col k and k+1 interleaved)
    loopi 32, 56
        bn.lid x26, 0(x16++)       # w3 = O pair WDR0
        bn.lid x27, 0(x16++)       # w4 = O pair WDR1
        bn.lid x28, 0(x16++)       # w5 = O pair WDR2
        bn.rshi w10, w31, w5 >> 128 # col k+1 nib 64-95 (before w5 clobbered)
        bn.rshi w9, w5, w4 >> 128   # col k+1 nib 0-63
        # Backup cursors (sw rshi slides consume w3/w4/w9/w10)
        bn.mov w21, w3             # backup col k WDR0
        bn.mov w22, w4             # backup col k WDR1
        bn.mov w23, w9             # backup col k+1 WDR0
        bn.mov w24, w10            # backup col k+1 WDR1
        lw x13, 4(x3)              # x13 = buffer base, reset to col 0
        loopi 64, 43
            bn.mov w3, w21         # restore col k cursor
            bn.mov w4, w22
            bn.mov w9, w23         # restore col k+1 cursor
            bn.mov w10, w24
            bn.xor w8, w8, w8      # clear col k acc
            bn.xor w12, w12, w12   # clear col k+1 acc
            add x11, x0, x13       # x11 = buffer[0][j]
            loopi 48, 32
                bn.lid x23, 0(x11) # w6 = buffer[2i][j]
                add x11, x11, x29
                bn.mov w0, w6      # col k: w8 ^= w6 x O[2i][k]
                bn.mov w19, w3
                bn.mov w20, w8
                jal x1, gf16_macc_sw
                bn.mov w8, w20
                bn.rshi w3, w4, w3 >> 4     # advance col k scalar
                bn.rshi w4, w31, w4 >> 4
                bn.mov w0, w6      # col k+1
                bn.mov w19, w9
                bn.mov w20, w12
                jal x1, gf16_macc_sw
                bn.mov w12, w20
                bn.rshi w9, w10, w9 >> 4     # advance col k+1 scalar
                bn.rshi w10, w31, w10 >> 4
                bn.lid x24, 0(x11) # w7 = buffer[2i+1][j]
                add x11, x11, x29
                bn.mov w0, w7      # col k
                bn.mov w19, w3
                bn.mov w20, w8
                jal x1, gf16_macc_sw
                bn.mov w8, w20
                bn.rshi w3, w4, w3 >> 4
                bn.rshi w4, w31, w4 >> 4
                bn.mov w0, w7      # col k+1
                bn.mov w19, w9
                bn.mov w20, w12
                jal x1, gf16_macc_sw
                bn.mov w12, w20
                bn.rshi w9, w10, w9 >> 4
                bn.rshi w10, w31, w10 >> 4
            bn.sid x25, 0(x10++)   # store P3_full[k][j]
            bn.sid x17, 0(x14++)   # store P3_full[k+1][j]
            addi x13, x13, 32      # next buffer column j
        add x10, x0, x14           # row k+2
        add x14, x14, x29          # row k+3
#endif

#ifndef GF_INSTRUCTIONS
    # STEP 2 (sw only): Upper triangle extract (pure XOR)
    lw x10, 0(x3)                  # P3 upper out
    lw x15, 16(x3)                 # P3_full base
    add x16, x0, x15               # diagonal tracker
    li x18, 63                     # off-diagonal count row 0
    li x19, 2080                   # diagonal stride (65 x 32)

    loopi 63, 13                   # rows 0..62
        bn.lid x23, 0(x16)         # w6 = P3_full[r][r]
        bn.sid x23, 0(x10++)
        addi x20, x16, 32          # P3_full[r][r+1]
        add x21, x16, x29          # P3_full[r+1][r]
        loop x18, 6
            bn.lid x23, 0(x20)
            addi x20, x20, 32
            bn.lid x24, 0(x21)
            add x21, x21, x29
            bn.xor w8, w6, w7
            bn.sid x25, 0(x10++)
        add x16, x16, x19
        addi x18, x18, -1

    bn.lid x23, 0(x16)             # row 63 diagonal only
    bn.sid x23, 0(x10++)
#endif

    lw x1, 12(x3)
#ifdef GF_INSTRUCTIONS
    li x30, 32
#else
    li x30, 131104
#endif
    add x2, x2, x30
#ifdef GF_INSTRUCTIONS
    csrrw x0, mod1, x0              # force mod1=0 on exit (HW cursor leaves mod1=32)
#endif
    ret

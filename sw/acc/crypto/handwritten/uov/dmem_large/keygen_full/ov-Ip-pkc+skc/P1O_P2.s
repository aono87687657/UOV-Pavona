/* P1O_P2 (Ip keygen) - compute P1*O + P2 over GF(256), V=68, O=44, M=44.
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW gf256 multiply + SW T-table AES
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8 + SW AES via bn.gfmul (aes128_keygen)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8 + inline bn.aes128.*
 *
 * HW tiers carry the hi GF-MAC chain in ACCH (bn.gfmul.8.acch) so the per-element
 * bn.wsrw acc spill is dropped: low chain w8 -> ACC, hi chain w9 -> ACCH.
 */

#if defined(AES_INSTRUCTIONS) && defined(GF_INSTRUCTIONS)

/* bngfaes (HW bn.gfmul.8 + inline bn.aes128.*) */
.section .text
.global P1O_P2
.balign 4
# P1O_P2: Compute (P1*O + P2) for UOV Ip (GF256, V=68, O=44, M=44)
# Dual-chain: w8 = lo bytes 0-31 (ACC chain), w9 = hi bytes 32-43 (ACCH chain).
# Order load-bearing: .acc reads mod1 cursor before .acch.inc advances it.
#
# Args:
#   x10 = result addr (68x44 x 64B = 191,488B)
#   x11 = AES-128 key addr (32B aligned)
#   x12 = O matrix addr (68x44 bytes column-major, 3008B padded)
#
# Stack layout (9888B total, grows down from x2):
#   x3 = frame (32B): saved x10, x11, x12, x1, buffer ptrs
#   O aligned buf (4224B = 44 cols x 96B)
#   P1 buffer (5120B = 10 batches x 8 entries x 64B, use 68 of 80)
#   P2 buffer (512B = 1 batch x 8 entries x 64B, circular)

P1O_P2:
    # Prologue
    bn.xor w31, w31, w31                    # w31 = 0
    li x31, 0x11b                           # GF(2^8) modulus
    csrrw x0, mod0, x31                     # set mod0

    addi x2, x2, -32                        # allocate frame
    add x3, x0, x2                          # x3 = frame ptr
    sw x10, 0(x3)                           # save result addr
    sw x11, 4(x3)                           # save AES key addr
    sw x12, 8(x3)                           # save O matrix addr
    sw x1, 12(x3)                           # save return addr

    li x30, 4224                            # O aligned buf (44 cols x 96B)
    sub x2, x2, x30
    sw x2, 16(x3)                           # save O buf addr

    li x30, 5120                            # P1 buf (10 batches x 8 x 64B max)
    sub x2, x2, x30
    sw x2, 20(x3)                           # save P1 buf addr

    li x30, 512                             # P2 buf (1 batch x 8 x 64B)
    sub x2, x2, x30
    sw x2, 24(x3)                           # save P2 buf addr

    # O Matrix Alignment Copy
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    lw x11, 16(x3)                          # O aligned dest base
    li x9, 17                               # WDR idx for w17 (temp)
    li x29, 1                               # WDR idx for w1
    li x30, 2                               # WDR idx for w2

    loopi 5, 57                             # 5 full batches x 8 cols = 40 cols
        li x8, 0                            # WDR load idx
        loopi 17, 2                         # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)                   # w0
        bn.sid x29, 32(x11)                 # w1
        bn.sid x30, 64(x11)                 # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128          # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128         # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                                # WDR load idx
    loopi 9, 2                              # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)                       # w0
    bn.sid x29, 32(x11)                     # w1
    bn.sid x30, 64(x11)                     # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96              # hi
    bn.sid x9, 64(x11)

    # AES-128 Key Schedule
    lw x11, 4(x3)                           # reload AES key addr
    li x31, 30                              # WDR idx w30
    bn.lid x31, 0(x11)                      # w30 = AES key
    bn.aes128.kf w29, w30, 1                # round keys 1-10
    bn.aes128.kf w28, w29, 2
    bn.aes128.kf w27, w28, 3
    bn.aes128.kf w26, w27, 4
    bn.aes128.kf w25, w26, 5
    bn.aes128.kf w24, w25, 6
    bn.aes128.kf w23, w24, 7
    bn.aes128.kf w22, w23, 8
    bn.aes128.kf w21, w22, 9
    bn.aes128.kf w20, w21, 10

    # P1 IV (w18): counters [1 | 0]
    bn.addi w18, w31, 1                     # 1
    bn.rshi w18, w18, w31 >> 32             # 1 at bit 224 (upper ctr=1)

    # IV Increment (w19): +2 per step
    bn.addi w19, w31, 2                     # 2
    bn.or w19, w19, w19 << 128              # dup to upper half
    bn.rshi w19, w19, w31 >> 160            # position at ctr bits

    # P2 IV set in phase 2

    # Hi Mask (w13): lower 96 bits = 1s
    bn.not w13, w31                         # all ones
    bn.rshi w13, w31, w13 >> 160            # keep lower 96 bits

    # GPR Constants
    li x31, 31                              # w31 (zero)
    li x4, 0                                # w0
    li x5, 1                                # w1
    li x6, 9                                # w9
    li x16, 11                              # w11 (repack temp)
    li x23, 6                               # w6 (P1 lo)
    li x24, 7                               # w7 (P1 hi)
    li x25, 8                               # w8 (result lo)
    li x26, 3                               # w3 (O col j lo)
    li x27, 4                               # w4 (O col j mid)
    li x28, 5                               # w5 (O col j hi)
    li x17, 14                              # w14 (O col j+1 lo)
    li x20, 15                              # w15 (O col j+1 mid)
    li x21, 16                              # w16 (O col j+1 hi)
    li x22, 10                              # w10 (col j+1 lo acc)

    # Phase 2: Direct store P2 for all 2992 entries (68 rows x 44 cols)
    # P2 IV = 22 x 293 = 6446 (batch containing P1/P2 boundary)
    bn.addi w1, w31, 22                     # 22 counters per batch
    bn.addi w0, w31, 293                    # floor(2346/8)
    bn.mulqacc.wo.z w1, w1.0, w0.0, 0      # w1 = 6446
    bn.addi w18, w1, 1                      # 6447
    bn.or w18, w1, w18 << 128              # [6447 | 6446]
    bn.rshi w18, w18, w31 >> 160           # counter position

    # Expand first P2 batch and set starting index
    lw x11, 24(x3)                          # P2 buf write ptr
    jal x1, expand_batch               # 8 entries -> P2 buf
    li x9, 2                                # skip 2 P1 entries -> start at entry 2

    # Direct store all 2992 P2 entries
    lw x10, 0(x3)                           # result addr
    li x7, 2992
    loop x7, 14
        slli x8, x9, 6                     # buf offset = idx x 64
        lw x15, 24(x3)                     # buf base
        add x15, x15, x8                   # buf addr
        bn.lid x4, 0(x15)                  # w0 = P2 lo
        bn.lid x5, 32(x15)                 # w1 = P2 hi
        bn.sid x4, 0(x10)                  # store P2 lo
        bn.sid x5, 32(x10)                 # store P2 hi
        addi x9, x9, 1                     # advance batch idx
        li x8, 8
        bne x9, x8, skip_p2_store     # not exhausted -> skip
        lw x11, 24(x3)                     # reset buf write ptr
        jal x1, expand_batch          # refill buffer
        li x9, 0                           # reset idx
    skip_p2_store:
        addi x10, x10, 64                  # advance result ptr

    # Phase 3: P1*O row 0 (no skip, 68 elements)
    # Reset P1 IV to starting counter [1 | 0]
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    # Expand 9 P1 batches (72 entries, use 68)
    lw x11, 20(x3)
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch

    # Dot product + XOR for 44 columns
    # K=29: 3 bn.lid + 2 bn.wsrw(zero-init) + 1 lw + 1 csrrw + 3 loopi-headers +
    #        3*4 body insns + 6 fold/store insns + 1 addi = 29
    lw x13, 16(x3)                          # O aligned base
    lw x10, 0(x3)                           # result base (row 0)
    lw x15, 20(x3)                          # P1 buf base (row-invariant, hoisted)
    loopi 44, 29
        bn.lid x26, 0(x13++)               # w3 = O col [0:31]
        bn.lid x27, 0(x13++)               # w4 = O col [32:63]
        bn.lid x28, 0(x13++)               # w5 = O col [64:67+pad]
        bn.wsrw acc, w31                   # ACC = 0  (lo chain)
        bn.wsrw acch, w31                  # ACCH = 0 (hi chain)
        add x14, x0, x15                   # reset P1 buf read ptr (x15 hoisted)
        # Order: low .acc reads mod1 cursor BEFORE high .acch.inc advances it.
        csrrw x0, mod1, x0                 # seg1: mod1=0
        loopi 32, 4                         # P1 elems 0..31, scalar w3
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4                         # P1 elems 32..63, scalar w4 (cursor wrapped 32->0)
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 4, 4                          # P1 elems 64..67, scalar w5 (cursor wrapped 32->0)
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        # Load P2 from result, XOR with P1*O, store back
        bn.lid x23, 0(x10)                 # w6 = P2 lo
        bn.lid x24, 32(x10)                # w7 = P2 hi
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x10)                 # store lo
        bn.sid x6, 32(x10)                 # store hi
        addi x10, x10, 64

    # row 0 used the mod1 cursor; reset to 0 for Phase 4 (byte0-indexed gfmul)
    csrrw x0, mod1, x0
    # Phase 4: P1*O rows 1-66 (with skip)
    # each row: redo IV from running element count.
    # x9 = running P1 element index (68 after row 0)
    # x15 = offset in batch (x9 & 7)
    # expand 9 batches from batch-aligned start, read from offset.
    li x9, 68                               # row 0 used 68 elements
    li x7, 1                                # current row

    # Phase 4: mod1 byte-cursor + bn.gfmul.8.acc/acch.inc (no rshi). row r dot starts at O[r].
    # 3 bands by start reg. per-row setup lives in phase4_row_setup.
    # x7 (row) and x9 (running elem idx) keep going across all 3 bands.

    # Band 1: rows 1..31 -> start in w3[r], then full w4, then w5 tail.
    # K=37: 1 jal + 1 lw + 1 addi + loopi(44,29) header+body(29) + 4 trailing = 37
    loopi 31, 37
        jal  x1, phase4_row_setup     # sets x8=68-r, x13=O base, 28(x3)=P1 ptr
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x20, x8, -36                   # x20 = 32-r (w3 elems: O[r..31])
        # K=29: 3 bn.lid + 2 bn.wsrw + 1 lw + 1 csrrw + loop(x20,4)hdr+body +
        #        loopi(32,4)hdr+body + loopi(4,4)hdr+body +
        #        6 fold/store + 1 addi = 29
        loopi 44, 29
            bn.lid x26, 0(x13++)           # w3 = O col [0:31]
            bn.lid x27, 0(x13++)           # w4 = O col [32:63]
            bn.lid x28, 0(x13++)           # w5 = O col [64:67+pad]
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15                 # adjusted P1 read ptr
            csrrw x0, mod1, x7             # cursor = O[r]
            loop x20, 4                     # w3: O[r..31]
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w3
                bn.gfmul.8.acch.inc w9, w7, w3
            loopi 32, 4                     # w4: O[32..63] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 4, 4                      # w5: O[64..67] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)             # P2 fold + store
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8                     # x9 += elements used
        addi x7, x7, 1                      # next row

    # Band 2: rows 32..63 -> start in w4[r-32], then w5 tail.
    # K=33: 1 jal + 1 lw + 2 addi + loopi(44,24)hdr+body(24) + 4 trailing = 33
    loopi 32, 33
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x21, x7, -32                   # start mod1 = r-32
        addi x20, x8, -4                    # x20 = 64-r (w4 elems: O[r..63])
        # K=24: 3 bn.lid + 2 bn.wsrw + 1 lw + 1 csrrw + loop(x20,4)hdr+body +
        #        loopi(4,4)hdr+body + 6 fold/store + 1 addi = 24
        loopi 44, 24
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15
            csrrw x0, mod1, x21            # cursor = O[r] in w4
            loop x20, 4                     # w4: O[r..63]
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 4, 4                      # w5: O[64..67] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    # Band 3: rows 64..67 -> start in w5[r-64].
    # K=26: 1 jal + 1 addi + loopi(44,19)hdr+body(19) + 4 trailing = 26
    loopi 4, 27
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x21, x7, -64                   # start mod1 = r-64
        # K=19: 3 bn.lid + 2 bn.wsrw + 1 lw + 1 csrrw + loop(x8,4)hdr+body +
        #        4 fold/store + 1 addi = 19
        loopi 44, 19
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15
            csrrw x0, mod1, x21            # cursor = O[r] in w5
            loop x8, 4                      # w5: O[r..67]  (x8 = 68-r)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    csrrw x0, mod1, x0                      # Phase 4 wrote mod1; reset to 0 (clean state)

    # Epilogue
    lw x1, 12(x3)                           # restore return addr
    addi x3, x3, 32                         # x3 was x2 - 32 at entry
    add x2, x0, x3                          # restore stack ptr
    ret

# expand_batch: Expand 8 entries (44B each) from AES-CTR stream (bngfaes tier)
#
# In:  w18 = current IV, x11 = buffer write ptr, x16 = 11 (repack bn.sid idx -
#      a wrong x16 silently stores the wrong WDR), w13 = hi mask, w19 = IV inc,
#      w20-w30 = RKs, w31 = 0
# Out: w18 += 22, x11 += 512 (8 entries x 64B) written to buffer
# Clobbers: w0-w11; preserves w12-w31 (w18 advances) + all GPRs except x1, x11
expand_batch:
    # AES-CTR: 11 parallel blocks
    bn.aes128.encz.swap w0, w18, w30        # block 0
    bn.add w18, w18, w19                    # IV += 2
    bn.aes128.encz.swap w1, w18, w30        # block 1
    bn.add w18, w18, w19
    bn.aes128.encz.swap w2, w18, w30        # block 2
    bn.add w18, w18, w19
    bn.aes128.encz.swap w3, w18, w30        # block 3
    bn.add w18, w18, w19
    bn.aes128.encz.swap w4, w18, w30        # block 4
    bn.add w18, w18, w19
    bn.aes128.encz.swap w5, w18, w30        # block 5
    bn.add w18, w18, w19
    bn.aes128.encz.swap w6, w18, w30        # block 6
    bn.add w18, w18, w19
    bn.aes128.encz.swap w7, w18, w30        # block 7
    bn.add w18, w18, w19
    bn.aes128.encz.swap w8, w18, w30        # block 8
    bn.add w18, w18, w19
    bn.aes128.encz.swap w9, w18, w30        # block 9
    bn.add w18, w18, w19
    bn.aes128.encz.swap w10, w18, w30       # block 10
    bn.add w18, w18, w19
    # Round 1
    bn.aes128.encm w0, w0, w29
    bn.aes128.encm w1, w1, w29
    bn.aes128.encm w2, w2, w29
    bn.aes128.encm w3, w3, w29
    bn.aes128.encm w4, w4, w29
    bn.aes128.encm w5, w5, w29
    bn.aes128.encm w6, w6, w29
    bn.aes128.encm w7, w7, w29
    bn.aes128.encm w8, w8, w29
    bn.aes128.encm w9, w9, w29
    bn.aes128.encm w10, w10, w29
    # Round 2
    bn.aes128.encm w0, w0, w28
    bn.aes128.encm w1, w1, w28
    bn.aes128.encm w2, w2, w28
    bn.aes128.encm w3, w3, w28
    bn.aes128.encm w4, w4, w28
    bn.aes128.encm w5, w5, w28
    bn.aes128.encm w6, w6, w28
    bn.aes128.encm w7, w7, w28
    bn.aes128.encm w8, w8, w28
    bn.aes128.encm w9, w9, w28
    bn.aes128.encm w10, w10, w28
    # Round 3
    bn.aes128.encm w0, w0, w27
    bn.aes128.encm w1, w1, w27
    bn.aes128.encm w2, w2, w27
    bn.aes128.encm w3, w3, w27
    bn.aes128.encm w4, w4, w27
    bn.aes128.encm w5, w5, w27
    bn.aes128.encm w6, w6, w27
    bn.aes128.encm w7, w7, w27
    bn.aes128.encm w8, w8, w27
    bn.aes128.encm w9, w9, w27
    bn.aes128.encm w10, w10, w27
    # Round 4
    bn.aes128.encm w0, w0, w26
    bn.aes128.encm w1, w1, w26
    bn.aes128.encm w2, w2, w26
    bn.aes128.encm w3, w3, w26
    bn.aes128.encm w4, w4, w26
    bn.aes128.encm w5, w5, w26
    bn.aes128.encm w6, w6, w26
    bn.aes128.encm w7, w7, w26
    bn.aes128.encm w8, w8, w26
    bn.aes128.encm w9, w9, w26
    bn.aes128.encm w10, w10, w26
    # Round 5
    bn.aes128.encm w0, w0, w25
    bn.aes128.encm w1, w1, w25
    bn.aes128.encm w2, w2, w25
    bn.aes128.encm w3, w3, w25
    bn.aes128.encm w4, w4, w25
    bn.aes128.encm w5, w5, w25
    bn.aes128.encm w6, w6, w25
    bn.aes128.encm w7, w7, w25
    bn.aes128.encm w8, w8, w25
    bn.aes128.encm w9, w9, w25
    bn.aes128.encm w10, w10, w25
    # Round 6
    bn.aes128.encm w0, w0, w24
    bn.aes128.encm w1, w1, w24
    bn.aes128.encm w2, w2, w24
    bn.aes128.encm w3, w3, w24
    bn.aes128.encm w4, w4, w24
    bn.aes128.encm w5, w5, w24
    bn.aes128.encm w6, w6, w24
    bn.aes128.encm w7, w7, w24
    bn.aes128.encm w8, w8, w24
    bn.aes128.encm w9, w9, w24
    bn.aes128.encm w10, w10, w24
    # Round 7
    bn.aes128.encm w0, w0, w23
    bn.aes128.encm w1, w1, w23
    bn.aes128.encm w2, w2, w23
    bn.aes128.encm w3, w3, w23
    bn.aes128.encm w4, w4, w23
    bn.aes128.encm w5, w5, w23
    bn.aes128.encm w6, w6, w23
    bn.aes128.encm w7, w7, w23
    bn.aes128.encm w8, w8, w23
    bn.aes128.encm w9, w9, w23
    bn.aes128.encm w10, w10, w23
    # Round 8
    bn.aes128.encm w0, w0, w22
    bn.aes128.encm w1, w1, w22
    bn.aes128.encm w2, w2, w22
    bn.aes128.encm w3, w3, w22
    bn.aes128.encm w4, w4, w22
    bn.aes128.encm w5, w5, w22
    bn.aes128.encm w6, w6, w22
    bn.aes128.encm w7, w7, w22
    bn.aes128.encm w8, w8, w22
    bn.aes128.encm w9, w9, w22
    bn.aes128.encm w10, w10, w22
    # Round 9
    bn.aes128.encm w0, w0, w21
    bn.aes128.encm w1, w1, w21
    bn.aes128.encm w2, w2, w21
    bn.aes128.encm w3, w3, w21
    bn.aes128.encm w4, w4, w21
    bn.aes128.encm w5, w5, w21
    bn.aes128.encm w6, w6, w21
    bn.aes128.encm w7, w7, w21
    bn.aes128.encm w8, w8, w21
    bn.aes128.encm w9, w9, w21
    bn.aes128.encm w10, w10, w21
    # Final round
    bn.aes128.encf w0, w0, w20
    bn.aes128.encf w1, w1, w20
    bn.aes128.encf w2, w2, w20
    bn.aes128.encf w3, w3, w20
    bn.aes128.encf w4, w4, w20
    bn.aes128.encf w5, w5, w20
    bn.aes128.encf w6, w6, w20
    bn.aes128.encf w7, w7, w20
    bn.aes128.encf w8, w8, w20
    bn.aes128.encf w9, w9, w20
    bn.aes128.encf w10, w10, w20

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.mov w11, w0                          # lo = w0
    bn.sid x16, 0(x11++)                    # store lo, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sid x16, 0(x11++)                    # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.and w11, w11, w13                    # mask (redundant but consistent)
    bn.sid x16, 0(x11++)

    ret

#elif defined(GF_INSTRUCTIONS)

/* bngfonly (HW bn.gfmul.8 + aes128_keygen jal) */
.section .text
.global P1O_P2
.balign 4
# P1O_P2: Compute (P1*O + P2) for UOV Ip (GF256, V=68, O=44, M=44)
# Dual-chain: w8 = lo bytes 0-31 (ACC chain), w9 = hi bytes 32-43 (ACCH chain).
# Order load-bearing: .acc reads mod1 cursor before .acch.inc advances it.
#
# Args:
#   x10 = result addr (68x44 x 64B = 191,488B)
#   x11 = AES-128 key addr (32B aligned)
#   x12 = O matrix addr (68x44 bytes column-major, 3008B padded)
#
# Stack layout (9888B total, grows down from x2):
#   x3 = frame (32B): saved x10, x11, x12, x1, buffer ptrs
#   O aligned buf (4224B = 44 cols x 96B)
#   P1 buffer (5120B = 10 batches x 8 entries x 64B, use 68 of 80)
#   P2 buffer (512B = 1 batch x 8 entries x 64B, circular)

P1O_P2:
    # Prologue
    bn.xor w31, w31, w31                    # w31 = 0
    li x31, 0x11b                           # GF(2^8) modulus
    csrrw x0, mod0, x31                     # set mod0

    addi x2, x2, -32                        # allocate frame
    add x3, x0, x2                          # x3 = frame ptr
    sw x10, 0(x3)                           # save result addr
    sw x11, 4(x3)                           # save AES key addr
    sw x12, 8(x3)                           # save O matrix addr
    sw x1, 12(x3)                           # save return addr

    li x30, 4224                            # O aligned buf (44 cols x 96B)
    sub x2, x2, x30
    sw x2, 16(x3)                           # save O buf addr

    li x30, 5120                            # P1 buf (10 batches x 8 x 64B max)
    sub x2, x2, x30
    sw x2, 20(x3)                           # save P1 buf addr

    li x30, 512                             # P2 buf (1 batch x 8 x 64B)
    sub x2, x2, x30
    sw x2, 24(x3)                           # save P2 buf addr

    # O Matrix Alignment Copy
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    lw x11, 16(x3)                          # O aligned dest base
    li x9, 17                               # WDR idx for w17 (temp)
    li x29, 1                               # WDR idx for w1
    li x30, 2                               # WDR idx for w2

    loopi 5, 57                             # 5 full batches x 8 cols = 40 cols
        li x8, 0                            # WDR load idx
        loopi 17, 2                         # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)                   # w0
        bn.sid x29, 32(x11)                 # w1
        bn.sid x30, 64(x11)                 # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128          # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128         # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                                # WDR load idx
    loopi 9, 2                              # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)                       # w0
    bn.sid x29, 32(x11)                     # w1
    bn.sid x30, 64(x11)                     # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96              # hi
    bn.sid x9, 64(x11)

    # AES-128 Key Schedule (BNGFONLY: SW KS via KeySchedule_keygen)
    lw x11, 4(x3)                           # reload AES key addr
    li x31, 30                              # WDR idx w30
    bn.lid x31, 0(x11)                      # w30 = AES key

    # Load AES constants (aes_constants_keygen provides .data labels)
    la x13, affine_value
    li x6, 8
    bn.lid x6, 0(x13)                       # w8 = affine_value (0x63..63)
    la x14, msb_mask
    li x6, 9
    bn.lid x6, 0(x14)                       # w9 = msb_mask (0x80..80)
    la x15, rcon
    li x6, 11
    bn.lid x6, 0(x15)                       # w11 = rcon

    # Prime w17 then dual-store w30
    bn.mov w17, w30                         # w17 = key | 0
    bn.or w30, w30, w30 << 128              # w30 = key | key (dual-stored RK0)

    # 10 SW KeySchedule_keygen calls produce RK1..RK10 in w20..w29 (FORWARD layout)
    # Helper clobbers w7, w12..w16; preserves w8, w9, w11, w17 across calls.
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
    bn.or  w29, w29, w29 << 128             # RK10 dual-store w29

    # P1 IV (w18): counters [1 | 0]
    bn.addi w18, w31, 1                     # 1
    bn.rshi w18, w18, w31 >> 32             # 1 at bit 224 (upper ctr=1)

    # IV Increment (w19): +2 per step
    bn.addi w19, w31, 2                     # 2
    bn.or w19, w19, w19 << 128              # dup to upper half
    bn.rshi w19, w19, w31 >> 160            # position at ctr bits

    # P2 IV set in phase 2

    # Hi Mask (w13): lower 96 bits = 1s
    bn.not w13, w31                         # all ones
    bn.rshi w13, w31, w13 >> 160            # keep lower 96 bits

    # GPR Constants
    li x31, 31                              # w31 (zero)
    li x4, 0                                # w0
    li x5, 1                                # w1
    li x6, 9                                # w9
    li x16, 11                              # w11 (repack temp)
    li x23, 6                               # w6 (P1 lo)
    li x24, 7                               # w7 (P1 hi)
    li x25, 8                               # w8 (result lo)
    li x26, 3                               # w3 (O col j lo)
    li x27, 4                               # w4 (O col j mid)
    li x28, 5                               # w5 (O col j hi)
    li x17, 14                              # w14 (O col j+1 lo)
    li x20, 15                              # w15 (O col j+1 mid)
    li x21, 16                              # w16 (O col j+1 hi)
    li x22, 10                              # w10 (col j+1 lo acc)

    # Phase 2: Direct store P2 for all 2992 entries (68 rows x 44 cols)
    # P2 IV = 22 x 293 = 6446 (batch containing P1/P2 boundary)
    bn.addi w1, w31, 22                     # 22 counters per batch
    bn.addi w0, w31, 293                    # floor(2346/8)
    bn.mulqacc.wo.z w1, w1.0, w0.0, 0      # w1 = 6446
    bn.addi w18, w1, 1                      # 6447
    bn.or w18, w1, w18 << 128              # [6447 | 6446]
    bn.rshi w18, w18, w31 >> 160           # counter position

    # Expand first P2 batch and set starting index
    lw x11, 24(x3)                          # P2 buf write ptr
    jal x1, expand_batch              # 8 entries -> P2 buf
    li x9, 2                                # skip 2 P1 entries -> start at entry 2

    # Direct store all 2992 P2 entries
    lw x10, 0(x3)                           # result addr
    li x7, 2992
    loop x7, 14
        slli x8, x9, 6                     # buf offset = idx x 64
        lw x15, 24(x3)                     # buf base
        add x15, x15, x8                   # buf addr
        bn.lid x4, 0(x15)                  # w0 = P2 lo
        bn.lid x5, 32(x15)                 # w1 = P2 hi
        bn.sid x4, 0(x10)                  # store P2 lo
        bn.sid x5, 32(x10)                 # store P2 hi
        addi x9, x9, 1                     # advance batch idx
        li x8, 8
        bne x9, x8, skip_p2_store    # not exhausted -> skip
        lw x11, 24(x3)                     # reset buf write ptr
        jal x1, expand_batch          # refill buffer
        li x9, 0                           # reset idx
    skip_p2_store:
        addi x10, x10, 64                  # advance result ptr

    # Phase 3: P1*O row 0 (no skip, 68 elements)
    # Reset P1 IV to starting counter [1 | 0]
    bn.addi w18, w31, 1
    bn.rshi w18, w18, w31 >> 32

    # Expand 9 P1 batches (72 entries, use 68)
    lw x11, 20(x3)
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch

    # Dot product + XOR for 44 columns
    # K=29: 3 bn.lid + 2 bn.wsrw(zero-init) + 1 lw + 1 csrrw + 3 loopi-headers +
    #        3*4 body insns + 6 fold/store insns + 1 addi = 29
    lw x13, 16(x3)                          # O aligned base
    lw x10, 0(x3)                           # result base (row 0)
    lw x15, 20(x3)                          # P1 buf base (row-invariant, hoisted)
    loopi 44, 29
        bn.lid x26, 0(x13++)               # w3 = O col [0:31]
        bn.lid x27, 0(x13++)               # w4 = O col [32:63]
        bn.lid x28, 0(x13++)               # w5 = O col [64:67+pad]
        bn.wsrw acc, w31                   # ACC = 0  (lo chain)
        bn.wsrw acch, w31                  # ACCH = 0 (hi chain)
        add x14, x0, x15                   # reset P1 buf read ptr (x15 hoisted)
        # Order: low .acc reads mod1 cursor BEFORE high .acch.inc advances it.
        csrrw x0, mod1, x0                 # seg1: mod1=0
        loopi 32, 4                         # P1 elems 0..31, scalar w3
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w3
            bn.gfmul.8.acch.inc w9, w7, w3
        loopi 32, 4                         # P1 elems 32..63, scalar w4 (cursor wrapped 32->0)
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w4
            bn.gfmul.8.acch.inc w9, w7, w4
        loopi 4, 4                          # P1 elems 64..67, scalar w5 (cursor wrapped 32->0)
            bn.lid x23, 0(x14++)
            bn.lid x24, 0(x14++)
            bn.gfmul.8.acc w8, w6, w5
            bn.gfmul.8.acch.inc w9, w7, w5
        # Load P2 from result, XOR with P1*O, store back
        bn.lid x23, 0(x10)                 # w6 = P2 lo
        bn.lid x24, 32(x10)                # w7 = P2 hi
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x10)                 # store lo
        bn.sid x6, 32(x10)                 # store hi
        addi x10, x10, 64

    # row 0 used the mod1 cursor; reset to 0 for Phase 4 (byte0-indexed gfmul)
    csrrw x0, mod1, x0
    # Phase 4: P1*O rows 1-66 (with skip)
    li x9, 68                               # row 0 used 68 elements
    li x7, 1                                # current row

    # Band 1: rows 1..31 -> start in w3[r], then full w4, then w5 tail.
    loopi 31, 37
        jal  x1, phase4_row_setup     # sets x8=68-r, x13=O base, 28(x3)=P1 ptr
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x20, x8, -36                   # x20 = 32-r (w3 elems: O[r..31])
        loopi 44, 29
            bn.lid x26, 0(x13++)           # w3 = O col [0:31]
            bn.lid x27, 0(x13++)           # w4 = O col [32:63]
            bn.lid x28, 0(x13++)           # w5 = O col [64:67+pad]
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15                 # adjusted P1 read ptr
            csrrw x0, mod1, x7             # cursor = O[r]
            loop x20, 4                     # w3: O[r..31]
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w3
                bn.gfmul.8.acch.inc w9, w7, w3
            loopi 32, 4                     # w4: O[32..63] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 4, 4                      # w5: O[64..67] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)             # P2 fold + store
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8                     # x9 += elements used
        addi x7, x7, 1                      # next row

    # Band 2: rows 32..63 -> start in w4[r-32], then w5 tail.
    loopi 32, 33
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x21, x7, -32                   # start mod1 = r-32
        addi x20, x8, -4                    # x20 = 64-r (w4 elems: O[r..63])
        loopi 44, 24
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15
            csrrw x0, mod1, x21            # cursor = O[r] in w4
            loop x20, 4                     # w4: O[r..63]
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w4
                bn.gfmul.8.acch.inc w9, w7, w4
            loopi 4, 4                      # w5: O[64..67] (cursor wrapped 32->0)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    # Band 3: rows 64..67 -> start in w5[r-64].
    loopi 4, 27
        jal  x1, phase4_row_setup
        lw   x15, 28(x3)                    # adjusted P1 ptr (row-invariant, hoisted)
        addi x21, x7, -64                   # start mod1 = r-64
        loopi 44, 19
            bn.lid x26, 0(x13++)
            bn.lid x27, 0(x13++)
            bn.lid x28, 0(x13++)
            bn.wsrw acc, w31               # ACC = 0  (lo chain)
            bn.wsrw acch, w31              # ACCH = 0 (hi chain)
            add x14, x0, x15
            csrrw x0, mod1, x21            # cursor = O[r] in w5
            loop x8, 4                      # w5: O[r..67]  (x8 = 68-r)
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.gfmul.8.acc w8, w6, w5
                bn.gfmul.8.acch.inc w9, w7, w5
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64
        li   x8, 68
        sub  x8, x8, x7
        add  x9, x9, x8
        addi x7, x7, 1

    csrrw x0, mod1, x0                      # Phase 4 wrote mod1; reset to 0 (clean state)

    # Epilogue
    lw x1, 12(x3)                           # restore return addr
    addi x3, x3, 32                         # x3 was x2 - 32 at entry
    add x2, x0, x3                          # restore stack ptr
    ret

# expand_batch: Expand 8 entries (44B each) from AES-CTR stream (bngfonly tier)
#
# In:  w18 = current IV, x11 = buffer write ptr, w19 = IV inc, w31 = 0
# Out: w18 += 22, x11 += 512 (8 entries x 64B) written to buffer
# Clobbers: w0-w17 (aes128_keygen w1/w10-w17 + staging), x18, x19 (via
# aes128_keygen); leaves mod0 = 0x11B; preserves other GPRs except x1, x11
expand_batch:
    # BNGFONLY AES-CTR: 11 sequential aes128_keygen calls
    # Each aes128_keygen returns dual-block ciphertext in w2 (32 B = 2 x 16 B).
    # 11 dual-block calls x 32 B = 352 B keystream (= 22 single AES blocks, matches w18 += 22 contract).
    # Helper clobbers w1, w10..w17 internally, so we stage outputs to DMEM,
    # then reload w0..w10 for the existing repack code.
    addi x2, x2, -384                       # alloc 352 B staging + 32 B for caller-save slack
    sw x6, 360(x2)                          # save caller x6 (= 9 for w9 stores)
    addi x12, x2, 0                         # x12 = staging buf base ptr

    # Reload AES constants (caller's outer dot-product loop may clobber w7/w8/w9)
    la x6, affine_value
    li x14, 8
    bn.lid x14, 0(x6)                       # w8 = affine_value
    la x6, msb_mask
    li x14, 9
    bn.lid x14, 0(x6)                       # w9 = msb_mask
    la x6, byte_swap_mask
    li x14, 7
    bn.lid x14, 0(x6)                       # w7 = byte_swap_mask

    # 11 aes128_keygen calls; each writes dual-block ciphertext to w2.
    # IV advances by w19 (=+2) per call.
    li x6, 2                                # WDR idx 2 (w2)
    jal x1, aes128_keygen
    bn.sid x6, 0(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 32(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 64(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 96(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 128(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 160(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 192(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 224(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 256(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 288(x12)
    bn.add w18, w18, w19
    jal x1, aes128_keygen
    bn.sid x6, 320(x12)
    bn.add w18, w18, w19

    # Reload 11 dual-block ciphertexts (352 B) into w0..w10 for the repack.
    li x14, 0
    bn.lid x14, 0(x12)
    li x14, 1
    bn.lid x14, 32(x12)
    li x14, 2
    bn.lid x14, 64(x12)
    li x14, 3
    bn.lid x14, 96(x12)
    li x14, 4
    bn.lid x14, 128(x12)
    li x14, 5
    bn.lid x14, 160(x12)
    li x14, 6
    bn.lid x14, 192(x12)
    li x14, 7
    bn.lid x14, 224(x12)
    li x14, 8
    bn.lid x14, 256(x12)
    li x14, 9
    bn.lid x14, 288(x12)
    li x14, 10
    bn.lid x14, 320(x12)

    # Rebuild w13 = mask96 (aes128_keygen uses w12..w17 as scratch; w13 was clobbered)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160

    lw x6, 360(x2)                          # restore caller x6 (= 9)
    addi x2, x2, 384                        # free staging buffer

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.mov w11, w0                          # lo = w0
    bn.sid x16, 0(x11++)                    # store lo, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sid x16, 0(x11++)                    # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.and w11, w11, w13                    # mask (redundant but consistent)
    bn.sid x16, 0(x11++)

    ret

#else

/* sw (SW gf256 + T-table AES) */
.section .text
.global P1O_P2
.balign 4
# P1O_P2: Compute (P1*O + P2) for UOV Ip (GF256, V=68, O=44, M=44)
#
# Args:
#   x10 = result addr (68x44 x 64B = 191,488B)
#   x11 = AES-128 key addr (32B aligned)
#   x12 = O matrix addr (68x44 bytes column-major, 3008B padded)
#
# Stack layout (10,112B total, grows down from x2; +416B transient staging mid-function):
#   x3 = frame (64B): saved x10, x11, x12, x1, buffer ptrs
#   O aligned buf (4224B = 44 cols x 96B)
#   P1 buffer (5120B = 10 batches x 8 entries x 64B, use 68 of 80)
#   P2 buffer (512B = 1 batch x 8 entries x 64B, circular)
#   RK buf (192B = 11 RKs x 16B, padded to 32B alignment)

P1O_P2:
    # Prologue
    bn.xor w31, w31, w31                    # w31 = 0
    li x31, 0x11b                           # GF(2^8) modulus (also AES poly; aes128table_352 doesn't touch mod0)
    csrrw x0, mod0, x31                     # set mod0

    addi x2, x2, -64                        # allocate 64 B frame (32-B aligned for subsequent WDR-aligned bufs; slots 0..32 used)
    add x3, x0, x2                          # x3 = frame ptr
    sw x10, 0(x3)                           # save result addr
    sw x11, 4(x3)                           # save AES key addr (pk_seed)
    sw x12, 8(x3)                           # save O matrix addr
    sw x1, 12(x3)                           # save return addr

    li x30, 4224                            # O aligned buf (44 cols x 96B)
    sub x2, x2, x30
    sw x2, 16(x3)                           # save O buf addr

    li x30, 5120                            # P1 buf (10 batches x 8 x 64B max)
    sub x2, x2, x30
    sw x2, 20(x3)                           # save P1 buf addr

    li x30, 512                             # P2 buf (1 batch x 8 x 64B)
    sub x2, x2, x30
    sw x2, 24(x3)                           # save P2 buf addr

    li x30, 192                             # SW AES round-key buf (176 B = 11 RKs x 16 B, padded to 32 B-aligned 192)
    sub x2, x2, x30
    sw x2, 32(x3)                           # save RK buf addr (slot 28 reserved for Phase 4 P1 read ptr)

    # SW AES key schedule: pk_seed -> 11 round keys at *(slot 32) buf.
    # AES_128_keyschedule: x10=key_in (preserved), x11=rk_out (advanced past end), x1=link.
    lw x10, 4(x3)                           # x10 = pk_seed addr
    lw x11, 32(x3)                          # x11 = RK buf base
    jal x1, AES_128_keyschedule             # expand into RK buf. Clobbers x5..x8, x12..x18, x29..x31.
    lw x12, 8(x3)                           # restore x12 = O matrix addr (KS clobbered)

    # O Matrix Alignment Copy
    # Copy 44 O columns from 68B stride to 96B-padded (32B-aligned) layout.
    # Batch: load 8 cols (17 WDRs = 544B), extract with rshi, store 3 WDRs/col.
    # x12 = O source (advances), x11 = O aligned dest (advances)
    lw x11, 16(x3)                          # O aligned dest base
    li x9, 17                               # WDR idx for w17 (temp)
    li x29, 1                               # WDR idx for w1
    li x30, 2                               # WDR idx for w2

    loopi 5, 57                             # 5 full batches x 8 cols = 40 cols
        li x8, 0                            # WDR load idx
        loopi 17, 2                         # load 17 WDRs -> w0..w16
            bn.lid x8, 0(x12++)
            addi x8, x8, 1
        # Col +0 (shift=0): w0, w1, w2 direct
        bn.sid x0, 0(x11)                   # w0
        bn.sid x29, 32(x11)                 # w1
        bn.sid x30, 64(x11)                 # w2
        addi x11, x11, 96
        # Col +1 (shift=32)
        bn.rshi w17, w3, w2 >> 32           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w4, w3 >> 32           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w5, w4 >> 32           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +2 (shift=64)
        bn.rshi w17, w5, w4 >> 64           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w6, w5 >> 64           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w7, w6 >> 64           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +3 (shift=96)
        bn.rshi w17, w7, w6 >> 96           # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w8, w7 >> 96           # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w9, w8 >> 96           # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +4 (shift=128)
        bn.rshi w17, w9, w8 >> 128          # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w10, w9 >> 128         # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w11, w10 >> 128        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +5 (shift=160)
        bn.rshi w17, w11, w10 >> 160        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w12, w11 >> 160        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w13, w12 >> 160        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +6 (shift=192)
        bn.rshi w17, w13, w12 >> 192        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w14, w13 >> 192        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w15, w14 >> 192        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96
        # Col +7 (shift=224)
        bn.rshi w17, w15, w14 >> 224        # lo
        bn.sid x9, 0(x11)
        bn.rshi w17, w16, w15 >> 224        # mid
        bn.sid x9, 32(x11)
        bn.rshi w17, w31, w16 >> 224        # hi
        bn.sid x9, 64(x11)
        addi x11, x11, 96

    # Last batch: 4 remaining columns (cols 40-43)
    li x8, 0                                # WDR load idx
    loopi 9, 2                              # load 9 WDRs (272B + padding)
        bn.lid x8, 0(x12++)
        addi x8, x8, 1
    # Col 40 (shift=0)
    bn.sid x0, 0(x11)                       # w0
    bn.sid x29, 32(x11)                     # w1
    bn.sid x30, 64(x11)                     # w2
    addi x11, x11, 96
    # Col 41 (shift=32)
    bn.rshi w17, w3, w2 >> 32              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w4, w3 >> 32              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w5, w4 >> 32              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 42 (shift=64)
    bn.rshi w17, w5, w4 >> 64              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w6, w5 >> 64              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w7, w6 >> 64              # hi
    bn.sid x9, 64(x11)
    addi x11, x11, 96
    # Col 43 (shift=96)
    bn.rshi w17, w7, w6 >> 96              # lo
    bn.sid x9, 0(x11)
    bn.rshi w17, w8, w7 >> 96              # mid
    bn.sid x9, 32(x11)
    bn.rshi w17, w9, w8 >> 96              # hi
    bn.sid x9, 64(x11)

    # AES-128 Key Schedule (SW: SW KS via AES_128_keyschedule done in prologue)
    # SW round keys are already in DMEM (slot 32(x3) RK buf base).
    # No WDR-resident RKs needed (aes128table_352 reads RKs from DMEM via x10).

    # No P1 IV (w18) / IV increment (w19)
    # SWONLY uses x13 = LE 32-bit counter (input/output of aes128table_352),
    # not the dual-block WDR IV that bngfaes/bngfonly use.

    # Hi Mask (w13): lower 96 bits = 1s
    bn.not w13, w31                         # all ones
    bn.rshi w13, w31, w13 >> 160            # keep lower 96 bits

    # GPR Constants
    li x31, 31                              # w31 (zero)
    li x4, 0                                # w0
    li x5, 1                                # w1
    li x6, 9                                # w9
    li x16, 11                              # w11 (repack temp)
    li x23, 6                               # w6 (P1 lo)
    li x24, 7                               # w7 (P1 hi)
    li x25, 8                               # w8 (result lo)
    li x26, 3                               # w3 (O col j lo)
    li x27, 4                               # w4 (O col j mid)
    li x28, 5                               # w5 (O col j hi)
    li x17, 14                              # w14 (O col j+1 lo)
    li x20, 15                              # w15 (O col j+1 mid)
    li x21, 16                              # w16 (O col j+1 hi)
    li x22, 10                              # w10 (col j+1 lo acc)

    # Phase 2: Direct store P2 for all 2992 entries (68 rows x 44 cols)
    # P2 IV = 22 x 293 = 6446 (batch containing P1/P2 boundary)
    li x13, 6446                            # SW: LE counter for aes128table_352 (passed through expand_batch)

    # Expand first P2 batch and set starting index
    lw x11, 24(x3)                          # P2 buf write ptr
    jal x1, expand_batch                    # 8 entries -> P2 buf (x13 advances by 22)
    li x9, 2                                # skip 2 P1 entries -> start at entry 2

    # Direct store all 2992 P2 entries
    lw x10, 0(x3)                           # result addr
    li x7, 2992
    loop x7, 14
        slli x8, x9, 6                     # buf offset = idx x 64
        lw x15, 24(x3)                     # buf base
        add x15, x15, x8                   # buf addr
        bn.lid x4, 0(x15)                  # w0 = P2 lo
        bn.lid x5, 32(x15)                 # w1 = P2 hi
        bn.sid x4, 0(x10)                  # store P2 lo
        bn.sid x5, 32(x10)                 # store P2 hi
        addi x9, x9, 1                     # advance batch idx
        li x8, 8
        bne x9, x8, skip_p2_store          # not exhausted -> skip
        lw x11, 24(x3)                     # reset buf write ptr
        jal x1, expand_batch               # refill buffer
        li x9, 0                           # reset idx
    skip_p2_store:
        addi x10, x10, 64                  # advance result ptr

    # Phase 3: P1*O row 0 (no skip, 68 elements)
    # Reset counter to 0 for P1 expansion (P1 starts at AES-CTR block 0)
    li x13, 0                               # SWONLY counter

    # Expand 9 P1 batches (72 entries, use 68)
    lw x11, 20(x3)
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch
    jal x1, expand_batch

    # SW GF256 helper constants (gf256_macc_dualvec_sw: w16=msb_mask, w17.0=0x1b, w31=0).
    # Set ONCE after Phase 1 O-alignment (which used w16/w17); expand_batch preserves them.
    li x9, 16
    la x14, msb_mask
    bn.lid x9, 0(x14)                       # w16 = 0x80-per-byte mask
    bn.addi w17, w31, 0x1b                  # w17.0 = 0x1b reduction constant
    # Dot product + XOR for 44 columns
    lw x13, 16(x3)                          # O aligned base
    lw x10, 0(x3)                           # result base (row 0)
    loopi 44, 25
        bn.lid x26, 0(x13++)               # w3 = O col [0:31]
        bn.lid x27, 0(x13++)               # w4 = O col [32:63]
        bn.lid x28, 0(x13++)               # w5 = O col [64:67+pad]
        bn.xor w20, w20, w20              # clear lo acc (SW; w20)
        bn.xor w30, w30, w30              # clear hi acc (SW; w30)
        lw x14, 20(x3)                     # reset P1 buf read ptr
        loopi 68, 9                         # all 68 P1 elements
            bn.lid x23, 0(x14++)            # w6 = P1 lo
            bn.lid x24, 0(x14++)            # w7 = P1 hi
            bn.mov w0, w6                  # vec lo
            bn.mov w1, w7                  # vec hi
            bn.mov w19, w3                 # scalar byte0 = O[i][k]
            jal x1, gf256_macc_dualvec_sw  # w20 ^= w0*s ; w30 ^= w1*s
            bn.rshi w3, w4, w3 >> 8
            bn.rshi w4, w5, w4 >> 8
            bn.rshi w5, w31, w5 >> 8
        # SW accs (w20/w30) -> w8/w9 for the P2 XOR
        bn.mov w8, w20
        bn.mov w9, w30
        # Load P2 from result, XOR with P1*O, store back
        bn.lid x23, 0(x10)                 # w6 = P2 lo
        bn.lid x24, 32(x10)                # w7 = P2 hi
        bn.xor w8, w8, w6
        bn.xor w9, w9, w7
        bn.sid x25, 0(x10)                 # store lo
        bn.sid x6, 32(x10)                 # store hi
        addi x10, x10, 64

    # Phase 4: P1*O rows 1-66 (with skip)
    # each row: redo IV from running element count.
    # x9 = running P1 element index (68 after row 0)
    # x15 = offset in batch (x9 & 7)
    # expand 9 batches from batch-aligned start, read from offset.
    li x9, 68                               # row 0 used 68 elements
    li x7, 1                                # current row
    loopi 67, 58                            # SW: body size 58 (single x13 set, no IV; +2 for SW acc moves)
        # Compute batch index and offset
        srli x29, x9, 3                    # batch_idx = x9 / 8
        andi x15, x9, 7                    # offset = x9 % 8

        # Compute AES counter = batch_idx * 22 (22 = 16+4+2)
        slli x30, x29, 4                   # batch*16
        slli x8, x29, 2                    # batch*4
        add x30, x30, x8                   # batch*20
        slli x8, x29, 1                    # batch*2
        add x30, x30, x8                   # x30 = batch*22

        # Set SWONLY counter = batch_idx * 22 (already in x30 from above)
        add x13, x0, x30                   # x13 = counter for aes128table_352

        # Expand ceil((elements + offset) / 8) batches
        li x8, 68
        sub x8, x8, x7                     # elements = 68-r
        add x8, x8, x15                    # elements + offset
        addi x8, x8, 7
        srli x8, x8, 3                     # num batches
        lw x11, 20(x3)                     # reset P1 buf write ptr
        loop x8, 2
            jal x1, expand_batch
            nop

        # Compute read pointer: buf_base + offset*64
        lw x14, 20(x3)                     # buf base
        slli x29, x15, 6                   # offset * 64
        add x14, x14, x29                  # adjusted read start
        sw x14, 28(x3)                     # save adjusted P1 read ptr

        # Precompute element count: 68 - r
        li x8, 68
        sub x8, x8, x7

        # Dot product + XOR for 44 columns
        lw x13, 16(x3)                     # reset O aligned base
        loopi 44, 29
            bn.lid x26, 0(x13++)           # w3 = O col [0:31]
            bn.lid x27, 0(x13++)           # w4 = O col [32:63]
            bn.lid x28, 0(x13++)           # w5 = O col [64:67+pad]
            # Skip r scalars (x7 >= 1, safe for loop)
            loop x7, 3
                bn.rshi w3, w4, w3 >> 8
                bn.rshi w4, w5, w4 >> 8
                bn.rshi w5, w31, w5 >> 8
            bn.xor w20, w20, w20          # clear lo acc (SW; w20)
            bn.xor w30, w30, w30          # clear hi acc (SW; w30)
            lw x14, 28(x3)                 # adjusted P1 read ptr (with offset)
            loop x8, 9                     # (68-r) P1 elements
                bn.lid x23, 0(x14++)
                bn.lid x24, 0(x14++)
                bn.mov w0, w6             # vec lo
                bn.mov w1, w7             # vec hi
                bn.mov w19, w3            # scalar byte0 = O[i][k]
                jal x1, gf256_macc_dualvec_sw  # w20 ^= w0*s ; w30 ^= w1*s
                bn.rshi w3, w4, w3 >> 8
                bn.rshi w4, w5, w4 >> 8
                bn.rshi w5, w31, w5 >> 8
            # SW accs (w20/w30) -> w8/w9 for the P2 XOR
            bn.mov w8, w20
            bn.mov w9, w30
            # Load P2, XOR with P1*O, store back
            bn.lid x23, 0(x10)
            bn.lid x24, 32(x10)
            bn.xor w8, w8, w6
            bn.xor w9, w9, w7
            bn.sid x25, 0(x10)
            bn.sid x6, 32(x10)
            addi x10, x10, 64

        # Update cumulative index and row
        li x8, 68
        sub x8, x8, x7
        add x9, x9, x8                     # x9 += elements used
        addi x7, x7, 1                     # next row

    # Epilogue
    lw x1, 12(x3)                           # restore return addr
    addi x3, x3, 64                         # x3 was x2 - 64 at entry (SWONLY frame: 32 B base + 32 B for 32-aligned padding & RK buf addr slot)
    add x2, x0, x3                          # restore stack ptr
    ret

# expand_batch: Expand 8 entries (44B each) from AES-CTR stream
#
# Input:  w18 = current IV, x11 = buffer write ptr
# Output: w18 += 22, x11 += 512 (8 entries x 64B), entries written to buffer
# Clobbers: w0-w11
# Preserves: w2, w13, w18(updated), w19-w31, all GPRs except x1, x11
expand_batch:
    # SWONLY AES-CTR: single jal aes128table_352 wraps 22 AES blocks
    # aes128table_352 ABI: x10 = RK buf addr (input, preserved by caller; clobbered internally),
    #                       x11 = output buf (352 B written), x13 = counter (in: start, out: start+22).
    # Clobbers: x6, x7, x9, x10, x11, x12, x28, x30 + all of AES_128_encrypt's clobbers
    # (x5..x8, x13..x16, x19..x22, x29, x31). Save+restore caller's live GPRs.
    addi x2, x2, -416                       # alloc 352 B staging + 64 B for 13 caller-saves (32-B aligned)
    sw x5,  352(x2)                         # save caller x5 (= 1, w1 WDR idx; aes128table_352 inner AES_128_encrypt clobbers x5..x8)
    sw x6,  356(x2)                         # save caller x6 (= 9, w9 WDR idx)
    sw x7,  360(x2)                         # save caller x7 (Phase 4 row counter)
    sw x9,  364(x2)                         # save caller x9 (Phase 2 batch idx OR Phase 4 cumulative)
    sw x10, 368(x2)                         # save caller x10 (result cursor)
    sw x11, 372(x2)                         # save caller x11 (buf write cursor; advances by 512 across this call)
    sw x14, 376(x2)                         # save caller x14 (Phase 4 P1 read ptr / adjusted)
    sw x15, 380(x2)                         # save caller x15 (Phase 2/4 batch base addr / offset)
    sw x16, 384(x2)                         # save caller x16 (= 11 = w11 WDR idx for repack)
    sw x20, 388(x2)                         # save caller x20 (= 15 = w15 WDR idx; AES_128_encrypt clobbers x19..x22)
    sw x21, 392(x2)                         # save caller x21 (= 16 = w16 WDR idx)
    sw x22, 396(x2)                         # save caller x22 (= 10 = w10 WDR idx)
    sw x28, 400(x2)                         # save caller x28 (= 5 = w5 WDR idx; aes128table_352 clobbers x28 as rk-save)
    # (x29 not saved: caller recomputes in Phase 4; AES_128_encrypt clobber x29 OK)
    addi x12, x2, 0                         # x12 = staging buf base ptr

    # Single call to aes128table_352 produces 352 B of AES-CTR keystream.
    lw x10, 32(x3)                          # x10 = RK buf base (set in P1O_P2 prologue)
    addi x11, x2, 0                         # x11 = output buf = staging base
    # x13 IN: caller-supplied current counter (set by outer Phase 2/3/4 code).
    jal x1, aes128table_352                 # writes 352 B keystream at x11, x13 += 22 on exit
    addi x12, x2, 0                         # re-derive x12 (aes128table_352 clobbers x12)

    # Reload 22 single-block (= 11 dual-block-in-WDR) ciphertexts into w0..w10.
    li x14, 0
    bn.lid x14, 0(x12)
    li x14, 1
    bn.lid x14, 32(x12)
    li x14, 2
    bn.lid x14, 64(x12)
    li x14, 3
    bn.lid x14, 96(x12)
    li x14, 4
    bn.lid x14, 128(x12)
    li x14, 5
    bn.lid x14, 160(x12)
    li x14, 6
    bn.lid x14, 192(x12)
    li x14, 7
    bn.lid x14, 224(x12)
    li x14, 8
    bn.lid x14, 256(x12)
    li x14, 9
    bn.lid x14, 288(x12)
    li x14, 10
    bn.lid x14, 320(x12)

    # Rebuild w13 = mask96 (aes128table_352 doesn't touch WDRs, but caller assumed w13 stale across phases)
    bn.not w13, w31
    bn.rshi w13, w31, w13 >> 160

    # Restore caller-saved GPRs (13 saved, matching the prologue list)
    lw x5,  352(x2)
    lw x6,  356(x2)
    lw x7,  360(x2)
    lw x9,  364(x2)
    lw x10, 368(x2)
    lw x11, 372(x2)
    lw x14, 376(x2)
    lw x15, 380(x2)
    lw x16, 384(x2)
    lw x20, 388(x2)
    lw x21, 392(x2)
    lw x22, 396(x2)
    lw x28, 400(x2)
    addi x2, x2, 416                        # free 416 B staging buffer

    # Repack 11 WDRs -> 8 x 64B-padded entries
    # 11 WDRs (352B) = 8 entries of 44B. Extract with rshi, mask hi, store.
    # Entry 0 (bytes 0-43, shift=0)
    bn.mov w11, w0                          # lo = w0
    bn.sid x16, 0(x11++)                    # store lo, x11+=32
    bn.and w11, w1, w13                     # hi = w1 & mask96
    bn.sid x16, 0(x11++)                    # store hi, x11+=32
    # Entry 1 (bytes 44-87, shift=96)
    bn.rshi w11, w2, w1 >> 96              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w3, w2 >> 96              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 2 (bytes 88-131, shift=192)
    bn.rshi w11, w3, w2 >> 192             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w4, w3 >> 192             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 3 (bytes 132-175, shift=32)
    bn.rshi w11, w5, w4 >> 32              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w6, w5 >> 32              # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 4 (bytes 176-219, shift=128)
    bn.rshi w11, w6, w5 >> 128             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w7, w6 >> 128             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 5 (bytes 220-263, shift=224)
    bn.rshi w11, w7, w6 >> 224             # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w8, w7 >> 224             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 6 (bytes 264-307, shift=64)
    bn.rshi w11, w9, w8 >> 64              # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w10, w9 >> 64             # hi pre-mask
    bn.and w11, w11, w13                    # mask
    bn.sid x16, 0(x11++)
    # Entry 7 (bytes 308-351, shift=160)
    bn.rshi w11, w10, w9 >> 160            # lo
    bn.sid x16, 0(x11++)
    bn.rshi w11, w31, w10 >> 160           # hi (upper already 0)
    bn.and w11, w11, w13                    # mask (redundant but consistent)
    bn.sid x16, 0(x11++)

    ret

#endif

#ifdef GF_INSTRUCTIONS
phase4_row_setup:
    srli x29, x9, 3                    # batch_idx = x9 / 8
    andi x15, x9, 7                    # offset = x9 % 8
    slli x30, x29, 4                   # batch*16
    slli x8, x29, 2                    # batch*4
    add x30, x30, x8                   # batch*20
    slli x8, x29, 1                    # batch*2
    add x30, x30, x8                   # x30 = batch*22
    lw x29, 24(x3)                     # P2 buf addr (32B aligned)
    bn.sid x31, 0(x29)                 # zero 32 bytes
    sw x30, 0(x29)                     # write counter low bytes
    li x8, 14
    bn.lid x8, 0(x29)                  # w14 = batch*22
    bn.addi w18, w14, 1                # w18 = batch*22 + 1
    bn.or w18, w14, w18 << 128         # [odd | even]
    bn.rshi w18, w18, w31 >> 160       # position IV
    li x8, 68
    sub x8, x8, x7                     # elements = 68-r
    add x8, x8, x15                    # elements + offset
    addi x8, x8, 7
    srli x8, x8, 3                     # num batches
    lw x11, 20(x3)                     # reset P1 buf write ptr
    loop x8, 2
        jal x1, expand_batch
        nop
    lw x14, 20(x3)                     # buf base
    slli x29, x15, 6                   # offset * 64
    add x14, x14, x29                  # adjusted read start
    sw x14, 28(x3)                     # save adjusted P1 read ptr
    li x8, 68
    sub x8, x8, x7                     # x8 = 68-r (element count for the bands)
    lw x13, 16(x3)                     # reset O aligned base
    ret
#endif

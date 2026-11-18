/* ov_Ip3_skc_sign - Ip3 sign body, S-precomputed (sprec) tier.
 * The Round-3 L-direct flow (dmem32k/sign_ldirect/ov-Ip3-skc/ov-Ip3-skc-sign.s) with S and the
 * raw P1 cache built once per signature (sprec_build_S_74_45: S 213,120 B + cache
 * 177,600 B on the stack) and each attempt taking L = v^T S (gf256_matvec_2880_74)
 * and y = v^T P1 v (batch_quad_cached_74) from them instead of re-streaming P.
 * in: x10 sig (160B slot, 135B payload; all five words = 160B are stored), x11 csk, x12 msg,
 *     x13 msglen; sig, csk, msg and x2 32B-aligned, msg readable up to msglen rounded up to 32B.
 * frame: x3 = 64 B (0 sig, 4 csk, 8 msg, 12 msglen, 16 salt, 20 target, 24 vinegar, 28 L, 32 S, 36 cache).
 * clob: x3-x9, x11, x12, x14-x17, x19-x21, x23-x31, w0-w31, ACC, ACCH, FG0, MOD, kmac_cfg, kmac_msg,
 *       kmac_partial_write.
 * stack: 64 B frame + pk_seed/O 4,352 + S 213,120 + cache 177,600 + salt/target 96, then
 *        4,288 for the live attempt (freed on a retry) and 96 for O*x. x2 is not restored:
 *        399,616 B below entry on return. Deepest is sprec_build_S_74_45 below the cache,
 *        399,904 B below entry.
 */

.section .text
.balign 4
.global ov_Ip3_skc_sign

ov_Ip3_skc_sign:
    bn.xor w31, w31, w31
    add x31, x0, x0
    /* zeroed as in the other sign orchestrators; only expand_360_table reads them */
    add x20, x0, x0
    add x21, x0, x0
    add x28, x0, x0
    addi x2, x2, -64
    add x3, x0, x2 # Copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)


    jal x1, expandsk_ret_O_pkseed
    add x10, x0, x2 # pk_seed
    addi x11, x2, 32 # O (padded-96: one 96B slot per column)
    li x5, 213120
    sub x2, x2, x5
    sw x2, 32(x3)   # S base
    add x12, x0, x2
    li x5, 177600
    sub x2, x2, x5
    sw x2, 36(x3)   # P1 cache base
    add x13, x0, x2
    jal x1, sprec_build_S_74_45
    add x14, x0, x10 # point to pk_seed (x10-x13 preserved by the builder)
    add x15, x0, x11 # point to O
    lw x10, 0(x3)    # sig, csk, msg, msglen back for the salt/hash code below
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_01(SHAKE256 ):0x9
    addi x31, x13, 16
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
#ifdef USE_TESTVEC_SALT
    # Testvec mode: load 16B salt from DMEM, then zero upper 128 bits so
    # w1 layout matches the non-testvec RND post-proc (w1 = zero_hi128 || salt_LE).
    li x31, 1
    la x30, salt_input
    bn.lid x31, 0(x30)
    bn.rshi w1, w1, w31 >> 128
    bn.rshi w1, w31, w1 >> 128
#else
    bn.wsrr w1, rnd                 # get salt from rnd
    bn.rshi w1, w1, w31 >> 128
    bn.rshi w1, w31, w1 >> 128
#endif

    li x31, 1
    addi x2, x2, -32
    #Store salt
    bn.sid x31, 0(x2)
    sw x2, 16(x3)   # store salt address

    lw x10,0(x3)
    lw x11,4(x3)
    lw x12,8(x3)
    lw x13,12(x3)

    jal x1, hash_salted_msg
    li x31, 29
    addi x2, x2, -64
    bn.sid x31++, 0(x2)
    bn.sid x31, 32(x2)
    sw x2, 20(x3)       # store target address

    lw x10,0(x3)
    lw x11,4(x3)
    lw x12,8(x3)
    lw x13,12(x3)

    li x28, 1
    #Counter x8, w6
    li x8, 0
    li x9, 256
    # loop up to 255
    sig_loop:
        beq x8, x9, abort_sig
        jal x1, expandv
        # counter slot (32B) left on stack; vinegar overlaps + reclaims it
        addi x2, x2, -96
        li x31, 28
        bn.sid x31++, 0(x2)
        bn.sid x31++, 32(x2)
        bn.sid x31, 64(x2)
        sw x2, 24(x3) # store vinegar address
        # L = v^T S (vinegar still in w28..w30 from expandv), y = v^T P1 v from the cache
        li x31, 4096
        sub x2, x2, x31
        sw x2, 28(x3)                 # store matrix L address
        addi x2, x2, -64              # 64B y/r slot just below L
        lw x10, 28(x3)                # x10 = L out (matvec zeroes all 4096 B)
        lw x11, 32(x3)                # x11 = S
        jal x1, gf256_matvec_2880_74
        lw x10, 36(x3)                # x10 = P1 cache
        lw x11, 24(x3)                # x11 = vinegar address
        add x12, x0, x2               # x12 = y/r slot
        jal x1, batch_quad_cached_74
        # Transpose L from column-major to row-major (in-place)
        lw x10, 28(x3)                  # x10 = L matrix address
        jal x1, gf256_transpose_45_45
        # Compute r = y XOR target  (y from batch_quad_cached_74, in y/r slot = x2)
        add x12, x0, x2               # x12 = y/r slot
        lw x11, 20(x3)                    # load target vector address
        li x31, 1
        bn.lid x0, 0(x11)                   #load target vector into w0, w1
        bn.lid x31, 32(x11)
        bn.ld w20, 0(x12)                # y_lo, y_hi from slot
        bn.ld w21, 32(x12)
        bn.xor w0, w0, w20
        bn.xor w1, w1, w21
        bn.sid x0, 0(x12)                #Store (target XOR Y ) = r into slot
        bn.sid x31, 32(x12)              #then ready to perform GE
        # Gaussian elimination: L x o = r
        lw x10, 28(x3)                  # x10 = L matrix input (row-major now)
        add x11, x0, x2                 # x11 = r vector input
        jal x1, gaussian_elimination_45x45

        # ----------------------------------------------------------
        # Check W20: all-zeros = invertible (success), all-ones = singular (retry)
        # ----------------------------------------------------------
        addi x2, x2, -32                # allocate temp slot
        li x31, 20
        bn.sid x31, 0(x2)               # store W20 to temp slot
        lw x4, 0(x2)                    # load first 32 bits of W20
        addi x2, x2, 32                 # free temp slot (restore x2)
        li x5, -1                       # x5 = 0xFFFFFFFF
        beq x4, x5, ge_failed           # if W20[31:0] == 0xFFFFFFFF -> singular, retry

        # GE succeeded, transpose L back to column-major for back-substitution
        lw x10, 28(x3)                  # x10 = GE result matrix address
        jal x1, gf256_transpose_45_45   # transpose matrix from row->col major
        lw x10, 28(x3)                  # reload (transpose clobbers x10)
        add x11, x0, x2                 # x11 = r vector (GE solution)
        jal x1, back_substitution

        add x12, x0, x2                 # x12 point at x vector
        addi x2, x2, -96                # allocate 96 bytes for accumulate result
        add x10, x0, x2                 # x10 accumulator
        add x11, x0, x15                # x11 point at O matrix
        jal x1, gf256mat_prod_74_45
        beq x0, x0, done_sign

ge_failed:
    # GE failed, reclaim loop-local stack and retry with next counter
    # Undo: r vector (64) + L matrix (4096) + vinegar (96) + counter (32) = 4288 bytes
    li x31, 4288
    add x2, x2, x31                 # restore x2 to top of sig_loop
    # Restore GPRs clobbered during the loop body
    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)
    li x28, 1                       # restore x28 (clobbered by GE)
    addi x8, x8, 1                  # increment counter
    beq x0, x0, sig_loop            # retry

done_sign:
    # Assemble full signature: vinegar || oil || salt
    li x31, 0
    bn.lid x31++, 0(x2)     # load O*x
    bn.lid x31++, 32(x2)    # into
    bn.lid x31++, 64(x2)    # w0-w2
    lw x30, 24(x3)          # load vinegar
    bn.lid x31++, 0(x30)    # into
    bn.lid x31++, 32(x30)   # w3-w5
    bn.lid x31++, 64(x30)   #
    bn.xor w8, w0, w3
    bn.xor w9, w1, w4
    bn.xor w10, w2, w5
    bn.lid x31++, 0(x12)    # load oil into w6-w7
    bn.lid x31++, 32(x12)
    bn.rshi w7, w7, w6 >> 176
    bn.rshi w6, w6, w31 >> 176
    bn.or w10, w10, w6
    bn.mov w11, w7
    lw x30, 16(x3)
    li x31, 12
    bn.lid x31, 0(x30)
    # salt lands at sig[119..134] and crosses the 128-byte line: split it
    bn.rshi w13, w31, w12 >> 72
    bn.rshi w12, w12, w31 >> 72
    bn.or w11, w11, w12
    bn.mov w12, w13
    lw x10, 0(x3)                   # x10 = signature output address
    li x31, 8
    bn.sid x31++, 0(x10)
    bn.sid x31++, 32(x10)
    bn.sid x31++, 64(x10)
    bn.sid x31++, 96(x10)
    bn.sid x31++, 128(x10)          # 135B sig needs a 5th word: 160B slot
    ret
abort_sig:
        unimp
    ret

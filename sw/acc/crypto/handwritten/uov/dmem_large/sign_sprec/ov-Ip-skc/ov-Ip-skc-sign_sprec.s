/* ov_Ip_skc_sign (Ip skc-only sign body).
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW path: extra GPR init + x13 reload + w20 reset
 *   bngfonly    -DGF_INSTRUCTIONS    HW path (identical bytes to bngfaes; calls tier helpers via shared symbol)
 *   bngfaes     -DAES_|GF_           HW path
 *
 * Tier dispatch happens via the linked tier-specific helper libs (jal x1, <symbol>
 * resolves to whichever tier lib is linked at acc_binary level).
 */

.section .text
.balign 4
.global ov_Ip_skc_sign

#if defined(GF_INSTRUCTIONS)

/* =============== bngfaes + bngfonly (HW path) =============== */
ov_Ip_skc_sign:
    bn.xor w31, w31, w31 
    add x31, x0, x0
    addi x2, x2, -32
    add x3, x0, x2 # Copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)


    jal x1, expandsk_ret_O_pkseed
    add x14, x0, x2 # point to pk_seed
    addi x15, x2, 32 # point to O
    # Allocate 191488 bytes in stack for S_i
    li x5, 191488 
    sub x2, x2, x5
    add x16, x0, x2 # x16 point at stack which store S_i
#if defined(GF_INSTRUCTIONS)
    # P1 cache (default, both HW tiers): 2346 entries * 64 B = 150144 B below S.
    # Filled once in trimat (transpose reuse), reread per attempt in batch_quad.
    li x5, 150144
    sub x2, x2, x5
    add x13, x0, x2 # x13 = P1 cache base, passed to gf256trimat as 4th arg
#endif

    add x10, x0, x14
    add x11, x0, x15
    add x12, x0, x16
    # Computing S_i
    jal x1, gf256trimat_2trimat_madd_68_68_44_44
#if defined(GF_INSTRUCTIONS)
    lw x13, 12(x3)  # x13 held cache base for trimat; restore msg_len for KMAC cfg
#endif

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_01(SHAKE256 ):0x9
    addi x31, x13, 16
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    # Salt: 16 B, read once and kept on retries; RND (EDN entropy), or salt_input in DMEM with USE_TESTVEC_SALT.
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
        # Prepare for S * v
        li x31, 4096
        sub x2, x2, x31
        sw x2, 28(x3) # store matrix L address
        add x10, x0, x2
        add x11, x0, x16
        jal x1, gf256_matvec_2816_68
        # Transpose L from column-major to row-major (in-place)
        lw x10, 28(x3)                  # x10 = L matrix address
        jal x1, gf256_transpose_44_44
        li x10, 150144
        sub x10, x16, x10            # x10 = P1 cache base (= S base - 150144); read cached P1
        lw x11, 24(x3)                # x11 = vinegar address
        addi x2, x2, -64              # allocate 64 bytes for y vector
        add x12, x0, x2               # x12 = y output
        jal x1, batch_quad_trimat_eval_gf256_cached
        # Compute r = y XOR target 
        lw x11, 20(x3)                    # load target vector address
        li x31, 1
        bn.lid x0, 0(x11)                   #load target vector into w0, w1
        bn.lid x31, 32(x11)
        bn.xor w0, w0, w20
        bn.xor w1, w1, w21
        bn.sid x0, 0(x12)                #Store (target XOR Y ) into Y vector address
        bn.sid x31, 32(x12)              #then ready to perform GE
        # Gaussian elimination: L × o = r
        lw x10, 28(x3)                  # x10 = L matrix input (row-major now)
        add x11, x0, x2                 # x11 = r vector input
        jal x1, gaussian_elimination_44x44

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

        # GE succeeded — transpose L back to column-major for back-substitution
        lw x10, 28(x3)                  # x10 = GE result matrix address
        jal x1, gf256_transpose_44_44   # transpose matrix from row→col major
        lw x10, 28(x3)                  # reload (transpose clobbers x10)
        add x11, x0, x2                 # x11 = r vector (GE solution)
        jal x1, back_substitution

        add x12, x0, x2                 # x12 point at x vector
        addi x2, x2, -96                # allocated 96 bytes for accumulaete result
        add x10, x0, x2                 # x10 accummulator                 
        add x11, x0, x15                # x11 point at O matrix
        jal x1, gf256mat_prod_68_44
        beq x0, x0, done_sign

ge_failed:
    # GE failed — reclaim loop-local stack and retry with next counter
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
    bn.rshi w7, w7, w6 >> 224
    bn.rshi w6, w6, w31 >> 224
    bn.or w10, w10, w6
    bn.mov w11, w7
    lw x30, 16(x3)
    li x31, 12
    bn.lid x31, 0(x30)
    bn.rshi w12, w12, w31 >> 128
    bn.or w11, w11, w12
    lw x10, 0(x3)                   # x10 = signature output address
    li x31, 8
    bn.sid x31++, 0(x10)
    bn.sid x31++, 32(x10)
    bn.sid x31++, 64(x10)
    bn.sid x31++, 96(x10)
    ret
abort_sig:
        unimp
    ret


#else

/* =============== sw (SW path with extra reg init + reloads) =============== */
ov_Ip_skc_sign:
    bn.xor w31, w31, w31
    add x31, x0, x0
    /* RTL/ISS GPR init differs (RTL leaves x20/x21/x28 random, ISS zeros).
     * trimat→expand_352_table saves these to stack before they are written
     * by the kernel, so the save itself diverges and the trace checker
     * aborts at the restore. Initialize them up front. */
    add x20, x0, x0
    add x21, x0, x0
    add x28, x0, x0
    addi x2, x2, -32
    add x3, x0, x2 # Copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)


    jal x1, expandsk_ret_O_pkseed
    # pk_seed at x2 (16 B), O at x2+32 (3008 B). Round keys now derived
    # in-frame by sub-kernels (trimat, batch_quad) themselves.
    add x14, x0, x2 # point to pk_seed
    addi x15, x2, 32 # point to O
    # Allocate 191488 bytes in stack for S_i
    li x5, 191488
    sub x2, x2, x5
    add x16, x0, x2 # x16 point at stack which store S_i
    # P1 cache (default): 2346 entries * 64 B = 150144 B below S_i.
    # Filled once in trimat (transpose reuse), reread per attempt in batch_quad.
    li x5, 150144
    sub x2, x2, x5
    add x13, x0, x2 # x13 = P1 cache base, passed to gf256trimat as 4th arg

    add x10, x0, x14
    add x11, x0, x15
    add x12, x0, x16
    # Computing S_i
    jal x1, gf256trimat_2trimat_madd_68_68_44_44

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_01(SHAKE256 ):0x9
    # AES_128_keyschedule (aestable-only call before gf256trimat) clobbers x13.
    # gf256trimat's x13-save-restore preserves THE ENTRY VALUE which is garbage.
    # Reload x13 = msg_len from saved slot 12(x3) before computing kmac output len.
    lw x13, 12(x3)
    addi x31, x13, 16
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    # Salt: 16 B, read once and kept on retries; RND (EDN entropy), or salt_input in DMEM with USE_TESTVEC_SALT.
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
        # Prepare for S * v
        li x31, 4096
        sub x2, x2, x31
        sw x2, 28(x3) # store matrix L address
        add x10, x0, x2
        add x11, x0, x16
        jal x1, gf256_matvec_2816_68
        # Transpose L from column-major to row-major (in-place)
        lw x10, 28(x3)                  # x10 = L matrix address
        jal x1, gf256_transpose_44_44
        li x10, 150144
        sub x10, x16, x10            # x10 = P1 cache base (= S base - 150144); read cached P1
        lw x11, 24(x3)                # x11 = vinegar address
        addi x2, x2, -64              # allocate 64 bytes for y vector
        add x12, x0, x2               # x12 = y output
        jal x1, batch_quad_trimat_eval_gf256_cached
        # Compute r = y XOR target 
        lw x11, 20(x3)                    # load target vector address
        li x31, 1
        bn.lid x0, 0(x11)                   #load target vector into w0, w1
        bn.lid x31, 32(x11)
        bn.xor w0, w0, w20
        bn.xor w1, w1, w21
        bn.sid x0, 0(x12)                #Store (target XOR Y ) into Y vector address
        bn.sid x31, 32(x12)              #then ready to perform GE
        # Gaussian elimination: L × o = r
        lw x10, 28(x3)                  # x10 = L matrix input (row-major now)
        add x11, x0, x2                 # x11 = r vector input
        jal x1, gaussian_elimination_44x44

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

        # GE succeeded — transpose L back to column-major for back-substitution
        lw x10, 28(x3)                  # x10 = GE result matrix address
        jal x1, gf256_transpose_44_44   # transpose matrix from row→col major
        lw x10, 28(x3)                  # reload (transpose clobbers x10)
        add x11, x0, x2                 # x11 = r vector (GE solution)
        jal x1, back_substitution

        add x12, x0, x2                 # x12 point at x vector
        addi x2, x2, -96                # allocated 96 bytes for accumulaete result
        add x10, x0, x2                 # x10 accummulator                 
        add x11, x0, x15                # x11 point at O matrix
        jal x1, gf256mat_prod_68_44
        beq x0, x0, done_sign

ge_failed:
    # GE failed — reclaim loop-local stack and retry with next counter
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
    bn.rshi w7, w7, w6 >> 224
    bn.rshi w6, w6, w31 >> 224
    bn.or w10, w10, w6
    bn.mov w11, w7
    lw x30, 16(x3)
    li x31, 12
    bn.lid x31, 0(x30)
    bn.rshi w12, w12, w31 >> 128
    bn.or w11, w11, w12
    lw x10, 0(x3)                   # x10 = signature output address
    li x31, 8
    bn.sid x31++, 0(x10)
    bn.sid x31++, 32(x10)
    bn.sid x31++, 64(x10)
    bn.sid x31++, 96(x10)
    /* Reset w20 = 0 to match HW final state (SW back_sub/matvec helpers use
     * w20 as acc accumulator; HW variants leave w20 untouched. Final w20 is
     * the [8] singularity-flag-check target; gauss already succeeded here. */
    bn.xor w20, w20, w20
    ret
abort_sig:
        unimp
    ret


#endif

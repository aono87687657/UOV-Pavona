/* ov_Is_skc_sign (Is skc-only sign body).
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW path
 *   bngfonly    -DGF_INSTRUCTIONS    HW path (identical to bngfaes; tier helpers via shared symbol)
 *   bngfaes     -DAES_|GF_           HW path
 */

.section .text
.balign 4
.global ov_Is_skc_sign

#if defined(GF_INSTRUCTIONS)

/* =============== bngfaes + bngfonly (HW path) =============== */
ov_Is_skc_sign:
    bn.xor w31, w31, w31 
    addi x2, x2, -32
    add x3, x0, x2 # Copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)


    jal x1, expandsk_ret_O_pkseed
    add x14, x0, x2 # point to pk_seed
    addi x15, x2, 32 # point to O
    # Allocate 196608 bytes in stack for S_i
    lui x5, 48
    sub x2, x2, x5
    add x16, x0, x2 # x16 point at stack which store S_i
#if defined(GF_INSTRUCTIONS)
    /* Allocate 148992 B raw-P1 cache below S (upper-tri incl diag, 4656*32 B).
     * Persists across the whole sign; base = x16 - 148992 (recompute when needed).
     * Both HW tiers (bngfaes + bngfonly) cache P1; sw does not. */
    li x5, 148992
    sub x2, x2, x5
    add x13, x0, x2 # x13 = P1 cache base (4th arg to gf16trimat)
#endif

    add x10, x0, x14
    add x11, x0, x15
    add x12, x0, x16
    # Computing S_i
    jal x1, gf16trimat_2trimat_madd_96_48_64_32
#if defined(GF_INSTRUCTIONS)
    lw x13, 12(x3) # reload msg_len (gf16trimat used x13 as cache base)
#endif

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_10(SHAKE256):0xA
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
    bn.wsrr w1, rnd
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
    li x31, 30
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x2, 20(x3)       # store target address

    lw x10,0(x3)
    lw x11,4(x3)
    lw x12,8(x3)
    lw x13,12(x3)
    
    #Counter x8, w6
    li x8, 0
    li x9, 256
    # loop up to 255
    sig_loop:
        beq x8, x9, abort_sig
        jal x1, expandv
        # counter slot (32B) left on stack; vinegar overlaps + reclaims it
        bn.rshi w29, w29, w31 >> 128
        bn.rshi w29, w31, w29 >> 128
        addi x2, x2, -64
        li x31, 28
        bn.sid x31++, 0(x2)
        bn.sid x31, 32(x2)
        sw x2, 24(x3) # store vinegar address
        # Prepare for S * v
        addi x2, x2, -2048
        sw x2, 28(x3) # store matrix L address
        add x10, x0, x2
        add x11, x0, x16
        jal x1, gf16_matvec_2048_96
        jal x1, gf16_transpose_64_64
#if defined(GF_INSTRUCTIONS)
        li x5, 148992
        sub x10, x16, x5               # x10 = P1 cache base (S base - cache size)
#else
        add x10, x0, x14               # x10 = pk_seed
#endif
        lw x11, 24(x3)
        add x2, x2, -32 # allocate space for y vector
        add x12, x0, x2
#if defined(GF_INSTRUCTIONS)
        jal x1, batch_quad_trimat_eval_gf16_cached
#else
        jal x1, batch_quad_trimat_eval_gf16
#endif
        lw x11, 20(x3)                  # load target vector address in x11
        li x31, 0
        bn.lid x31++, 0(x11)            # load target vector into w0
        bn.lid x31, 0(x2)               # load vector y into w1
        bn.xor w0, w0, w1               # vector Y XOR target Vec
        bn.sid x0, 0(x2)                # Store at vector Y address
        lw x10, 28(x3)                  # load matrix L address
        add x11, x0, x2                 # load (vector y XOR target vector) address
        jal x1, gaussian_elemination_64x64

        # ----------------------------------------------------------
        # Check W24: all-zeros = invertible (success), all-ones = singular (retry)
        # Store W24 to a temp slot BELOW the stack so we don't clobber the
        # GE result vector at 0(x2) which back-substitution still needs.
        # ----------------------------------------------------------
        addi x2, x2, -32                # allocate temp slot below stack
        li x31, 24
        bn.sid x31, 0(x2)               # store W24 to temp slot
        lw x4, 0(x2)                    # load first 32 bits of W24
        addi x2, x2, 32                 # free temp slot (restore x2)
        li x5, -1                       # x5 = 0xFFFFFFFF
        beq x4, x5, ge_failed           # if W24[31:0] == 0xFFFFFFFF -> singular, retry

        # GE succeeded — continue with back-substitution and signature assembly
        lw x10, 28(x3)                  # load GE result matrix address
        add x11, x0, x2                 # Load GE result vector address
        jal x1, gf16_transpose_64_64    # transpose matrix from row to col major
        jal x1, back_substitution
        bn.lid x0, 0(x11)               # load o vector into w0
        bn.rshi w2, w31, w0 >> 128      # shift o vec upper 16 bytes to w2
        bn.rshi w1, w0, w31 >> 128      # shift o vec lower 16 bytes to w1
        add x10, x0, x15                # set x10 to x15(matrix O address)
        jal x1, gf16_matvec_48_64
        li x31, 3
        lw x10, 24(x3)                  # Load vinegar address
        lw x11, 16(x3)                  # Load salt address
        bn.lid x31++, 0(x10)            # load vinegar into w3(lower), w4(upper)
        bn.lid x31++, 32(x10)       
        bn.lid x31++, 0(x11)            # load salt into w5        
        bn.xor w3, w3, w7               # linear transform vinegar variable 
        bn.xor w4, w4, w8               #
        bn.or w4, w4, w1                # concate o variable
        bn.or w5, w2, w5 << 128         # concate salt
        beq x0, x0, done_sign

ge_failed:
    # GE failed — reclaim loop-local stack and retry with next counter
    # Undo: y vector (32) + L matrix (2048) + vinegar (64) + counter (32) = 2176 bytes
    li x31, 2176
    add x2, x2, x31                 # restore x2 to SP0 (top of sig_loop)
    # Restore GPRs clobbered during the loop body
    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)
    li x28, 1                       # restore x28 (clobbered by GE: x28=63)
    addi x8, x8, 1                  # increment counter
    beq x0, x0, sig_loop            # retry

done_sign:
        lw x10, 0(x3)   #Store Signature to Signature address
        li x31, 3
        bn.sid x31++, 0(x10) 
        bn.sid x31++, 32(x10) 
        bn.sid x31++, 64(x10) 
    ret
abort_sig:
        unimp
    ret


#else

/* =============== sw (SW path) =============== */
ov_Is_skc_sign:
    bn.xor w31, w31, w31
    addi x2, x2, -32
    add x3, x0, x2 # Copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)


    jal x1, expandsk_ret_O_pkseed
    add x14, x0, x2 # point to pk_seed
    addi x15, x2, 32 # point to O
    # Allocate 196608 bytes in stack for S_i
    lui x5, 48
    sub x2, x2, x5
    add x16, x0, x2 # x16 point at stack which store S_i
    # P1 cache (default): 4656 entries * 32 B = 148992 B below S_i.
    # Filled once in trimat (transpose reuse), reread per attempt in batch_quad.
    li x5, 148992
    sub x2, x2, x5
    add x13, x0, x2 # x13 = P1 cache base, passed to gf16trimat as 4th arg

    add x10, x0, x14
    add x11, x0, x15
    add x12, x0, x16
    # Computing S_i
    jal x1, gf16trimat_2trimat_madd_96_48_64_32

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_10(SHAKE256):0xA
    # SW: trimat's AES_128_keyschedule clobbers x13 (in its x12..x18
    # clobber list). Reload x13 = msg_len from saved slot before using it
    # to compute the KMAC config word.
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
    bn.wsrr w1, rnd
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
    li x31, 30
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x2, 20(x3)       # store target address

    lw x10,0(x3)
    lw x11,4(x3)
    lw x12,8(x3)
    lw x13,12(x3)

    #Counter x8, w6
    li x8, 0
    li x9, 256
    # loop up to 255
    sig_loop:
        beq x8, x9, abort_sig
        jal x1, expandv
        # counter slot (32B) left on stack; vinegar overlaps + reclaims it
        bn.rshi w29, w29, w31 >> 128
        bn.rshi w29, w31, w29 >> 128
        addi x2, x2, -64
        li x31, 28
        bn.sid x31++, 0(x2)
        bn.sid x31, 32(x2)
        sw x2, 24(x3) # store vinegar address
        # Prepare for S * v
        addi x2, x2, -2048
        sw x2, 28(x3) # store matrix L address
        add x10, x0, x2
        add x11, x0, x16
        jal x1, gf16_matvec_2048_96
        jal x1, gf16_transpose_64_64
        li x5, 148992
        sub x10, x16, x5               # x10 = P1 cache base (S base - cache size)
        lw x11, 24(x3)
        add x2, x2, -32 # allocate space for y vector
        add x12, x0, x2
        jal x1, batch_quad_trimat_eval_gf16_cached
        lw x11, 20(x3)                  # load target vector address in x11
        li x31, 0
        bn.lid x31++, 0(x11)            # load target vector into w0
        bn.lid x31, 0(x2)               # load vector y into w1
        bn.xor w0, w0, w1               # vector Y XOR target Vec
        bn.sid x0, 0(x2)                # Store at vector Y address
        lw x10, 28(x3)                  # load matrix L address
        add x11, x0, x2                 # load (vector y XOR target vector) address
        jal x1, gaussian_elemination_64x64

        # ----------------------------------------------------------
        # Check W24: all-zeros = invertible (success), all-ones = singular (retry)
        # Store W24 to a temp slot BELOW the stack so we don't clobber the
        # GE result vector at 0(x2) which back-substitution still needs.
        # ----------------------------------------------------------
        addi x2, x2, -32                # allocate temp slot below stack
        li x31, 24
        bn.sid x31, 0(x2)               # store W24 to temp slot
        lw x4, 0(x2)                    # load first 32 bits of W24
        addi x2, x2, 32                 # free temp slot (restore x2)
        li x5, -1                       # x5 = 0xFFFFFFFF
        beq x4, x5, ge_failed           # if W24[31:0] == 0xFFFFFFFF -> singular, retry

        # GE succeeded — continue with back-substitution and signature assembly
        lw x10, 28(x3)                  # load GE result matrix address
        add x11, x0, x2                 # Load GE result vector address
        jal x1, gf16_transpose_64_64    # transpose matrix from row to col major
        jal x1, back_substitution
        bn.lid x0, 0(x11)               # load o vector into w0
        bn.rshi w2, w31, w0 >> 128      # shift o vec upper 16 bytes to w2
        bn.rshi w1, w0, w31 >> 128      # shift o vec lower 16 bytes to w1
        add x10, x0, x15                # set x10 to x15(matrix O address)
        jal x1, gf16_matvec_48_64
        li x31, 3
        lw x10, 24(x3)                  # Load vinegar address
        lw x11, 16(x3)                  # Load salt address
        bn.lid x31++, 0(x10)            # load vinegar into w3(lower), w4(upper)
        bn.lid x31++, 32(x10)
        bn.lid x31++, 0(x11)            # load salt into w5
        bn.xor w3, w3, w7               # linear transform vinegar variable
        bn.xor w4, w4, w8               #
        bn.or w4, w4, w1                # concate o variable
        bn.or w5, w2, w5 << 128         # concate salt
        beq x0, x0, done_sign

ge_failed:
    # GE failed — reclaim loop-local stack and retry with next counter
    # Undo: y vector (32) + L matrix (2048) + vinegar (64) + counter (32) = 2176 bytes
    li x31, 2176
    add x2, x2, x31                 # restore x2 to SP0 (top of sig_loop)
    # Restore GPRs clobbered during the loop body
    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)
    li x28, 1                       # restore x28 (clobbered by GE: x28=63)
    addi x8, x8, 1                  # increment counter
    beq x0, x0, sig_loop            # retry

done_sign:
        lw x10, 0(x3)   #Store Signature to Signature address
        li x31, 3
        bn.sid x31++, 0(x10)
        bn.sid x31++, 32(x10)
        bn.sid x31++, 64(x10)
    ret
abort_sig:
        unimp
    ret

#endif

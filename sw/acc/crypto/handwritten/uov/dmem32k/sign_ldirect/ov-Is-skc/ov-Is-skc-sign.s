/* ov_Is_skc_sign — Is sign body, L-direct tier.
 * Same as uov/dmem_large/sign_sprec/ov-Is-skc/ov-Is-skc-sign_sprec.s but with no S precompute: instead of the one-time
 * trimat S + per-attempt gf16_matvec_2048_96, each attempt builds L directly via
 * gf16_ldirect_96_64. ~196 KB less stack; retries re-stream P. bngfaes + bngfonly + swonly.
 * in: x10 sig, x11 csk, x12 msg, x13 msglen.
 */

.section .text
.balign 4
.global ov_Is_skc_sign

ov_Is_skc_sign:
    bn.xor w31, w31, w31
    addi x2, x2, -32
    add x3, x0, x2                  # copy initial stack address
    sw x10, 0(x2)
    sw x11, 4(x2)
    sw x12, 8(x2)
    sw x13, 12(x2)

    jal x1, expandsk_ret_O_pkseed
    add x14, x0, x2                 # x14 = pk_seed
    addi x15, x2, 32                # x15 = O
    # (no S_i precompute / trimat in the L-direct tier)

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x13, 16
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    # Salt: 16 B, read once and kept on retries; RND (EDN entropy), or salt_input in DMEM with USE_TESTVEC_SALT.
#ifdef USE_TESTVEC_SALT
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

    addi x2, x2, -32
    bn.sd w1, 0(x2)               # store salt
    sw x2, 16(x3)                   # salt address

    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)

    jal x1, hash_salted_msg
    addi x2, x2, -32
    bn.sd w30, 0(x2)
    sw x2, 20(x3)                   # target address

    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)

    li x8, 0
    li x9, 256
    sig_loop:
        beq x8, x9, abort_sig
        jal x1, expandv
        # counter slot (32B) left on stack; vinegar overlaps + reclaims it
        bn.rshi w29, w29, w31 >> 128
        bn.rshi w29, w31, w29 >> 128
        addi x2, x2, -64
        bn.sd w28, 0(x2)
        bn.sd w29, 32(x2)
        sw x2, 24(x3)               # vinegar address
        # Build L = t^T*O + vin^T*P2 directly from the P stream (no S_i)
        # Fused ldirect also computes y = vin^T P1 vin (single P1 pass, all tiers).
        addi x2, x2, -2048
        sw x2, 28(x3)               # matrix L address
        add x10, x0, x14            # x10 = pk_seed (before x14 repurposed as y ptr)
        addi x2, x2, -32            # 32B y/r slot below L; fused ldirect writes y here
        add x14, x0, x2             # x14 = y-out ptr (5th arg)
        lw x11, 24(x3)              # x11 = vinegar address
        lw x12, 28(x3)             # x12 = L out (kernel zeroes all 2048 B)
        add x13, x0, x15           # x13 = O
        addi x2, x2, -32           # spill x8 (keeps ge_failed reclaim = 2176)
        sw x8, 0(x2)
        jal x1, gf16_ldirect_96_64
        lw x8, 0(x2)
        addi x2, x2, 32            # x2 now = y/r slot (L - 32)
        li x9, 256                  # retry limit
        add x14, x0, x10            # x14 = pk_seed (x10..x13 preserved by kernel)
        add x15, x0, x13            # x15 = O
        lw x10, 28(x3)              # x10 = L matrix (transpose operates on L, not pk_seed!)
        jal x1, gf16_transpose_64_64
        # r = y XOR target (y produced by fused ldirect, in y/r slot = x2)
        lw x11, 20(x3)             # target vector address
        li x31, 0
        bn.lid x31++, 0(x11)       # target -> w0
        bn.lid x31, 0(x2)          # y -> w1
        bn.xor w0, w0, w1
        bn.sd w0, 0(x2)           # (y XOR target) = r -> y/r slot
        lw x10, 28(x3)             # L matrix
        add x11, x0, x2            # r vector
        jal x1, gaussian_elemination_64x64

        # Check W24: all-ones (0xFFFFFFFF) = singular -> retry
        addi x2, x2, -32
        bn.sd w24, 0(x2)
        lw x4, 0(x2)
        addi x2, x2, 32
        li x5, -1
        beq x4, x5, ge_failed

        # GE succeeded — back-substitution and signature assembly
        lw x10, 28(x3)
        add x11, x0, x2
        jal x1, gf16_transpose_64_64
        jal x1, back_substitution
        bn.lid x0, 0(x11)          # o vector -> w0
        bn.rshi w2, w31, w0 >> 128 # o upper 16 B -> w2
        bn.rshi w1, w0, w31 >> 128 # o lower 16 B -> w1
        add x10, x0, x15           # x10 = O matrix
        jal x1, gf16_matvec_48_64
        li x31, 3
        lw x10, 24(x3)             # vinegar
        lw x11, 16(x3)             # salt
        bn.lid x31++, 0(x10)       # vinegar -> w3, w4
        bn.lid x31++, 32(x10)
        bn.lid x31++, 0(x11)       # salt -> w5
        bn.xor w3, w3, w7          # linear transform vinegar variable
        bn.xor w4, w4, w8
        bn.or w4, w4, w1           # concat o variable
        bn.or w5, w2, w5 << 128    # concat salt
        beq x0, x0, done_sign

ge_failed:
    # reclaim: y(32) + L(2048) + vinegar(64) + counter(32) = 2176 (x8 spill already freed)
    li x31, 2176
    add x2, x2, x31
    lw x10, 0(x3)
    lw x11, 4(x3)
    lw x12, 8(x3)
    lw x13, 12(x3)
    li x28, 1
    addi x8, x8, 1
    beq x0, x0, sig_loop

done_sign:
    lw x10, 0(x3)                  # signature output address
    bn.sd w3, 0(x10)
    bn.sd w4, 32(x10)
    bn.sd w5, 64(x10)
    ret
abort_sig:
    unimp
    ret

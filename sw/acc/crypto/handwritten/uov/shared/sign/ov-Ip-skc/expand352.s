/* expand_352 (Ip) - 11 AES-128 dual-block outputs for P1 expansion stream.
 *
 *   variant     cpp flag                                  body
 *   bngfonly    -DGF_INSTRUCTIONS                         11 sequential aes128_sign jal calls + stack buffer
 *   bngfaes     -DAES_INSTRUCTIONS|GF_INSTRUCTIONS        11 inline bn.aes128.encz/encm/encf streams
 *
 * Swonly tier uses a separately-named kernel `expand_352_table.s` (different signature).
 *
 * Caller pre-loads w18=IV, w19=IV-inc, w30=RK0, w31=0, and RK1..RK10 in the order its arm
 * consumes them: bngfaes w29..w20 (descending, as the caller's kf chain assigns them),
 * bngfonly w20..w29 forward AND every key dual-stored K|K — aes128_sign XORs all 256 bits,
 * so a low-half-only key silently corrupts the second block.
 * Output: w1/w3/w5/w7/w9/w11/w13/w15 = 8 packed P1 entries; w18 += 11*w19.
 */

.section .text
.balign 4
.global expand_352

#if defined(AES_INSTRUCTIONS)

/* =============== bngfaes (inline HW bn.aes128.*) =============== */
expand_352:
    # Assumes: w30 = RK0, w29..w20 = RK1..RK10 (descending, per the caller's kf chain)
    #          w19 = IV increment, w18 = current IV, w31 = zero
    # Output: 8 entries in w0/w1..w14/w15, Clobbers: w0-w15

    bn.mov w0, w18
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
    bn.add w18, w10, w19

    bn.aes128.encz.swap w0, w0, w30
    bn.aes128.encz.swap w1, w1, w30
    bn.aes128.encz.swap w2, w2, w30
    bn.aes128.encz.swap w3, w3, w30
    bn.aes128.encz.swap w4, w4, w30
    bn.aes128.encz.swap w5, w5, w30
    bn.aes128.encz.swap w6, w6, w30
    bn.aes128.encz.swap w7, w7, w30
    bn.aes128.encz.swap w8, w8, w30
    bn.aes128.encz.swap w9, w9, w30
    bn.aes128.encz.swap w10, w10, w30
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

    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    bn.rshi w13, w9, w31 >> 160
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w9, w8 >> 64
    bn.rshi w11, w8, w7 >> 64
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w7, w6 >> 224
    bn.rshi w9, w6, w31 >> 224
    bn.rshi w9, w31, w9 >> 160
    bn.rshi w8, w6, w5 >> 128
    bn.rshi w7, w5, w31 >> 128
    bn.rshi w7, w31, w7 >> 160
    bn.rshi w6, w5, w4 >> 32
    bn.rshi w5, w4, w3 >> 32
    bn.rshi w5, w31, w5 >> 160
    bn.rshi w4, w3, w2 >> 192
    bn.rshi w3, w2, w31 >> 192
    bn.rshi w3, w31, w3 >> 160
    bn.rshi w2, w2, w1 >> 96
    bn.rshi w1, w1, w31 >> 96
    bn.rshi w1, w31, w1 >> 160

    ret

#else

/* =============== bngfonly (jal aes128_sign + stack buffer) =============== */
expand_352:
    # Save caller's x5, x6 (clobbered by la/li below; gf256trimat needs both).
    # Allocate 384 (= 12*32) to keep x2 32-byte aligned for bn.sid/lid; x5/x6
    # saved at offsets 352/356, AES buffer at offsets 0..351 (11 x 32 B).
    addi x2, x2, -384
    sw x5, 352(x2)
    sw x6, 356(x2)

    # Reload AES constants the rshi-reorder block at the end clobbers w7/w8/w9
    # with P1-entry data. Caller may invoke expand_352 multiple times, so we
    # restore from .data each call. (.data labels resolved by linker.)
    la x5, byte_swap_mask
    li x6, 7
    bn.lid x6, 0(x5)
    la x5, affine_value
    li x6, 8
    bn.lid x6, 0(x5)
    la x5, msb_mask
    li x6, 9
    bn.lid x6, 0(x5)

    # Use x17 for bn.sid/lid index (x8 is used by gf256trimat caller, x6 by
    # multiple callers; x17 is safe orchestrator/gf256trimat don't use it,
    # batch_quad reloads it after expand_352 returns).
    li x17, 2                        # bn.sid/lid index for w2 (aes128_sign output)

    # ---- 11 sequential AES-CTR ciphertexts to stack ----
    jal x1, aes128_sign             # w2 = AES(IV[0])
    bn.sid x17, 0(x2)
    bn.add w18, w18, w19            # IV[1]
    jal x1, aes128_sign
    bn.sid x17, 32(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 64(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 96(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 128(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 160(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 192(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 224(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 256(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 288(x2)
    bn.add w18, w18, w19
    jal x1, aes128_sign
    bn.sid x17, 320(x2)
    bn.add w18, w18, w19            # final IV update for caller (w18 = IV[11])

    # ---- load 11 CTs back into w0..w10 using fixed offsets from x2 ----
    # Reuse x17 as the WDR-index GPR (was used for bn.sid above). This
    # avoids clobbering caller's x5 gf256trimat uses x5 as P1+P1T row
    # cursor and would crash with misaligned bn.sid if x5 had a small value.
    li x17, 0
    bn.lid x17, 0(x2)
    addi x17, x17, 1
    bn.lid x17, 32(x2)
    addi x17, x17, 1
    bn.lid x17, 64(x2)
    addi x17, x17, 1
    bn.lid x17, 96(x2)
    addi x17, x17, 1
    bn.lid x17, 128(x2)
    addi x17, x17, 1
    bn.lid x17, 160(x2)
    addi x17, x17, 1
    bn.lid x17, 192(x2)
    addi x17, x17, 1
    bn.lid x17, 224(x2)
    addi x17, x17, 1
    bn.lid x17, 256(x2)
    addi x17, x17, 1
    bn.lid x17, 288(x2)
    addi x17, x17, 1
    bn.lid x17, 320(x2)

    # ---- rshi-reorder: pack 8 P1 entries into w1, w3, w5, ..., w15 ----
    # from bngfaes expand_352.
    bn.rshi w15, w31, w10 >> 160
    bn.rshi w14, w10, w9 >> 160
    bn.rshi w13, w9, w31 >> 160
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w9, w8 >> 64
    bn.rshi w11, w8, w7 >> 64
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w7, w6 >> 224
    bn.rshi w9, w6, w31 >> 224
    bn.rshi w9, w31, w9 >> 160
    bn.rshi w8, w6, w5 >> 128
    bn.rshi w7, w5, w31 >> 128
    bn.rshi w7, w31, w7 >> 160
    bn.rshi w6, w5, w4 >> 32
    bn.rshi w5, w4, w3 >> 32
    bn.rshi w5, w31, w5 >> 160
    bn.rshi w4, w3, w2 >> 192
    bn.rshi w3, w2, w31 >> 192
    bn.rshi w3, w31, w3 >> 160
    bn.rshi w2, w2, w1 >> 96
    bn.rshi w1, w1, w31 >> 96
    bn.rshi w1, w31, w1 >> 160

    # Restore caller's x5, x6 and free stack
    lw x5, 352(x2)
    lw x6, 356(x2)
    addi x2, x2, 384
    ret

#endif

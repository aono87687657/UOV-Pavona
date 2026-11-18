/* Standalone harness — measure ONE `aes128` encrypt call (compute-AES path).
 *
 * aes128 expects round keys pre-loaded in w5..w14 (each duplicated to high
 * 128 b for dual-block packing) and w28 (key duplicated). Constants w23/w24/
 * w25 (affine_value/msb_mask/shiftrow_mask) are loaded from .data.  IV in
 * w29; counter-increment in w15; byte-swap mask in w30.
 *
 * Round keys are zeroed (cycle count is independent of their values), so the
 * resulting ciphertext is meaningless — the point is purely cycle stats.
 *
 * Use `--dump-stats` to read function-level cycle counts.
 */
.section .data

.balign 32
.global shiftrow_mask
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00

.balign 32
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080

.balign 32
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363

.section .text.start
.global main
.balign 4
main:
    bn.xor w31, w31, w31
    bn.wsrw acc, w31

    # round keys w5..w14 = 0 (cycle count independent of key values)
    bn.xor w5,  w5,  w5
    bn.xor w6,  w6,  w6
    bn.xor w7,  w7,  w7
    bn.xor w8,  w8,  w8
    bn.xor w9,  w9,  w9
    bn.xor w10, w10, w10
    bn.xor w11, w11, w11
    bn.xor w12, w12, w12
    bn.xor w13, w13, w13
    bn.xor w14, w14, w14
    bn.xor w27, w27, w27
    bn.xor w28, w28, w28

    # counter-increment constant w15 (0x02 at byte 12 and byte 28)
    bn.addi w15, w31, 0x2
    bn.or  w15, w15, w15 << 128
    bn.rshi w15, w15, w31 >> 160

    # byte-swap mask w30 (0xff at byte 12 and byte 28)
    bn.addi w30, w31, 0xff
    bn.or  w30, w30, w30 << 128
    bn.rshi w30, w30, w31 >> 160

    # constants for Substitute affine + ShiftRow
    la x5, affine_value
    li x6, 23
    bn.lid x6, 0(x5)

    la x5, msb_mask
    li x6, 24
    bn.lid x6, 0(x5)

    la x5, shiftrow_mask
    li x6, 25
    bn.lid x6, 0(x5)

    # IV w29 (LE counter = 1 in byte position 12)
    bn.addi w29, w31, 0x01
    bn.or  w29, w31, w29 << 224

    # call aes128 ONCE
    jal x1, aes128

    ecall

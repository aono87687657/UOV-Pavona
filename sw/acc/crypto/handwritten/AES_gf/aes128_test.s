/* Standalone harness for `aes128` (compute-AES dual-block).
 *
 * Brings up the constants/round keys aes128 expects, then calls it once.
 * Use `--dump-stats` to read function-level cycle counts.
 *
 * Generates 2 AES blocks per call (32 B = 1 WDR) via dual-block packing.
 */
.section .data

.balign 32
.global key
key:
    .zero 16
    .zero 16

.balign 32
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b
    .zero 26

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

    # counter-increment constant (0x02 at byte 12 and byte 28)
    bn.addi w15, w31, 0x2
    bn.or w15, w15, w15 << 128
    bn.rshi w15, w15, w31 >> 160

    # byte-swap mask (0xff at byte 12 and byte 28)
    bn.addi w30, w31, 0xff
    bn.or w30, w30, w30 << 128
    bn.rshi w30, w30, w31 >> 160

    # load AES128 key into w28 (low 16 B), zero high 16 B
    la x5, key
    li x6, 28
    bn.lid x6, 0(x5)
    bn.rshi w28, w28, w31 >> 128
    bn.rshi w28, w31, w28 >> 128

    # constants for KeySchedule + Substitute affine map
    la x5, rcon
    li x6, 26
    bn.lid x6, 0(x5)

    la x5, affine_value
    li x6, 23
    bn.lid x6, 0(x5)

    la x5, msb_mask
    li x6, 24
    bn.lid x6, 0(x5)

    la x5, shiftrow_mask
    li x6, 25
    bn.lid x6, 0(x5)

    # IV = 1 in byte position 12 (LE counter)
    bn.addi w29, w31, 0x01
    bn.or w29, w31, w29 << 224

    # KeySchedule × 10 → fill w5..w14 with round keys
    li x5, 5
    li x6, 28
    loopi 10, 2
        jal x1, KeySchedule
        bn.movr x5++, x6

    # double round keys for dual-block (low 128 = block0, high 128 = block1)
    bn.or w5,  w5,  w5  << 128
    bn.or w6,  w6,  w6  << 128
    bn.or w7,  w7,  w7  << 128
    bn.or w8,  w8,  w8  << 128
    bn.or w9,  w9,  w9  << 128
    bn.or w10, w10, w10 << 128
    bn.or w11, w11, w11 << 128
    bn.or w12, w12, w12 << 128
    bn.or w13, w13, w13 << 128
    bn.or w14, w14, w14 << 128

    # restore w28 = original key (KeySchedule mutated it), then duplicate to high half
    la x5, key
    li x6, 28
    bn.lid x6, 0(x5)
    bn.rshi w28, w28, w31 >> 128
    bn.rshi w28, w31, w28 >> 128
    bn.or w28, w28, w28 << 128

    # call aes128 ONCE (this is the function we're measuring)
    jal x1, aes128

    ecall

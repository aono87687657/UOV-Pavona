/* kg bank objects: key schedule A, two encryptions, rekey B (key 4 bytes off 32-byte alignment), one
 * encryption (counter wrap at 0xffffffff), rekey A, one encryption; packed schedule 4 bytes off 32-byte
 * alignment, IVs loaded before the key schedule; sentinels in every register the test
 * does not use, guards around the packed schedule. */
.section .data
.balign 32
key_a: .word 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
.balign 32
key_b_pad: .word 0
key_b: .word 0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09
.balign 32
rk_guard_lo: .fill 9, 4, 0x2468ace0
round_keys: .zero 176
rk_guard: .fill 8, 4, 0x12345678
.balign 32
output: .zero 128
deltas: .zero 16
.balign 32
wsr_output: .zero 96
flags_output: .word 0
.balign 32
ivs:
    .word 0, 0, 0, 0x000000fe, 0, 0, 0, 0x000000ff
    .word 0, 0, 0, 0x00000100, 0, 0, 0, 0x00000101
    .word 0, 0, 0, 0xffffffff, 0, 0, 0, 0x00000000
    .word 0, 0, 0, 0x000003e8, 0, 0, 0, 0x000003e9
.balign 32
sentinels:
.set sentinel_word, 0x31415900
.rept 32
    .fill 8, 4, sentinel_word
    .set sentinel_word, sentinel_word + 1
.endr

.section .text.start
.globl main
main:
    la x6, sentinels
    li x5, 0
    loopi 32, 2
        bn.lid x5++, 0(x6)
        addi x6, x6, 32
    bn.wsrw mod, w0
    bn.wsrw acc, w1
    bn.wsrw acch, w2
    li x2, 0x44556677
    li x3, 0x44556677
    li x4, 0x44556677
    li x9, 0x44556677
    li x12, 0x44556677
    li x13, 0x44556677
    li x14, 0x44556677
    li x15, 0x44556677
    li x16, 0x44556677
    li x17, 0x44556677
    li x18, 0x44556677
    li x19, 0x44556677
    li x20, 0x44556677
    li x21, 0x44556677
    li x22, 0x44556677
    li x23, 0x44556677
    li x24, 0x44556677
    li x25, 0x44556677
    li x26, 0x44556677
    li x27, 0x44556677
    li x28, 0x44556677
    li x30, 0x44556677
    li x31, 0x44556677
    li x5, 0xa5
    csrrw x0, flags, x5
    la x6, ivs
    bn.ld w18, 0(x6)
    la x10, key_a
    la x11, round_keys
    jal x1, AES_128_keyschedule
    la x5, round_keys
    sub x5, x11, x5
    la x6, deltas
    sw x5, 0(x6)
    jal x1, aes128_dual_table
    la x6, output
    bn.sd w2, 0(x6)
    la x6, ivs
    bn.ld w18, 32(x6)
    jal x1, aes128_dual_table
    la x6, output
    bn.sd w2, 32(x6)
    la x6, ivs
    bn.ld w18, 64(x6)
    la x10, key_b
    la x11, round_keys
    jal x1, AES_128_keyschedule
    la x5, round_keys
    sub x5, x11, x5
    la x6, deltas
    sw x5, 4(x6)
    jal x1, aes128_dual_table
    la x6, output
    bn.sd w2, 64(x6)
    la x6, ivs
    bn.ld w18, 96(x6)
    la x10, key_a
    la x11, round_keys
    jal x1, AES_128_keyschedule
    la x5, round_keys
    sub x5, x11, x5
    la x6, deltas
    sw x5, 8(x6)
    jal x1, aes128_dual_table
    la x6, output
    bn.sd w2, 96(x6)
    la x5, flags_output
    csrrs x6, flags, x0
    sw x6, 0(x5)
    la x5, wsr_output
    bn.wsrr w2, mod
    bn.sd w2, 0(x5)
    bn.wsrr w2, acc
    bn.sd w2, 32(x5)
    bn.wsrr w2, acch
    bn.sd w2, 64(x5)
    ecall

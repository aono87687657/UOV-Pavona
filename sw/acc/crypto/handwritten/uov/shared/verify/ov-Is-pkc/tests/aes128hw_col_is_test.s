/* Two chained AES columns with guarded scratch and preserved-state sentinels. */
.section .data
.balign 32
frame: .zero 32
key: .word 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
.balign 32
round_keys: .zero 192
.balign 32
guard_lo: .fill 8, 4, 0x12345678
scratch: .fill 8, 4, 0xdeadbeef
guard_hi: .fill 8, 4, 0x87654321
output: .zero 64
wsr_output: .zero 96
flags_output: .word 0
counter: .word 254
repeat_call: .word 1
.balign 32
rk_before: .zero 192
sentinels:
.set sentinel_word, 0x31415900
.rept 32
    .fill 8, 4, sentinel_word
    .set sentinel_word, sentinel_word + 1
.endr

.section .text.start
.globl main
main:
    la x10, key
    la x11, round_keys
    jal x1, AES_128_keyschedule
    la x5, round_keys
    la x6, rk_before
    loopi 6, 4
        bn.ld w0, 0(x5)
        bn.sd w0, 0(x6)
        addi x5, x5, 32
        addi x6, x6, 32

    la x6, sentinels
    li x5, 0
    loopi 32, 2
        bn.lid x5++, 0(x6)
        addi x6, x6, 32
    bn.xor w31, w31, w31
    bn.wsrw mod, w0
    bn.wsrw acc, w1
    bn.wsrw acch, w2

    la x3, frame
    la x18, round_keys
    la x5, scratch
    sw x5, 20(x3)
    la x5, counter
    lw x13, 0(x5)
    li x2, 0x44556677
    li x4, 0x44556677
    li x7, 0x44556677
    li x8, 0x44556677
    li x9, 0x44556677
    li x10, 0x44556677
    li x11, 0x44556677
    li x12, 0x44556677
    li x14, 0x44556677
    li x15, 0x44556677
    li x16, 0x44556677
    li x17, 0x44556677
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
    li x29, 0x44556677
    li x30, 0x44556677
    li x31, 0x44556677
    li x5, 0xa5
    csrrw x0, flags, x5

    jal x1, aes128_col_is
    la x5, output
    bn.sd w13, 0(x5)
    la x5, repeat_call
    lw x6, 0(x5)
    beq x6, x0, save_state
    jal x1, aes128_col_is
    la x5, output
    bn.sd w13, 32(x5)
save_state:
    la x5, flags_output
    csrrs x6, flags, x0
    sw x6, 0(x5)
    la x5, wsr_output
    bn.wsrr w13, mod
    bn.sd w13, 0(x5)
    bn.wsrr w13, acc
    bn.sd w13, 32(x5)
    bn.wsrr w13, acch
    bn.sd w13, 64(x5)
    ecall

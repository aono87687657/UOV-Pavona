/* AES memory-ABI test: packed round keys, unaligned blocks, and saved state. */
.section .data
.balign 32
sentinel:
    .word 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
    .word 0xa5a5a5a5, 0x5a5a5a5a, 0x13579bdf, 0x2468ace0
mode: .word 0
key: .zero 16
plaintext: .zero 16
ct_guard_lo: .word 0x12345678
ciphertext: .zero 16
ct_guard_hi: .word 0x87654321
rk_guard_lo: .word 0x11223344
round_keys: .zero 176
rk_guard_hi: .word 0x44332211
.balign 32
ks_state: .zero 96

.section .text.start
.globl main
main:
    la x6, sentinel
    li x5, 0
    loopi 32, 1
        bn.lid x5++, 0(x6)
    li x2, 0x44556677
    li x3, 0x44556677
    li x4, 0x44556677
    li x9, 0x44556677
    li x23, 0x44556677
    li x24, 0x44556677
    li x25, 0x44556677
    li x26, 0x44556677
    li x27, 0x44556677
    li x28, 0x44556677
    li x5, 0xa5
    csrrw x0, flags, x5

    la x10, key
    la x11, round_keys
    jal x1, AES_128_keyschedule
    la x5, ks_state
    bn.sd w0, 0(x5)
    bn.sd w1, 32(x5)
    sw x10, 64(x5)
    sw x11, 68(x5)
    csrrs x6, flags, x0
    sw x6, 72(x5)

    li x17, 0x44556677
    li x18, 0x44556677
    li x30, 0x44556677
    la x10, round_keys
    la x11, plaintext
    la x12, ciphertext
    la x5, mode
    lw x5, 0(x5)
    beq x5, x0, encrypt
    addi x12, x11, 0
encrypt:
    jal x1, AES_128_encrypt
    la x5, ks_state
    csrrs x6, flags, x0
    sw x6, 76(x5)
    ecall

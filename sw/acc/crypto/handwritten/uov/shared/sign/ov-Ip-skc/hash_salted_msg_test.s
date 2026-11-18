.section .data
.balign 4
msg_len:
    .zero 4
.balign 32 
msg:
    .zero 1000
.balign 32
stack:
    .zero 640
stack_end:
.section .text.start
.balign 4
.global main
main:

    bn.xor w31, w31, w31
    bn.xor w29, w29, w29
    la x2, stack_end
    la x12, msg
    la x13, msg_len
    lw x13, 0(x13) 

    csrrw x0, rnd_prefetch, x0
    li x5, 0xA                      # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x13, 16
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, 0x7d9, x31
    bn.wsrr w1, rnd
    bn.rshi w1, w1, w31 >> 128
    bn.rshi w1, w31, w1 >> 128

    jal x1, hash_salted_msg

ecall

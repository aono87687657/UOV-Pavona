.section .data
.balign 32
key0:
    .zero 32
.balign 32
m0: 
    .word 0x80,0x0,0x0,0x0
    .word 0xc0,0x0,0x0,0x0
m1: 
    .word 0xe0,0x0,0x0,0x0
    .word 0xf0,0x0,0x0,0x0
m2: 
    .word 0xf8,0x0,0x0,0x0
    .word 0xfc,0x0,0x0,0x0
.section .text.start
.global aes128_ext_test
.balign 4
aes128_ext_test:

    addi x5, x0, 0
    la x6, key0
    bn.lid x5,0(x6)        

    addi x5, x0, 1
    la x6, m0
    bn.lid x5,0(x6)        

    
    bn.xor w30, w30, w30
    bn.rshi w30, w0, w30 >> 128
    bn.or w0, w30, w0

    bn.xor w1,w1,w0


    bn.aes128.kf w0, w0, 1
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 2
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 3
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 4
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 5
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 6
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 7
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 8
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 9
    bn.aes128.encm w1, w1, w0

    bn.aes128.kf w0, w0, 10
    bn.aes128.encf w1, w1, w0

    addi x5, x0, 0
    la x6, key0
    bn.lid x5,0(x6)        

    addi x5, x0, 2
    la x6, m1
    bn.lid x5,0(x6)        



    bn.xor w30, w30, w30
    bn.rshi w30, w0, w30 >> 128
    bn.or w0, w30, w0

    bn.xor w2,w2,w0


    bn.aes128.kf w0, w0, 1
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 2
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 3
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 4
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 5
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 6
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 7
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 8
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 9
    bn.aes128.encm w2, w2, w0

    bn.aes128.kf w0, w0, 10
    bn.aes128.encf w2, w2, w0

    addi x5, x0, 0
    la x6, key0
    bn.lid x5,0(x6)        

    addi x5, x0, 3
    la x6, m2
    bn.lid x5,0(x6)        



    bn.xor w30, w30, w30
    bn.rshi w30, w0, w30 >> 128
    bn.or w0, w30, w0

    bn.xor w3,w3,w0


    bn.aes128.kf w0, w0, 1
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 2
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 3
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 4
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 5
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 6
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 7
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 8
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 9
    bn.aes128.encm w3, w3, w0

    bn.aes128.kf w0, w0, 10
    bn.aes128.encf w3, w3, w0


    ecall
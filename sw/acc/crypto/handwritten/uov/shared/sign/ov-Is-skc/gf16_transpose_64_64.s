.section .text
.global gf16_transpose_64_64
.balign 4
gf16_transpose_64_64:
    bn.xor w31, w31, w31
    # Save registers
    addi x2, x2, -32
    sw x10, 0(x2)

    li x26, 2048
    li x27, 30
    la x28, mask
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 4

    li x29, 3
    li x30, 2
    li x31, 1

    loopi 32, 12
        bn.lid x0, 0(x10++)
        bn.lid x31, 0(x10++)
        bn.and w2, w0, w30
        bn.and w3, w1, w30
        bn.rshi w3, w3, w31 >> 252
        bn.or w2, w2, w3
        bn.and w3, w0, w29
        bn.rshi w3, w31, w3 >> 4
        bn.and w4, w1, w29 
        bn.or w3, w3, w4
        bn.sid x30, -64(x10)
        bn.sid x29, -32(x10)

    lw x10, 0(x2) 
    
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 8
    loopi 16, 14
        loopi 2, 12
            bn.lid x0, 0(x10++)
            bn.lid x31, 32(x10)
            bn.and w2, w0, w30
            bn.and w3, w1, w30
            bn.rshi w3, w3, w31 >> 248
            bn.or w2, w2, w3
            bn.and w3, w0, w29
            bn.rshi w3, w31, w3 >> 8
            bn.and w4, w1, w29 
            bn.or w3, w3, w4
            bn.sid x30, -32(x10)
            bn.sid x29, 32(x10)
        addi x10, x10, 64
    
    lw x10, 0(x2) 
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 16
    loopi 8, 14
        loopi 4, 12
            bn.lid x0, 0(x10++)
            bn.lid x31, 96(x10)
            bn.and w2, w0, w30
            bn.and w3, w1, w30
            bn.rshi w3, w3, w31 >> 240
            bn.or w2, w2, w3
            bn.and w3, w0, w29
            bn.rshi w3, w31, w3 >> 16
            bn.and w4, w1, w29 
            bn.or w3, w3, w4
            bn.sid x30, -32(x10)
            bn.sid x29, 96(x10)
        addi x10, x10, 128
    
    lw x10, 0(x2) 
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 32
    loopi 4, 14
        loopi 8, 12
            bn.lid x0, 0(x10++)
            bn.lid x31, 224(x10)
            bn.and w2, w0, w30
            bn.and w3, w1, w30
            bn.rshi w3, w3, w31 >> 224
            bn.or w2, w2, w3
            bn.and w3, w0, w29
            bn.rshi w3, w31, w3 >> 32
            bn.and w4, w1, w29 
            bn.or w3, w3, w4
            bn.sid x30, -32(x10)
            bn.sid x29, 224(x10)
        addi x10, x10, 256
    
    lw x10, 0(x2) 
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 64
    loopi 2, 14
        loopi 16, 12
            bn.lid x0, 0(x10++)
            bn.lid x31, 480(x10)
            bn.and w2, w0, w30
            bn.and w3, w1, w30
            bn.rshi w3, w3, w31 >> 192
            bn.or w2, w2, w3
            bn.and w3, w0, w29
            bn.rshi w3, w31, w3 >> 64
            bn.and w4, w1, w29 
            bn.or w3, w3, w4
            bn.sid x30, -32(x10)
            bn.sid x29, 480(x10)
        addi x10, x10, 512
    
    
    lw x10, 0(x2) 
    bn.lid x27, 0(x28++)
    bn.rshi w29, w30, w30 >> 128
    loopi 32, 12
        bn.lid x0, 0(x10++)
        bn.lid x31, 992(x10)
        bn.and w2, w0, w30
        bn.and w3, w1, w30
        bn.rshi w3, w3, w31 >> 128
        bn.or w2, w2, w3
        bn.and w3, w0, w29
        bn.rshi w3, w31, w3 >> 128
        bn.and w4, w1, w29 
        bn.or w3, w3, w4
        bn.sid x30, -32(x10)
        bn.sid x29, 992(x10)

    lw x10, 0(x2)
    addi x2, x2, 32
    ret

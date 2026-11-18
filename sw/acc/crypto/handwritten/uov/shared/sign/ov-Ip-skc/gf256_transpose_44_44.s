.section .text
.global gf256_transpose_44_44
.balign 4
gf256_transpose_44_44:
    bn.xor w31, w31, w31

    la x24, mask
    li x23, 30
    bn.lid x23, 0(x24++)
    bn.rshi w29, w30, w30 >> 8
    li x31, 1
    li x30, 2
    li x29, 3
    li x28, 4
    li x27, 5 
    li x26, 6
    li x25, 7
    loopi 22, 24
        bn.lid x0, 0(x10++)  
        bn.lid x31, 0(x10++)  
        bn.lid x30, 0(x10++)  
        bn.lid x29, 0(x10++)  
        bn.and w4, w0, w30
        bn.and w5, w2, w30
        bn.rshi w5, w5, w31 >> 248
        bn.or w4, w4, w5
        bn.and w5, w1, w30
        bn.and w6, w3, w30
        bn.rshi w6, w6, w31 >> 248
        bn.or w5, w5, w6
        bn.and w6, w0, w29
        bn.rshi w6, w31, w6 >> 8
        bn.and w7, w2, w29
        bn.or w6, w6, w7
        bn.and w7, w1, w29
        bn.rshi w7, w31, w7 >> 8
        bn.and w8, w3, w29
        bn.or w7, w7, w8
        bn.sid x28, -128(x10)
        bn.sid x27, -96(x10)
        bn.sid x26, -64(x10)
        bn.sid x25, -32(x10)

    bn.lid x23, 0(x24++)
    bn.rshi w29, w30, w30 >> 16
    li x20, 2816
    sub x10, x10, x20
    loopi 11, 26
        loopi 2, 24
            bn.lid x0, 0(x10++)  
            bn.lid x31, 0(x10++)  
            bn.lid x30, 64(x10)  
            bn.lid x29, 96(x10)  
            bn.and w4, w0, w30
            bn.and w5, w2, w30  
            bn.rshi w5, w5, w31 >> 240
            bn.or w4, w4, w5
            bn.and w5, w1, w30
            bn.and w6, w3, w30
            bn.rshi w6, w6, w31 >> 240
            bn.or w5, w5, w6
            bn.and w6, w0, w29
            bn.rshi w6, w31, w6 >> 16
            bn.and w7, w2, w29
            bn.or w6, w6, w7
            bn.and w7, w1, w29
            bn.rshi w7, w31, w7 >> 16
            bn.and w8, w3, w29
            bn.or w7, w7, w8
            bn.sid x28, -64(x10)
            bn.sid x27, -32(x10)
            bn.sid x26, 64(x10)
            bn.sid x25, 96(x10)
        addi x10, x10, 128
    bn.lid x23, 0(x24++)
    bn.rshi w29, w30, w30 >> 32
    sub x10, x10, x20
    loopi 6, 26
        loopi 4, 24
            bn.lid x0, 0(x10++)  
            bn.lid x31, 0(x10++)  
            bn.lid x30, 192(x10)  
            bn.lid x29, 224(x10)  
            bn.and w4, w0, w30
            bn.and w5, w2, w30  
            bn.rshi w5, w5, w31 >> 224
            bn.or w4, w4, w5
            bn.and w5, w1, w30
            bn.and w6, w3, w30
            bn.rshi w6, w6, w31 >> 224
            bn.or w5, w5, w6
            bn.and w6, w0, w29
            bn.rshi w6, w31, w6 >> 32
            bn.and w7, w2, w29
            bn.or w6, w6, w7
            bn.and w7, w1, w29
            bn.rshi w7, w31, w7 >> 32
            bn.and w8, w3, w29
            bn.or w7, w7, w8
            bn.sid x28, -64(x10)
            bn.sid x27, -32(x10)
            bn.sid x26, 192(x10)
            bn.sid x25, 224(x10)
        addi x10, x10, 256
    
    bn.lid x23, 0(x24++)
    bn.rshi w29, w30, w30 >> 64
    li x20, 3072
    sub x10, x10, x20
    loopi 3, 26
        loopi 8, 24
            bn.lid x0,  0(x10++)  
            bn.lid x31, 0(x10++)  
            bn.lid x30, 448(x10)  
            bn.lid x29, 480(x10)  
            bn.and w4, w0, w30
            bn.and w5, w2, w30  
            bn.rshi w5, w5, w31 >> 192
            bn.or w4, w4, w5
            bn.and w5, w1, w30
            bn.and w6, w3, w30
            bn.rshi w6, w6, w31 >> 192
            bn.or w5, w5, w6
            bn.and w6, w0, w29
            bn.rshi w6, w31, w6 >> 64
            bn.and w7, w2, w29
            bn.or w6, w6, w7
            bn.and w7, w1, w29
            bn.rshi w7, w31, w7 >> 64
            bn.and w8, w3, w29
            bn.or w7, w7, w8
            bn.sid x28, -64(x10)
            bn.sid x27, -32(x10)
            bn.sid x26, 448(x10)
            bn.sid x25, 480(x10)
        addi x10, x10, 512
    
    bn.lid x23, 0(x24++)
    bn.rshi w29, w30, w30 >> 128
    sub x10, x10, x20
    loopi 2, 26
        loopi 16, 24
            bn.lid x0,  0(x10++)  
            bn.lid x31, 0(x10++)  
            bn.lid x30, 960(x10)  
            bn.lid x29, 992(x10)  
            bn.and w4, w0, w30
            bn.and w5, w2, w30  
            bn.rshi w5, w5, w31 >> 128
            bn.or w4, w4, w5
            bn.and w5, w1, w30
            bn.and w6, w3, w30
            bn.rshi w6, w6, w31 >> 128
            bn.or w5, w5, w6
            bn.and w6, w0, w29
            bn.rshi w6, w31, w6 >> 128
            bn.and w7, w2, w29
            bn.or w6, w6, w7
            bn.and w7, w1, w29
            bn.rshi w7, w31, w7 >> 128
            bn.and w8, w3, w29
            bn.or w7, w7, w8
            bn.sid x28, -64(x10)
            bn.sid x27, -32(x10)
            bn.sid x26, 960(x10)
            bn.sid x25, 992(x10)
        addi x10, x10, 1024
        
    li x20, 4096
    sub x10, x10, x20   
    loopi 32, 8
        bn.lid x0,  0(x10++)  
        bn.lid x31, 0(x10++)  
        bn.lid x30, 1984(x10)  
        bn.lid x29, 2016(x10)  
        bn.sid x0, -64(x10)
        bn.sid x30, -32(x10)
        bn.sid x31, 1984(x10)
        bn.sid x29, 2016(x10)

    ret

 
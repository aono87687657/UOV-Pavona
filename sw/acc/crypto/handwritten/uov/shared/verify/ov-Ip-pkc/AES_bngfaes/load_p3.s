/* load_p3 (Ip verify, bngfaes): load 8 packed 44B P3 columns (352B) and realign
 * each to a 32B WDR boundary via rshi slides.
 * in   : x12 packed-P3 read ptr (advanced +352), w31 zero
 * clob : w8-w23, x12 (+352); no flags (bn.ld/bn.rshi only)
 * stack: none (leaf)
 */
.section .text
.balign 4
.global load_p3
load_p3:
    bn.ld w8,  0(x12++)
    bn.ld w9,  0(x12++)
    bn.ld w10, 0(x12++)
    bn.ld w11, 0(x12++)
    bn.ld w12, 0(x12++)
    bn.ld w13, 0(x12++)
    bn.ld w14, 0(x12++)
    bn.ld w15, 0(x12++)
    bn.ld w16, 0(x12++)
    bn.ld w17, 0(x12++)
    bn.ld w18, 0(x12++)

    bn.rshi w23, w31, w18 >> 160
    bn.rshi w22, w18, w17 >> 160

    bn.rshi w21, w17, w31 >> 160
    bn.rshi w21, w31, w21 >> 160
    bn.rshi w20, w17, w16 >> 64

    bn.rshi w19, w16, w15 >> 64
    bn.rshi w19, w31, w19 >> 160
    bn.rshi w18, w15, w14 >> 224

    bn.rshi w17, w14, w31 >> 224
    bn.rshi w17, w31, w17 >> 160
    bn.rshi w16, w14, w13 >> 128

    bn.rshi w15, w13, w31 >> 128
    bn.rshi w15, w31, w15 >> 160
    bn.rshi w14, w13, w12 >> 32

    bn.rshi w13, w12, w11 >> 32
    bn.rshi w13, w31, w13 >> 160
    bn.rshi w12, w11, w10 >> 192

    bn.rshi w11, w10, w31 >> 192
    bn.rshi w11, w31, w11 >> 160
    bn.rshi w10, w10, w9 >> 96

    bn.rshi w9, w9, w31 >> 96
    bn.rshi w9, w31, w9 >> 160
    
    ret 
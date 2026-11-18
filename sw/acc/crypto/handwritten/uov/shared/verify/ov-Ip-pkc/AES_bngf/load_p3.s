/* load_p3 (Ip verify, bngf): load 8 packed 44B P3 columns (352B) and realign
 * each to a 32B WDR boundary via rshi slides.
 * in   : x12 packed-P3 read ptr (advanced +352), w31 zero
 * clob : w9-w24, x12 (+352); no flags (bn.ld/bn.rshi only)
 * stack: none (leaf)
 */
.section .text
.balign 4
.global load_p3
load_p3:
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
    bn.ld w19, 0(x12++)

    bn.rshi w24, w31, w19 >> 160
    bn.rshi w23, w19, w18 >> 160

    bn.rshi w22, w18, w31 >> 160
    bn.rshi w22, w31, w22 >> 160
    bn.rshi w21, w18, w17 >> 64

    bn.rshi w20, w17, w16 >> 64
    bn.rshi w20, w31, w20 >> 160
    bn.rshi w19, w16, w15 >> 224

    bn.rshi w18, w15, w31 >> 224
    bn.rshi w18, w31, w18 >> 160
    bn.rshi w17, w15, w14 >> 128

    bn.rshi w16, w14, w31 >> 128
    bn.rshi w16, w31, w16 >> 160
    bn.rshi w15, w14, w13 >> 32

    bn.rshi w14, w13, w12 >> 32
    bn.rshi w14, w31, w14 >> 160
    bn.rshi w13, w12, w11 >> 192

    bn.rshi w12, w11, w31 >> 192
    bn.rshi w12, w31, w12 >> 160
    bn.rshi w11, w11, w10 >> 96

    bn.rshi w10, w10, w31 >> 96
    bn.rshi w10, w31, w10 >> 160
    
    ret 
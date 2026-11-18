/* KeySchedule (Ip verify, bngf): one AES-128 key-schedule round.
 * RotWord + SubBytes (Itoh-Tsujii a^254 via gfmul.8.vv) + affine + rcon + column derive.
 * in    : w27 affine_value, w28 msb_mask, w31 zero; mod0=0x11b preset by caller
 * in-out: w30 round key -> next round key; w26 rcon carrier (8 bits consumed per call)
 * clob  : w20-w25, FG0
 * stack : none (leaf; no GPR writes)
 */
.section .text
.balign 4
.global KeySchedule
KeySchedule:


    /*getting third word(last 32 bits) of the key store in w25*/
    bn.rshi w25, w31, w30 >> 96
    /*rotate word*/
    bn.rshi w24, w25, w31 >> 8
    bn.rshi w24, w31, w24 >>  224
    bn.or w25, w24, w25 >> 8

    bn.gfmul.8.vv w24, w25, w25 /*w24:a^2*/
    bn.gfmul.8.vv w23, w24, w24 /*w23:a^4*/
    bn.gfmul.8.vv w24, w24, w23 /*w24: a^(2+4)*/
    bn.gfmul.8.vv w23, w23, w23 /*w23:a^8*/
    bn.gfmul.8.vv w24, w24, w23 /*w24: a^(6+8)*/
    bn.gfmul.8.vv w23, w23, w23 /*w23:a^16*/
    bn.gfmul.8.vv w24, w24, w23 /*w24: a^(14+16)*/
    bn.gfmul.8.vv w23, w23, w23 /*:a^32*/
    bn.gfmul.8.vv w24, w24, w23 /*w24: a^(30+32)*/
    bn.gfmul.8.vv w23, w23, w23 /*w23:a^64*/
    bn.gfmul.8.vv w24, w24, w23 /*w24: a^(62+64)*/
    bn.gfmul.8.vv w23, w23, w23 /*w23:a^128*/
    bn.gfmul.8.vv w22, w24, w23 /*w22: a^(126+128) = a^254 = a^-1 (Itoh-Tsujii inverse)*/
   
    /*w24: b circular shift <<< 1*/
    bn.and w24, w22, w28 
    bn.xor w23, w22, w24
    bn.rshi w24, w31, w24 >> 7
    bn.rshi w23, w23, w31 >> 255
    bn.xor w24, w23, w24

    /*w23: b circulant shift <<< 2 */
    bn.and w23, w24, w28 
    bn.xor w21, w24, w23
    bn.rshi w23, w31, w23 >> 7
    bn.rshi w21, w21, w31 >> 255
    bn.xor w23, w21, w23

    /*w24: b<<<1 XOR b<<<2*/
    bn.xor w24, w23, w24

    /*w23: b circulant shift <<< 3 */
    bn.and w21, w23, w28
    bn.xor w20, w23, w21
    bn.rshi w21, w31, w21 >> 7
    bn.rshi w20, w20, w31 >> 255 
    bn.xor w23, w21, w20

    /*w24: b<<<3 XOR (b<<<1 XOR b<<<2)*/
    bn.xor w24, w23, w24

    /*w23: b circulant shift <<< 4 */
    bn.and w21, w23, w28
    bn.xor w20, w23, w21
    bn.rshi w21, w31, w21 >> 7
    bn.rshi w20, w20, w31 >> 255 
    bn.xor w23, w21, w20

    /*w24: b<<<4 XOR (b<<<1 XOR b<<<2 XOR b<<<3)*/
    bn.xor w24, w23, w24
    /*w22: b XOR (b<<<1 XOR b<<<2 XOR b<<<3 XOR b<<<4)*/
    bn.xor w22, w22, w24
    /*w22: affine_val XOR (b XOR b<<<1 XOR b<<<2 XOR b<<<3 XOR b<<<4)*/
    bn.xor w22, w22, w27
    /*Subtitute done*/

    /*Beacuse of affine value{w27} is 256bit i need to clear out unneeded part*/
    bn.rshi w22, w22, w31 >> 32
    bn.rshi w22, w31, w22 >> 224

    /*Preparing round constant*/
    bn.rshi w25, w26, w31 >> 8
    bn.rshi w26, w31, w26 >> 8
    bn.rshi w25, w31, w25 >> 248

    /*Adding round constant*/
    bn.xor w25, w22, w25
    
    bn.xor w24, w25, w30 
    bn.rshi w24, w24, w31 >> 32
    bn.rshi w24, w31, w24 >> 224

    bn.addi w25, w31, 0xff
    bn.or w25, w25, w25 << 8
    bn.or w25, w25, w25 << 16

    bn.and w23, w30, w25 << 32
    bn.xor w23, w23, w24 << 32

    bn.and w21, w30, w25 << 64
    bn.xor w21, w21, w23 << 32

    bn.and w20, w30, w25 << 96
    bn.xor w20, w20, w21 << 32

    bn.or w30, w20, w21
    bn.or w30, w30, w23
    bn.or w30, w30, w24
    ret
    
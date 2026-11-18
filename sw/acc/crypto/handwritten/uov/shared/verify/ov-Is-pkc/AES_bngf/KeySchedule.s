/* KeySchedule (Is verify, bngf): one AES-128 key-schedule round.
 * RotWord + SubBytes (Itoh-Tsujii a^254 via gfmul.8.vv) + affine + rcon + column derive.
 * in    : w23 affine_value, w24 msb_mask
 * in-out: w28 round key -> next round key; w26 rcon carrier (8 bits consumed per call)
 * clob  : w17-w22, w31 (rezeroed), x23, FG0; sets mod0=0x11b (caller restores 0x13 for gfmul.4)
 * stack : none (leaf)
 */
.section .text
.balign 4
.global KeySchedule
KeySchedule:
    # Set GF(256) polynomial in mod0 CSR: x^8 + x^4 + x^3 + x + 1 = 0x11B
    li x23, 0x0000011b
    csrrw x0, mod0, x23
    bn.xor w31,w31,w31

    /*getting third word(last 32 bits) of the key store in w92*/
    bn.rshi w22, w31, w28 >> 96
    /*rotate word*/
    bn.rshi w21, w22, w31 >> 8
    bn.rshi w21, w31, w21 >>  224
    bn.or w22, w21, w22 >> 8

    bn.gfmul.8.vv w21, w22, w22 /*w21:a^2*/
    bn.gfmul.8.vv w20, w21, w21 /*w20:a^4*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(2+4)*/
    bn.gfmul.8.vv w20, w20, w20 /*w20:a^8*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(6+8)*/
    bn.gfmul.8.vv w20, w20, w20 /*w20:a^16*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(14+16)*/
    bn.gfmul.8.vv w20, w20, w20 /*:a^32*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(30+32)*/
    bn.gfmul.8.vv w20, w20, w20 /*w20:a^64*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(62+64)*/
    bn.gfmul.8.vv w20, w20, w20 /*w20:a^128*/
    bn.gfmul.8.vv w21, w21, w20 /*w21: a^(126+128)*/

    bn.mov w17, w21
   
    /*w21: b circular shift <<< 1*/
    bn.and w21, w17, w24 
    bn.xor w20, w17, w21
    bn.rshi w21, w31, w21 >> 7
    bn.rshi w20, w20, w31 >> 255
    bn.xor w21, w20, w21

    /*w20: b circulant shift <<< 2 */
    bn.and w20, w21, w24 
    bn.xor w19, w21, w20
    bn.rshi w20, w31, w20 >> 7
    bn.rshi w19, w19, w31 >> 255
    bn.xor w20, w19, w20

    /*w21: b<<<1 XOR b<<<2*/
    bn.xor w21, w20, w21

    /*w20: b circulant shift <<< 3 */
    bn.and w19, w20, w24
    bn.xor w18, w20, w19
    bn.rshi w19, w31, w19 >> 7
    bn.rshi w18, w18, w31 >> 255 
    bn.xor w20, w19, w18

    /*w21: b<<<3 XOR (b<<<1 XOR b<<<2)*/
    bn.xor w21, w20, w21

    /*w20: b circulant shift <<< 4 */
    bn.and w19, w20, w24
    bn.xor w18, w20, w19
    bn.rshi w19, w31, w19 >> 7
    bn.rshi w18, w18, w31 >> 255 
    bn.xor w20, w19, w18

    /*w21: b<<<4 XOR (b<<<1 XOR b<<<2 XOR b<<<3)*/
    bn.xor w21, w20, w21
    /*w17: b XOR (b<<<1 XOR b<<<2 XOR b<<<3 XOR b<<<4)*/
    bn.xor w17, w17, w21
    /*w17: affine_val XOR (b XOR b<<<1 XOR b<<<2 XOR b<<<3 XOR b<<<4)*/
    bn.xor w17, w17, w23
    /*Subtitute done*/

    /*Beacuse of affine value{w23} is 256bit i need to clear out unneeded part*/
    bn.rshi w17, w17, w31 >> 32
    bn.rshi w17, w31, w17 >> 224

    /*Preparing round constant*/
    bn.rshi w22, w26, w31 >> 8
    bn.rshi w26, w31, w26 >> 8
    bn.rshi w22, w31, w22 >> 248

    /*Adding round constant*/
    bn.xor w22, w17, w22
    
    bn.xor w21, w22, w28 
    bn.rshi w21, w21, w31 >> 32
    bn.rshi w21, w31, w21 >> 224

    bn.addi w22, w31, 0xff
    bn.or w22, w22, w22 << 8
    bn.or w22, w22, w22 << 16

    bn.and w20, w28, w22 << 32
    bn.xor w20, w20, w21 << 32

    bn.and w19, w28, w22 << 64
    bn.xor w19, w19, w20 << 32

    bn.and w18, w28, w22 << 96
    bn.xor w18, w18, w19 << 32

    bn.or w28, w18, w19
    bn.or w28, w28, w20
    bn.or w28, w28, w21
    ret
    
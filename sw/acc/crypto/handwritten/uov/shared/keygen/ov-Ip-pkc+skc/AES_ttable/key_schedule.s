/* AES_128_keyschedule: T-table AES, expand 16B key -> 11 round keys (176B).
 *   SubWord via AES128_TABLE LSB (lw + andi 0xff = S[x]).
 * in:  x10 = 16B key (preserved) ; x11 = 176B RK buf out (advanced to base+160 = RK10)
 * out: RK0 (= key) at off 0, RK1 at 16, ... RK10 at 160.
 * clobber: x5..x8 (rk words), x12..x18, x29 (table base), x30, x31 (0xff0 mask).
 */

.section .text
.globl AES_128_keyschedule
AES_128_keyschedule:

    #round 0 = key copy
    lw   x5,  0(x10)
    lw   x6,  4(x10)
    lw   x7,  8(x10)
    lw   x8, 12(x10)
    sw   x5,  0(x11)
    sw   x6,  4(x11)
    sw   x7,  8(x11)
    sw   x8, 12(x11)

    la   x29, AES128_TABLE           # S-box / T-table base
    li   x31, 0xff0              # byte*16 mask
    addi x18, x0, 1              # Rcon start = 0x01

    #10 rounds
    loopi 10, 43
        slli x30, x8,  4           # extract 4 bytes from x8 (last word prev RK), each *16
        and  x15, x30, x31         # byte0 *16
        srli x30, x8,  4
        and  x12, x30, x31         # byte1 *16
        srli x30, x8, 12
        and  x13, x30, x31         # byte2 *16
        srli x30, x8, 20
        and  x14, x30, x31         # byte3 *16
        add  x30, x12, x29         # SubWord via AES128_TABLE (Te2 LSB = S[x])
        lw   x12, 0(x30)
        andi x12, x12, 0xff        # S[byte1]
        add  x30, x13, x29
        lw   x13, 0(x30)
        andi x13, x13, 0xff        # S[byte2]
        add  x30, x14, x29
        lw   x14, 0(x30)
        andi x14, x14, 0xff        # S[byte3]
        add  x30, x15, x29
        lw   x15, 0(x30)
        andi x15, x15, 0xff        # S[byte0]
        xor  x5, x5,  x18          # SubWord(RotWord) XOR Rcon then chain XOR; XOR Rcon (LSB)
        xor  x5, x5,  x12          # XOR S[byte1] in byte 0
        slli x13, x13, 8
        xor  x5, x5,  x13          # XOR S[byte2] in byte 1
        slli x14, x14, 16
        xor  x5, x5,  x14          # XOR S[byte3] in byte 2
        slli x15, x15, 24
        xor  x5, x5,  x15          # XOR S[byte0] in byte 3 (RotWord wrap)
        xor  x6, x6,  x5           # chain
        xor  x7, x7,  x6
        xor  x8, x8,  x7
        addi x11, x11, 16          # advance buf, store new RK
        sw   x5,  0(x11)
        sw   x6,  4(x11)
        sw   x7,  8(x11)
        sw   x8, 12(x11)
        slli x16, x18, 1           # Rcon = Rcon*x in GF(2^8), branchless
        andi x16, x16, 0xff        # low 8 bit
        andi x17, x18, 0x80        # MSB
        srli x17, x17, 7           # 0 or 1
        sub  x17, x0,  x17         # 0 or all-1
        andi x17, x17, 0x1b        # 0x1b iff MSB set
        xor  x18, x16, x17

    ret

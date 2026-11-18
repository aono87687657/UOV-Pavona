/* expandsk_ret_O_pkseed - SHAKE256(sk_seed) -> pk_seed || O (UOV-Ip).
 * Squeezes 94 blocks, then shifts the 16B pk_seed prefix out so O lands
 * 32B-aligned. The frame is NOT freed: x2 stays at the frame base on return,
 * and the caller reads pk_seed at 0(x2) (low 16B) and raw O at 32(x2) (2,992B).
 * pk_seed is stored zero-extended to the full 32B word; the bngfonly sign tier depends on it.
 * KeySchedule_sign reads w17[255:96] for RotWord, so a nonzero upper half corrupts RK1 right
 * off the load, and aes128_sign then XORs all 256 bits of the dual-stored key. bn.aes128.*
 * masks the key to 128 bits and does not care.
 * in:    x11 = sk_seed addr (32B), x2 = 32B-aligned stack, w31 = 0
 * clob:  x2 (-3040), x5, x31; w0, w1; kmac_cfg (left disabled on exit)
 * stack: 3040 B, kept live for the caller
 */
.section .text
.balign 4
.global expandsk_ret_O_pkseed
expandsk_ret_O_pkseed:
    # Assume sk_seed address in x11
    bn.lid x0, 0(x11)
    li x5, 0xA                       # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x0, 0x20
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    bn.wsrw 0x9, w0
    # Assume stack is 32 balign
    li x31, 3040
    sub x2, x2, x31
    addi x5, x2, 32
    loopi 94, 27
        bn.wsrr w0, 0xa
        bn.sid x0, 0(x5++)
        .rept 25
            NOP
        .endr
    li x31, 3008
    sub x5, x5, x31
    bn.lid x0, 0(x5)            #pk_seed(16)||O(16)
    bn.rshi w0, w0, w31 >> 128
    bn.rshi w0, w31, w0 >> 128
    bn.sid x0, 0(x2)
    li x31, 1
    loopi 93, 4
        bn.lid x0, 0(x5)
        bn.lid x31, 32(x5)
        bn.rshi w0, w1, w0 >> 128
        bn.sid x0, 0(x5++) 

    bn.lid x0, 0(x5)
    bn.rshi w0, w31, w0 >> 128
    bn.sid x0, 0(x5)
    li x31, 0x80000000
    csrrw x0, kmac_cfg, x31
    
ret
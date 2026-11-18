/* expandsk_ret_O_pkseed - SHAKE256(sk_seed) -> pk_seed || O (UOV-Is).
 * Squeezes 97 blocks, then walks back down shifting the 16B pk_seed prefix out
 * so O lands 32B-aligned. The frame is NOT freed: x2 stays at the frame base on
 * return, and the caller reads pk_seed at 0(x2) (low 16B) and raw O at 32(x2)
 * (3,072B, GF16 nibble-packed). pk_seed is stored zero-extended to the full 32B word; the
 * bngfonly sign tier depends on it. KeySchedule_sign reads w17[255:96] for RotWord, so a
 * nonzero upper half corrupts RK1 right off the load, and aes128_sign then XORs all 256 bits
 * of the dual-stored key. bn.aes128.* masks the key to 128 bits and does not care.
 * in:    x11 = sk_seed addr (32B), x2 = 32B-aligned stack, w31 = 0
 * clob:  x2 (-3104), x5, x30, x31; w0, w1; kmac_cfg (left ENABLED - unlike the
 *        Ip twin, this one does not disable KMAC on exit)
 * stack: 3104 B, kept live for the caller
 */
.section .text
.balign 4
.global expandsk_ret_O_pkseed
expandsk_ret_O_pkseed:
    # Assume sk_seed address in x11
    bn.lid x0, 0(x11)
    li x5, 0xA                      # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x0, 0x20
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    bn.wsrw kmac_msg, w0
    # Assume stack is 32 balign
    li x31, 3104
    sub x2, x2, x31
    loopi 97, 27
        bn.wsrr w0, kmac_digest
        bn.sid x0, 0(x2++)
        .rept 25
            NOP
        .endr
    addi x2, x2, -32
    li x30, 1
    loopi 96,5
        bn.lid x0, 0(x2) 
        bn.lid x30, -32(x2)
        bn.rshi w0, w0, w1 >> 128
        bn.sid x0, 0(x2)
        addi x2, x2, -32
    bn.lid x0, 0(x2)
    bn.rshi w0, w0, w31 >> 128
    bn.rshi w0, w31, w0 >> 128
    bn.sid x0, 0(x2)

    
ret
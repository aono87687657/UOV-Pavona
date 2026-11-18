/* expandv (Is sign): vinegar expansion via KMAC/SHAKE256 - msg||salt||csk||ctr.
 * in   : x8 attempt counter, x11 csk ptr, x12 msg ptr, x13 msglen, 16(x3) salt ptr
 * out  : w28/w29 = 64B vinegar (96 nibbles used, 48B; Is needs no third lane)
 * clob : x4, x5, x6, x30, x31; w0-w3 (msg/salt/csk/ctr staging); kmac CSRs
 * stack: allocates a 32B counter slot at x2 and LEAVES IT on return - the caller
 *        reclaims it (vinegar buffer overlaps it, see sign.s "counter slot" note).
 *        Do NOT "fix" the missing dealloc.
 */
.section .text
.balign 4
.global expandv
expandv:

    #Setup KMAC for ExpandV
    li x5, 0xA      # KMAC Config 010(L256)_10(SHAKE256):0xA
    addi x31, x13, 49
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31

    # Load csk into w2
    li x31, 2
    bn.lid x31, 0(x11)

    #load stored salt into w1
    lw x4, 16(x3)
    li x31, 1
    bn.lid x31, 0(x4)

    # Clear stack for passing counter
    li x31, 31
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x8, 0(x2)        #store Counter
    #load counter into w3
    li x31, 3
    bn.lid x31, 0(x2)
    
    beq x0, x13, expandv_msg_len_zero
    srli x5, x13, 5                     # nr. of direct write msg to KMAC MSG reg without append salt
    addi x30, x0, 0x1f
    and x6, x13, x30                    # Additional byte/nr. write to kmac msg reg
    beq x5, x0, expandv_short_msg
    loop x5, 27
        bn.lid x0, 0(x12++)
        bn.wsrw kmac_msg, w0
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    expandv_short_msg:
    beq x6, x0, expandv_msg_len_zero
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x12++)
    bn.wsrw kmac_msg, w0
    expandv_msg_len_zero:
    li x31, 16
    csrrw x0, kmac_partial_write, x31
    bn.wsrw kmac_msg, w1
    NOP
    NOP
    bn.wsrw kmac_msg, w2
    .rept 25
        NOP
    .endr
    li x31, 1
    csrrw x0, kmac_partial_write, x31
    bn.wsrw kmac_msg, w3
    .rept 256
        NOP
    .endr


    bn.wsrr w28, 0xa
    bn.wsrr w29, 0xa

ret

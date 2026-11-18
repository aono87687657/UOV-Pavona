/* expandv (Ip sign): vinegar expansion via KMAC/SHAKE256 - msg||salt||csk||ctr.
 * in   : x8 attempt counter, x11 csk ptr, x12 msg ptr, x13 msglen, 16(x3) salt ptr
 * out  : w28/w29/w30 = 80B vinegar (w30 high lane masked to 16B)
 * clob : x5, x6, x30, x31; w0; kmac CSRs
 * stack: allocates a 32B counter slot at x2 and LEAVES IT on return - the caller
 *        reclaims it (vinegar buffer overlaps it, see sign.s "counter slot" note).
 *        Do NOT "fix" the missing dealloc.
 */
.section .text
.balign 4
.global expandv
expandv:
    #Setup KMAC for ExpandV
    li x5, 0xA      # KMAC Config 010(L256)_01(SHAKE256):0x9
    addi x31, x13, 49
    slli x31, x31, 5
    or x31, x31, x5
    csrrw x0, kmac_cfg, x31
    # Clear stack for passing counter
    li x31, 31
    addi x2, x2, -32
    bn.sid x31, 0(x2)
    sw x8, 0(x2)        #store Counter
    beq x13, x0, expandv_msglen_0
    srli x5, x13, 5                 # nr. of direct write msg to KMAC MSG reg without append salt
    addi x30, x0, 0x1f
    and x6, x13, x30                # Additional byte/nr. write to kmac msg reg
    beq x0, x5, expandv_short_msg
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
    beq x6, x0, expandv_msglen_0
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x12++)
    bn.wsrw kmac_msg, w0
    expandv_msglen_0:
    # load salt into w0
    li x31, 16
    csrrw x0, kmac_partial_write, x31
    lw x31, 16(x3) 
    bn.lid x0, 0(x31)
    bn.wsrw kmac_msg, w0
    NOP
    #load csk into w0
    bn.lid x0, 0(x11)
    bn.wsrw kmac_msg, w0
    .rept 25
        NOP
    .endr
    #load counter into w0
    bn.lid x0, 0(x2)
    li x31, 1
    csrrw x0, kmac_partial_write, x31
    bn.wsrw kmac_msg, w0
    .rept 256
        NOP
    .endr

    bn.wsrr w28, 0xa
    bn.wsrr w29, 0xa
    bn.wsrr w30, 0xa
    bn.rshi w30, w30, w31 >> 32
    bn.rshi w30, w31, w30 >> 224 
ret

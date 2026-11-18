.section .text
.balign 4
.global hash_salted_msg
hash_salted_msg:
   
    beq x13, x0, msg_len_zero
    srli x5, x13, 5                 # nr. of direct write msg to KMAC MSG reg without append salt
    addi x30, x0, 0x1f
    and x6, x13, x30                # Additional byte/nr. write to kmac msg reg
    beq x0, x5, msg_len_short       # check msg_len < 32 
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
    beq x0, x6, msg_len_zero        # check if msg_len % 32 == 0
    # msg_len < 32
    msg_len_short:
    csrrw x0, kmac_partial_write, x6
    bn.lid x0, 0(x12++)
    bn.wsrw kmac_msg, w0
    msg_len_zero:
    li x6, 16
    csrrw x0, kmac_partial_write, x6
    bn.wsrw kmac_msg, w1
    .rept 256
        NOP
    .endr
    bn.wsrr w29, 0xA                #lower 32 bytes
    bn.wsrr w30, 0xa                #lower 12 bytes
    bn.rshi w30, w30, w31 >> 96 
    bn.rshi w30, w31, w30 >> 160    

    li x31, 0x80000000
    csrrw x0, kmac_cfg, x31
ret

.section .text
.balign 4
.global hash_salted_msg
hash_salted_msg:
   
    beq x13, x0, msg_len_zero
    srli x5, x13, 5                 # nr. of direct write msg to KMAC MSG reg without append salt
    addi x30, x0, 0x1f
    and x6, x13, x30                # Additional byte/nr. write to kmac msg reg
    beq x5, x0, msg_len_short       # check if msg_len < 32
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
    beq x6, x0, msg_len_zero        # if msg_len % 32 == 0, skip to salt
    msg_len_short:                  # msg_len < 32
        bn.lid x0, 0(x12++)
        csrrw x0, kmac_partial_write, x6
        bn.wsrw kmac_msg, w0
    msg_len_zero:
    li x31, 16
    csrrw x0, kmac_partial_write, x31
    bn.wsrw kmac_msg, w1
    .rept 256
        NOP
    .endr

    # Target t
    bn.wsrr w30, 0xa

    li x31, 0x80000000
    csrrw x0, kmac_cfg, x31
ret

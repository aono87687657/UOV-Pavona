.section .data
.balign 32
.global mask
mask:
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
    .word 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000
    .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000
.balign 32
csk:
    .zero 32
.balign 4
msg_len:
    .zero 4
.balign 32
msg:
    .zero 1000
#ifdef USE_TESTVEC_SALT
.balign 32
.global salt_input
salt_input:
    .zero 32              #salt_input slot for -DUSE_TESTVEC_SALT
                          #place before sig: at 0x500, sig shift +32 to 0x520 in testvec ELF
                          #0x500-0x51F sit below sig: above stack: floor
                          #bngfaes deepest reach batch_quad -352, no touch 0x500
                          #salt load before sig_loop start
#endif
.balign 32
sig:
    .zero 160
.balign 32
# L-direct exact DMEM stack per tier (peak x2 below stack_end): bngfaes 13824,
# bngfonly 14280, sw 14272 B. Everything from `stack` to stack_end is the
# reservation; the slots below sum to 13024, so the worst tier (bngfonly)
# needs 1256 more, rounded to the 32-byte grid.
stack:
    .zero 1280            # Ip3 stack reserve
.balign 32
Y:
    .zero 64
.balign 32
L:
    .zero 4096
.balign 32
vinegar:
    .zero 96
.balign 32
counter:
    .zero 32
.balign 32
Target:
    .zero 64
.balign 32
Salt:
    .zero 32
.balign 32
S:
    .zero 4256
.balign 32
pk_seed:
    .zero 32
.balign 32
O:
    .zero 4320
.balign 32
argument:
    .zero 32
stack_end:
.section .text.start
.balign 4
.global main
main:
    la x2, stack_end
    la x10, sig
    la x11, csk
    la x12, msg
    la x13, msg_len
    lw x13, 0(x13) 
    jal x1, ov_Ip3_skc_sign

ecall


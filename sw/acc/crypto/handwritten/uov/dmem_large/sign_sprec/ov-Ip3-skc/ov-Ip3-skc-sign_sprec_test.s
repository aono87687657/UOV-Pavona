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
    .zero 32              #salt_input slot for -DUSE_TESTVEC_SALT, read before sig_loop
#endif
.balign 32
sig:
    .zero 160
.balign 32
# S-precompute DMEM: S 213,120 B and the raw P1 cache 177,600 B on the stack, plus
# the per-attempt buffers below. The deepest point is sprec_build_S_74_45, which runs
# below the cache before those buffers exist; measured lowest x2 below Y is 384 B.
stack:
    .zero 8192            # Ip3 sprec stack reserve
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
P1cache:
    .zero 177600
.balign 32
S:
    .zero 213120
.balign 32
pk_seed:
    .zero 32
.balign 32
O:
    .zero 4320
.balign 32
argument:
    .zero 64
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

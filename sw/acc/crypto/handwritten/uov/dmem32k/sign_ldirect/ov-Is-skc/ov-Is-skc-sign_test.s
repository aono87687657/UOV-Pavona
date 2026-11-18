.section .data
.global bswap32_mask
.balign 32
bswap32_mask:
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.word 0x000000ff
.balign 32
.global mask
mask:
    .word 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f
    .word 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f
.balign 32
.global mask_2
mask_2:
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
    .word 0x00ff00ff, 0x00ff00ff, 0x00ff00ff, 0x00ff00ff
.balign 32
.global mask_3
mask_3:
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
    .word 0x0000ffff, 0x0000ffff, 0x0000ffff, 0x0000ffff
.balign 32
.global mask_4
mask_4:
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
    .word 0xffffffff, 0x00000000, 0xffffffff, 0x00000000
.balign 32
.global mask_5
mask_5:
    .word 0xffffffff, 0xffffffff, 0x00000000,  0x00000000
    .word 0xffffffff, 0xffffffff, 0x00000000,  0x00000000
.balign 32
.global mask_6
mask_6:
    .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
    .word 0x00000000, 0x00000000, 0x00000000, 0x00000000
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
                          #Is bngfaes: place before sig: at 0x520, sig shift +32 to 0x540 in testvec ELF
                          #0x520-0x53F below deepest x2 reach
                          #trimat -3136 reach lands in below-S static buf (Salt/Target/.../L/y = 2240B)
                          #residual ~896B fit stack: 1152 with +256 margin
#endif
.balign 32
sig:
    .zero 96
.balign 32
# L-direct exact DMEM stack per tier (peak x2 below stack_end): bngfaes 8512,
# bngfonly 8520, sw 8736 B. Wrapper reserves the worst tier (sw 8736); the
# S slot below holds only that residual (no S buffer in L-direct).
stack:
    .zero 1184
y:
    .zero 32
L:
    .zero 2048
vinegar:
    .zero 64
Counter:
    .zero 32
Target:
    .zero 32
Salt:
    .zero 32
S:
    .zero 2176
pk_seed:
    .zero 32
O:
    .zero 3072
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
    jal x1, ov_Is_skc_sign

ecall


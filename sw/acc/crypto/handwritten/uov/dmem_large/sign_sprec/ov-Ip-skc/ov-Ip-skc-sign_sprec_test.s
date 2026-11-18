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
    .zero 128
.balign 32
# S-precompute exact DMEM stack per tier (peak x2 below stack_end): bngfaes
# 203680, bngfonly 204076 B (incl the 191488 B S buffer). sw tier uses the #else
# (no-cache) branch: un-cached precompute-S, T-table AES.
# -DP1_CACHE (bngfaes): +150144 B P1 cache below S -> peak ~353824 (fits 512 KiB DMEM).
stack:
#ifdef P1_CACHE
    .zero 150912          # 768 base + 150144 P1 cache
#else
    .zero 768             # Ip stack reserve
#endif
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
    .zero 191488 
.balign 32
pk_seed:
    .zero 32
.balign 32
O:
    .zero 3008
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
    jal x1, ov_Ip_skc_sign

ecall


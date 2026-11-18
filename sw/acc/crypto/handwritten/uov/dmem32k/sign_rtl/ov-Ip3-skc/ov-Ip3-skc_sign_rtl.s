# RTL harness for ov_Ip3_skc_sign (Round-3 Ip: 135-B signature in a 160-B slot).
# Tier (bngfaes/bngfonly/bnaesonly/sw) selected via BUILD dep. Data symbols
# (sk_seed, msg_len, msg, sig, salt_input) come from the linked testvector
# library; the host may overwrite them over TL-UL. Output goes to the
# harness-local sign_s_output_addr and is compared against the linked sig:
# x5 = 0 on PASS, -1 on MISMATCH, -2 if the stack guard poison was clobbered.
# DMEM layout below `stack` is the ov-Ip3-skc-sign_test.s wrapper's, so the
# per-tier stack peaks measured there (bngfaes 13824, bngfonly 14280, sw 14272 B
# below stack_end) hold here too.

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
.global sign_s_output_addr
sign_s_output_addr:
    .zero 160

.balign 32
.global stack_guard
stack_guard:                       /* 32 B poison; checked after sign */
    .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
    .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
.balign 32
stack:
    .zero 1280            /* Ip3 stack reserve */
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
    # Sign call: x10=output slot, x11=sk_seed, x12=msg, x13=msg_len (value).
    la x10, sign_s_output_addr
    la x11, sk_seed
    la x12, msg
    la x13, msg_len
    lw x13, 0(x13)
    jal x1, ov_Ip3_skc_sign
    # Publish the produced slot into w0..w4 so an external checker can verify
    # the bytes from the register dump independently of the compare below.
    la x6, sign_s_output_addr
    li x7, 0
    bn.lid x7, 0(x6)
    li x7, 1
    bn.lid x7, 32(x6)
    li x7, 2
    bn.lid x7, 64(x6)
    li x7, 3
    bn.lid x7, 96(x6)
    li x7, 4
    bn.lid x7, 128(x6)
    # Stack guard first: the reserve is exactly the measured peak.
    la x6, stack_guard
    li x9, 8
    li x30, 0xdeadbeef
guard_loop:
    lw x28, 0(x6)
    bne x28, x30, guard_fail
    addi x6, x6, 4
    addi x9, x9, -1
    bne x9, x0, guard_loop
    # Compare 135 B against the linked sig: 33 whole words, then the low 3
    # bytes of word 33 (byte 135 is slot padding on both sides).
    la x6, sign_s_output_addr
    la x7, sig
    li x9, 33
cmp_loop:
    lw x28, 0(x6)
    lw x29, 0(x7)
    bne x28, x29, sign_fail
    addi x6, x6, 4
    addi x7, x7, 4
    addi x9, x9, -1
    bne x9, x0, cmp_loop
    lw x28, 0(x6)
    lw x29, 0(x7)
    li x30, 0x00ffffff
    and x28, x28, x30
    and x29, x29, x30
    bne x28, x29, sign_fail
    li x5, 0
#ifndef ISS_SIM_TEST              /* the ISS stops 4 B past this ecall */
    .global _expected_end_addr   # PASS stop PC = this ecall; sign_fail's is 8 B on
_expected_end_addr:
#endif
    ecall
sign_fail:
    li x5, -1
    ecall
guard_fail:
    li x5, -2                   /* stack overflow: guard poison clobbered */
    ecall

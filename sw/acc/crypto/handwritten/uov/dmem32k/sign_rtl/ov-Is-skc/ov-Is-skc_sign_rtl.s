# RTL msglen harness for ov_Is_skc_sign. Tier (bngfaes/bngfonly/sw) selected via BUILD dep.
# Data symbols (sk_seed, msg_len, msg, sig) come from linked testvector library.
# Output sig is written to harness-local sign_s_output_addr; compared against
# linked sig (expected) at end; x5 = 0 on PASS, -1 on MISMATCH, -2 if the stack
# guard poison was clobbered (overflow).

.section .data
.global bswap32_mask
.balign 32
bswap32_mask:
    .word 0x000000ff, 0x000000ff, 0x000000ff, 0x000000ff
    .word 0x000000ff, 0x000000ff, 0x000000ff, 0x000000ff
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
    .word 0xffffffff, 0xffffffff, 0x00000000, 0x00000000
    .word 0xffffffff, 0xffffffff, 0x00000000, 0x00000000
.balign 32
.global mask_6
mask_6:
    .word 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
    .word 0x00000000, 0x00000000, 0x00000000, 0x00000000

.balign 32
.global salt_input
salt_input:
    .zero 32

.balign 32
.global sign_s_output_addr
sign_s_output_addr:
    .zero 96

.balign 32
# -DP1_CACHE: +148992 B raw-P1 cache below S (sprec-style builds; no in-tree
# target sets it since the msglen grid was removed — reserve overflows without it).
.balign 32
.global stack_guard
stack_guard:                       /* 32 B poison; checked after sign */
    .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
    .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
.balign 32
stack:
#ifdef P1_CACHE
    .zero 150144           # 1152 base + 148992 P1 cache
#else
    .zero 1152             # Is stack reserve
#endif
.balign 32
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
#ifdef P1_CACHE
    .zero 196608          /* sprec materializes the full S */
#else
    .zero 2208            /* L-direct: measured stack residual only */
#endif
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

    # Stage testvec salt: copy 16 B from linked sig+80 into salt_input[0..16].
    la x5, sig
    addi x5, x5, 80
    la x6, salt_input
    lw x7, 0(x5)
    sw x7, 0(x6)
    lw x7, 4(x5)
    sw x7, 4(x6)
    lw x7, 8(x5)
    sw x7, 8(x6)
    lw x7, 12(x5)
    sw x7, 12(x6)

    # Sign call: x10=output buf, x11=sk_seed, x12=msg, x13=msg_len (value).
    la x10, sign_s_output_addr
    la x11, sk_seed
    la x12, msg
    la x13, msg_len
    lw x13, 0(x13)
    jal x1, ov_Is_skc_sign

    # Publish the produced signature into w0.. so an EXTERNAL checker can
    # verify the bytes from the register dump. x5 is computed by the DUT and
    # would report PASS if the compare loop itself were broken; this does not.
    la x6, sign_s_output_addr
    li x7, 0
    bn.lid x7, 0(x6)
    li x7, 1
    bn.lid x7, 32(x6)
    li x7, 2
    bn.lid x7, 64(x6)

    # Stack guard: the reserve is exactly the measured peak, so any deepening
    # of the call graph lands here first. Checked before the sig compare
    # because the kernel rewrites sign_s_output_addr at the end (masking).
    la x6, stack_guard
    li x9, 8
    li x30, 0xdeadbeef
guard_loop:
    lw x28, 0(x6)
    bne x28, x30, guard_fail
    addi x6, x6, 4
    addi x9, x9, -1
    bne x9, x0, guard_loop

    # Compare output (96 B = 24 words) against linked sig.
    la x6, sign_s_output_addr
    la x7, sig
    li x9, 24
cmp_loop:
    lw x28, 0(x6)
    lw x29, 0(x7)
    bne x28, x29, sign_fail
    addi x6, x6, 4
    addi x7, x7, 4
    addi x9, x9, -1
    bne x9, x0, cmp_loop

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

.section .data
.balign 32
result:
    .zero 196608
.balign 32
O:
    .zero 3072
.balign 32
AES_KEY:
    .zero 32
.balign 32
# raw-P1 cache (upper-tri incl diag, 4656*32 B) — bngfaes arm fills it via x13.
P1_cache:
    .zero 148992
.balign 32
P1_P1T:
    .zero 3072
    .zero 32
    .zero 32
stack_end:
.section .text.start
.global main
.balign 4
main:
    bn.xor w31, w31, w31
    la x2, stack_end
    la x10, AES_KEY
    la x11, O
    la x12, result
    la x13, P1_cache                # bngfaes arm needs the raw-P1 cache base
    jal x1, gf16trimat_2trimat_madd_96_48_64_32
    ecall
.section .data
.balign 32
sk_seed:
    .zero 32
pk_seed:
    .zero 32     # pk_seed is 16 bytes
O:
    .zero 3008   # O size is 2992 bytes (not 32balign)
stack_end:
    .zero 32
.section .text.start
.balign 4
.global main
main:
    
    # Initialize stack pointer
    la x2, stack_end
    
    # Load sk_seed address into x11
    la x11, sk_seed
    
    # Call expandsk_ret_O_pkseed
    jal x1, expandsk_ret_O_pkseed

ecall

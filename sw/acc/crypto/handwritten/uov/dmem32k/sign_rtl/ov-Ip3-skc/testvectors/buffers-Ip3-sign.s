/* Sign buffers for cryptotest; the host writes all of them. msg fits pqov's longest message. */

.section .data

.balign 4
.global msg_len
msg_len:
    .word 0

.balign 32
.global msg
msg:
    .zero 3328

.balign 32
.global sk_seed
sk_seed:
    .zero 32

/* Only the harness's compare reads sig; the result is in sign_s_output_addr. */
.balign 32
.global sig
sig:
    .zero 160

.balign 32
.global salt_input
salt_input:
    .zero 32

/* aes_constants_keygen: .data constants for aes128_keygen + KeySchedule_keygen.
 *   byte_swap_mask  0xff at CTR bytes (12, 28) -> byte-swap LE counter slots of the IV
 *   affine_value    0x63..63   AES SubBytes affine constant (after Itoh-Tsujii inverse)
 *   msb_mask        0x80..80   per-byte MSB mask for the affine GF-rotation shifts
 *   shiftrow_mask   0x0000ff00 x8   ShiftRows row-1 base (other rows = shifts of this)
 *   rcon            AES-128 rcon[1..10] stream; KeySchedule_keygen shifts 8 bits/call
 */
.section .data
.balign 32
.global byte_swap_mask
byte_swap_mask:
    /* 0xff at bytes 12 (= word 3 low half) and 28 (= word 7 high half), ZERO elsewhere.
       aes128_keygen byte-swaps ONLY these CTR-field bytes within each 128-bit half.
       (Wider masks byte-swap non-CTR bytes of the IV wrong.) */
    .word 0, 0, 0, 0x000000ff
    .word 0, 0, 0, 0x000000ff
.balign 32
.global affine_value
affine_value:
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
    .word 0x63636363, 0x63636363, 0x63636363, 0x63636363
.balign 32
.global msb_mask
msb_mask:
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
    .word 0x80808080, 0x80808080, 0x80808080, 0x80808080
.balign 32
.global shiftrow_mask
shiftrow_mask:
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
    .word 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00
.balign 32
.global rcon
rcon:
    .word 0x08040201, 0x80402010, 0x361b, 0
    .zero 16

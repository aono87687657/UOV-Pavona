/*
 * aes_constants_sign .data constants shared by aes128_sign + KeySchedule_sign.
 *
 * Values verified against ov-verify_base/ov-Is-pkc_gf/ov-Is-pkc_publicmap_gf_test.s
 * (which is the canonical source for these constants in the verify path).
 *
 *   byte_swap_mask 0xff at CTR bytes 12 and 28 only (ZERO elsewhere). aes128_sign
 *                    shifts it (<<8/<<16/<<24) to byte-swap the LE counter slot
 *                    (bytes 12-15, 28-31) of the IV. See the data note below for why
 *                    a broader "every 4-byte boundary" mask is wrong here.
 *   affine_value   0x63..63 (8x 0x63636363). AES SubBytes affine constant, applied
 *                    after the Itoh-Tsujii inverse.
 *   msb_mask       0x80..80 (8x 0x80808080). Mask for the MSB of each byte; used in
 *                    the GF-rotation shifts that compute the affine.
 *   shiftrow_mask  0x0000ff00 repeated 8x. Used by aes128_sign ShiftRows (row-1 mask;
 *                    other row masks are derived by shifts of this base).
 *   rcon           AES-128 round constants stream. Caller loads into w11 once; each
 *                    KeySchedule_sign call shifts it by 8 bits to consume one rcon byte.
 *                    First 11 bytes: 01, 02, 04, 08, 10, 20, 40, 80, 1B, 36 (the standard
 *                    AES-128 rcon[1..10]). Packed LE: 0x08040201, 0x80402010, 0x361b.
 */
.section .data
.balign 32
.global byte_swap_mask
byte_swap_mask:
    /* 0xff at bytes 12 (= word 3 low half) and 28 (= word 7 high half), ZERO elsewhere.
       aes128_sign byte-swaps ONLY these CTR-field bytes within each 128-bit half.
       (Wider masks like 0xff at every 4-byte boundary cause aes128_sign to byte-swap
       all 4-byte groups of the IV wrong for non-sparse IVs and inconsistent with
       verify_base's inline mask construction.) */
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

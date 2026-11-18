/*gf256_matvec_2816_68_test.s*/

/*
 * Test harness for gf256_matvec_2816_68
 *
 * Matrix dimensions: 2816 rows × 68 columns (GF256, column-major)
 * This matches the S matrix layout for OV-Ip signing:
 *   S has V=68 super-columns, each 44×64 = 2816 bytes
 *   (44 batch entries padded to 64 bytes each)
 */

.section .data
.balign 32
matrixA:
    .zero 191488     /* 2816 × 68 = 191,488 bytes */
.balign 32
accumulator:
    .zero 2816       /* 2816 bytes (88 × 32, already 32-byte aligned) */
.balign 32
vectorB:
    .zero 96         /* 68 bytes needed, padded to 96 for 32-byte alignment */

.section .text.start
.balign 4
.global main
/*
@param[in][out] x10 : accumulator
@param[in]      x11 : matrixA
@param[in]      x12 : vectorB
*/
.global main
main:

    /* x10: accumulator */
    la x10, accumulator

    /* x11: matrixA */
    la x11, matrixA

    /* Load vectorB (68 bytes = 3 WDRs) into w28, w29, w30 */
    la x12, vectorB
    li x31, 28
    bn.lid x31, 0(x12++)
    li x31, 29
    bn.lid x31, 0(x12++)
    li x31, 30
    bn.lid x31, 0(x12)

    jal x1, gf256_matvec_2816_68

    ecall

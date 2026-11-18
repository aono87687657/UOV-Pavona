/* gaussian_elemination_64x64 (Is) - GF(16) row-reduction.
 *
 *   variant     cpp flag            body
 *   sw      (none)              SW gf16_macc_sw per multiply
 *   bngfonly    -DGF_INSTRUCTIONS   HW bn.gfmul.4 (same impl as bngfaes; no AES used)
 *   bngfaes     -DAES_|GF_          HW bn.gfmul.4
 *
 * I/O: x10=matrix (64x32B), x11=solution vec (32B). Returns w24=0 if non-singular,
 *      else all-ones.
 */

.section .text
.balign 4
.global gaussian_elemination_64x64

#if defined(GF_INSTRUCTIONS)

/* =============== bngfaes + bngfonly (HW bn.gfmul.4) =============== */
gaussian_elemination_64x64:

    /* ----------------------------------------------------------------
     * Initialisation
     * ---------------------------------------------------------------- */
    li x31, 0x13
    csrrw x0, mod0, x31             # Set GF(2^4) modulus: x^4 + x + 1

    bn.xor w31, w31, w31            # w31 = 0 (constant zero)
    bn.xor w22, w22, w22            # w22 = 0 (per-row singularity flag)
    bn.not w23, w31                 # w23 = all-ones (used for flag selection)
    bn.xor w24, w24, w24            # w24 = 0 (cumulative singularity flag)
    bn.addi w30, w31, 0xf           # w30 = 0x0F (mask for lowest nibble)

    li x26, 2                       # WDR index: loads into w2
    li x31, 1                       # WDR index: accesses w1 (solution)

    bn.lid x31, 0(x11)              # w1 = solution vector

    addi x2, x2, -32               # Pre-allocate 32 bytes of stack space

    /* ================================================================
     * ROWS 0..62 — unified elimination loop.
     * The lane-indexed bn.gfmul (csrrw mod1, x28) makes pivot lane 0 a
     * valid cursor, so row 0 is just the x28=0 iteration and needs no
     * special case. (The SW path still peels row 0: its scalar-shift
     * loop count would be 0.) Row 63 stays peeled below — it has no
     * rows beneath it to scan/eliminate.
     * ================================================================ */
    sw x10, 4(x2)                 # seed current-row pointer = row 0 (matrix base)
    li x27, 63                    # x27 = rows below current (63 for row 0)
    li x28, 0                     # x28 = current pivot lane (0 for row 0)

    loopi 63, 48                  # Process rows 0 through 62
        /* --- Step 1: Load current row & conditional-add ------------ */
        lw x10, 4(x2)            # x10 = pointer to current row
        bn.lid x0, 0(x10++)      # w0 = current row; advance pointer
        sw x10, 0(x2)            # Save pointer to next row
        bn.rshi w4, w31, w1 >> 4 # Prepare shifted solution for scanning
        bn.and w5, w1, w30       # Extract current solution nibble
        bn.xor w1, w1, w5        # Clear it from solution
        loop x27, 8              # Scan subsequent rows for non-zero pivot
            bn.lid x26, 0(x10++)
            bn.and w29, w0, w30           # Extract pivot nibble
            bn.cmp w29, w31, FG0          # Test if zero
            bn.sel w3, w2, w31, FG0.z     # Conditionally select row
            bn.sel w6, w4, w31, FG0.z     # Conditionally select solution nibble
            bn.xor w0, w0, w3            # XOR row in if pivot was zero
            bn.xor w5, w5, w6            # XOR solution in if pivot was zero
            bn.rshi w4, w31, w4 >> 4     # Advance to next solution nibble
        bn.and w5, w5, w30       # Mask to current nibble position
        bn.or w1, w1, w5         # Merge back into solution
        /* --- Step 2: Singularity check ----------------------------- */
        lw x10, 0(x2)            # Restore pointer
        bn.and w29, w0, w30      # Extract final pivot
        bn.cmp w29, w31, FG0     # Check if still zero
        bn.sel w22, w23, w31, FG0.z
        bn.or w24, w24, w22      # Latch singularity flag
        /* --- Step 3: Compute pivot inverse (a^{-1} = a^14) --------- */
        bn.gfmul.4.vv w28, w29, w29   # a^2
        bn.gfmul.4.vv w27, w28, w28   # a^4
        bn.gfmul.4.vv w26, w27, w27   # a^8
        bn.gfmul.4.vv w29, w28, w27   # a^6
        bn.gfmul.4.vv w29, w26, w29   # a^14 = a^{-1}
        /* Set mod1 = x28 so gfmul reads nibble at pivot position directly */
        csrrw x0, mod1, x28
        /* --- Step 4: Scale row and solution by pivot inverse ------- */
        bn.gfmul.4 w0, w0, w29       # Row *= w29[mod1=x28] = pivot^{-1}
        bn.sid x0, -32(x10)          # Store scaled row back in-place
        bn.and  w3, w1, w30          # Extract current solution nibble
        bn.xor  w1, w1, w3           # Clear from solution
        bn.gfmul.4 w3, w3, w29      # Scale by pivot^{-1}
        bn.or w1, w1, w3             # Merge back
        bn.rshi w3, w3, w31 >> 252   # Prepare for elimination (shift for multiplying subsequent solution nibbles)
        /* --- Step 5: Eliminate pivot column from remaining rows ----- */
        sw x10, 4(x2)               # Save pointer to next row
        loop x27, 8                  # For each remaining row j:
            bn.lid x26, 0(x10)      #   w2 = row j
            bn.and w4, w2, w30      #   w4 = column-k nibble of row j (at nibble x28)
            bn.gfmul.4 w5, w0, w4   #   w5 = scaled_row_k * w4[mod1=x28]
            bn.gfmul.4 w6, w3, w4   #   w6 = solution contribution
            bn.xor w2, w2, w5       #   row_j ^= elimination term
            bn.sid x26, 0(x10++)    #   Store modified row j in-place
            bn.xor w1, w1, w6       #   solution ^= solution contribution
            bn.rshi w3, w3, w31 >> 252  # Advance scaled solution nibble
        /* --- Advance counters and pivot mask ----------------------- */
        bn.rshi w30, w30, w31 >> 252  # w30 >>= 4 (next nibble position)
        addi x28, x28, 1             # x28++ (current row index)
        addi x27, x27, -1            # x27-- (remaining rows)

    /* ================================================================
     * LAST ROW (row 63) — only needs scaling, no elimination
     * ================================================================ */
    lw x10, 4(x2)                # Load pointer to last row
    bn.lid x0, 0(x10)            # w0 = last row
    bn.addi w30, w31, 0xf        # Reset mask to 0x0F (row 63's pivot is at
                                  #   bit position 252..255, but we use full
                                  #   nibble comparison here)
    /* --- Singularity check for last row ----------------------------- */
    bn.cmp w0, w31, FG0          # If entire row is zero → singular
    bn.sel w22, w23, w31, FG0.z
    bn.or w24, w24, w22          # Latch flag
    /* --- Compute pivot inverse -------------------------------------- */
    bn.gfmul.4.vv w28, w0, w0    # a^2
    bn.gfmul.4.vv w27, w28, w28  # a^4
    bn.gfmul.4.vv w26, w27, w27  # a^8
    bn.gfmul.4.vv w29, w28, w27  # a^6
    bn.gfmul.4.vv w29, w26, w29  # a^14 = a^{-1}
    /* --- Scale solution nibble for last row ------------------------- */
    bn.gfmul.4.vv w2, w1, w29    # Multiply full solution by inverse (only top nibble matters)
    bn.rshi w1, w1, w31 >> 252   # Clear the top nibble of solution
    bn.rshi w1, w31, w1 >> 4     # Shift back to restore lower nibbles
    bn.or w1, w1, w2             # Merge scaled top nibble back

    /* --- Scale last row -------------------------------------------- */
    csrrw x0, mod1, x28          # mod1 = 63 (x28 after main loop); read inverse at nibble 63
    bn.gfmul.4 w0, w0, w29      # Last row *= w29[63] = pivot^{-1}

    /* --- Store results in-place ------------------------------------ */
    bn.sid x0, 0(x10)            # Store last row
    bn.sid x31, 0(x11)           # Store final solution vector

    addi x2, x2, 32              # Deallocate stack space

    csrrw x0, mod1, x0           # reset mod1 = 0 so downstream bn.gfmul.4 callers see clean state
ret


#else

/* =============== sw (SW gf16 multiply) =============== */
gaussian_elemination_64x64:
    bn.xor w31, w31, w31

    /* Build msb_mask in w16. */
    bn.addi w16, w31, 0x88
    bn.rshi w17, w16, w31 >> 248
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 240
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 224
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 192
    bn.or   w16, w16, w17
    bn.rshi w17, w16, w31 >> 128
    bn.or   w16, w16, w17

    bn.xor w22, w22, w22
    bn.not w23, w31
    bn.xor w24, w24, w24
    bn.addi w30, w31, 0xf

    li x26, 2
    li x31, 1
    li x25, 1

    bn.lid x31, 0(x11)
    addi x2, x2, -32

    /* ================================================================
     * PHASE A: ROW 0
     * ================================================================ */
    bn.lid x0, 0(x10++)
    sw x10, 0(x2)
    bn.rshi w4, w31, w1 >> 4
    bn.and w5, w1, w30
    bn.xor w1, w1, w5

    loopi 63, 7
        bn.lid x26, 0(x10++)
        bn.and w29, w0, w30, FG0
        bn.sel w3, w2, w31, FG0.z
        bn.sel w6, w4, w31, FG0.z
        bn.xor w0, w0, w3
        bn.xor w5, w5, w6
        bn.rshi w4, w31, w4 >> 4

    bn.and w5, w5, w30
    bn.or w1, w1, w5

    lw x10, 0(x2)
    bn.and w29, w0, w30
    bn.cmp w29, w31, FG0
    bn.sel w22, w23, w31, FG0.z
    bn.or w24, w24, w22

    /* Inverse via scalar_inv (input/output: w29 nibble 0). */
    bn.mov w13, w0    # save w0; scalar_inv clobber w22..w28
    jal x1, gf16_scalar_inv_sw
    bn.mov w0, w13    # restore w0 = row 0

    /* Scale row 0: w12 = w0 * inv. */
    bn.mov w0, w0
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w12, w20
    bn.mov w0, w12

    /* Scale sol nibble for row 0. */
    bn.and w2, w1, w30
    bn.xor w1, w1, w2
    bn.mov w0, w2
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w2, w20
    bn.or w1, w1, w2

    /* Restore w0 = scaled row 0 (helper trashed w0 during sol scale). */
    bn.mov w0, w12

    /* Write row 0 + sol back. */
    bn.sid x0, -32(x10)
    sw x10, 4(x2)
    bn.sid x31, 0(x11)

    bn.and w4, w1, w30              /* w4 = scaled sol[0] */

    loopi 63, 18
        bn.lid x26, 0(x10++)
        bn.and w3, w2, w30
        bn.mov w0, w12
        bn.mov w19, w3
        bn.mov w20, w31
        jal x1, gf16_macc_sw
        bn.mov w5, w20
        bn.mov w0, w4
        bn.mov w19, w3
        bn.mov w20, w31
        jal x1, gf16_macc_sw
        bn.mov w6, w20
        loop x25, 1
            bn.rshi w6, w6, w31 >> 252
        bn.xor w1, w1, w6
        bn.xor w2, w2, w5
        bn.sid x26, -32(x10)
        addi x25, x25, 1

    bn.rshi w30, w30, w31 >> 252

    /* ================================================================
     * PHASE B: ROWS 1..62
     * ================================================================ */
    li x27, 62
    li x28, 1

    loopi 62, 67
        /* Step 1: Load + cond-add scan */
        lw x10, 4(x2)
        bn.lid x0, 0(x10++)
        sw x10, 0(x2)
        bn.rshi w4, w31, w1 >> 4
        bn.and w5, w1, w30
        bn.xor w1, w1, w5
        loop x27, 7
            bn.lid x26, 0(x10++)
            bn.and w29, w0, w30, FG0
            bn.sel w3, w2, w31, FG0.z
            bn.sel w6, w4, w31, FG0.z
            bn.xor w0, w0, w3
            bn.xor w5, w5, w6
            bn.rshi w4, w31, w4 >> 4
        bn.and w5, w5, w30
        bn.or w1, w1, w5
        /* Step 2: Sing check */
        lw x10, 0(x2)
        bn.and w29, w0, w30
        bn.cmp w29, w31, FG0
        bn.sel w22, w23, w31, FG0.z
        bn.or w24, w24, w22
        /* Step 3: Extract pivot nib (w29 has pivot at nib x28; shift down) */
        bn.mov w13, w0    /* w13 preserved by scalar_inv (clobbers w22..w28) */
        loop x28, 1
            bn.rshi w29, w31, w29 >> 4
        jal x1, gf16_scalar_inv_sw
        nop
        bn.mov w0, w13    /* w13 preserved across scalar_inv */
        /* Step 4: Scale row (w20 = w0 * inv-at-nib0). */
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf16_macc_sw
        bn.mov w0, w20
        bn.sid x0, -32(x10)
        bn.mov w12, w0
        /* Step 5: Scale sol nibble (mask at nib K, sg, merge). */
        bn.and w3, w1, w30
        bn.xor w1, w1, w3
        bn.mov w0, w3
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf16_macc_sw
        bn.mov w3, w20
        bn.or w1, w1, w3
        bn.rshi w3, w3, w31 >> 252
        /* Step 6: Elim inner loop */
        sw x10, 4(x2)
        loop x27, 20
            bn.lid x26, 0(x10)
            bn.and w4, w2, w30
            bn.mov w19, w4
            loop x28, 1
                bn.rshi w19, w31, w19 >> 4
            bn.mov w0, w12
            bn.mov w20, w31
            jal x1, gf16_macc_sw
            bn.mov w5, w20
            bn.mov w19, w4
            loop x28, 1
                bn.rshi w19, w31, w19 >> 4
            bn.mov w0, w3
            bn.mov w20, w31
            jal x1, gf16_macc_sw
            bn.mov w6, w20
            bn.xor w2, w2, w5
            bn.sid x26, 0(x10++)
            bn.xor w1, w1, w6
            bn.rshi w3, w3, w31 >> 252
        /* Step 7: advance counters */
        bn.rshi w30, w30, w31 >> 252
        addi x28, x28, 1
        addi x27, x27, -1

    /* ================================================================
     * PHASE C: ROW 63
     * ================================================================ */
    lw x10, 4(x2)
    bn.lid x0, 0(x10)
    bn.addi w30, w31, 0xf
    bn.cmp w0, w31, FG0
    bn.sel w22, w23, w31, FG0.z
    bn.or w24, w24, w22

    /* Pivot inv: shift row 63's nib63 to nib0. */
    bn.mov w13, w0    /* w13 preserved by scalar_inv (clobbers w22..w28) */
    bn.mov w29, w0
    li x4, 63
    loop x4, 1
        bn.rshi w29, w31, w29 >> 4
    jal x1, gf16_scalar_inv_sw
    nop
    bn.mov w0, w13    /* w13 preserved across scalar_inv */

    /* Scale sol top nibble. */
    bn.mov w19, w29
    bn.mov w0, w1
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w2, w20
    /* Build mask at nibble 63 to keep only top nibble of w2. */
    bn.addi w3, w31, 0xf
    li x4, 63
    loop x4, 1
        bn.rshi w3, w3, w31 >> 252
    bn.and w2, w2, w3
    /* Clear w1 top nibble. */
    bn.rshi w1, w1, w31 >> 252
    bn.rshi w1, w31, w1 >> 4
    bn.or w1, w1, w2

    /* Scale row 63: w0 *= inv. */
    bn.mov w19, w29
    bn.mov w0, w13    /* w13 preserved across scalar_inv */
    bn.mov w20, w31
    jal x1, gf16_macc_sw
    bn.mov w0, w20

    bn.sid x0, 0(x10)
    bn.sid x31, 0(x11)

    bn.mov w20, w24

    addi x2, x2, 32
    ret



#endif

/* gaussian_elimination_45x45 (Ip3 45x45 GF(256) forward elimination).
 *
 *   variant     cpp flag             body
 *   sw      (none)               SW gf256 multiply, unrolled
 *   bngfonly    -DGF_INSTRUCTIONS    HW bn.gfmul.8 (same impl as bngfaes; no AES used)
 *   bngfaes     -DAES_|GF_           HW bn.gfmul.8
 *
 * Phases by pivot row: A 0, B 1..30, C 31, D 32, E 33..43, F 44. Every pivot k searches rows k+1..44
 * for a non-zero entry. No loop count depends on the data.
 *
 * in:    x10 = matrix, 45 rows of 64 B (bytes 0..31 low WDR, 32..44 high WDR, 45..63 zero), 32 B aligned;
 *        x11 = right-hand side, 64 B, 32 B aligned; mod1 = 0 (bn.gfmul arms)
 * out:   w20 = 0 (nonsingular) or all ones (singular); if 0, unit pivots and x11 reduced in place
 * clob:  x10, x12, x23..x25, x27..x31; sw arm also x4..x6
 * wdr:   bn.gfmul arms w0..w11, w19..w31; sw arm w0..w21, w23..w25, w29..w31; FG0, sw arm also FG1;
 *        mod0 = 0x11b, mod1 = 0
 * stack: 8 B (bn.gfmul arms); 128 B + 160 B in gf256_scalar_inv_sw (sw arm); x2 32 B aligned
 */

.section .text
.balign 4
.global gaussian_elimination_45x45

#if defined(GF_INSTRUCTIONS)

/* =============== bngfaes + bngfonly (HW bn.gfmul.8) =============== */
gaussian_elimination_45x45:

    /* ----------------------------------------------------------------
     * Initialisation
     * ---------------------------------------------------------------- */
    bn.xor w19, w19, w19            # w19 = 0 (per-row singularity flag)
    bn.xor w20, w20, w20            # w20 = 0 (cumulative singularity flag)
    bn.xor w21, w21, w21
    bn.not w21, w21                 # w21 = all-ones (for flag selection)
    bn.xor w31, w31, w31            # w31 = 0 (constant zero)
    li x31, 0x11b
    csrrw x0, mod0, x31             # Set GF(2^8) modulus: x^8+x^4+x^3+x+1

    bn.addi w30, w31, 0xff          # w30 = 0xFF (mask for lowest byte)

    li x29, 1                       # WDR index → w1
    li x30, 2                       # WDR index → w2
    li x31, 3                       # WDR index → w3
    li x27, 4                       # WDR index → w4
    li x28, 5                       # WDR index → w5

    bn.lid x30, 0(x11)             # w2 = solution vector low  (bytes 0-31)
    bn.lid x31, 32(x11)            # w3 = solution vector high (bytes 32-44)

    addi x2, x2, -8                # Pre-allocate 8 bytes of stack

    /* ================================================================
     * PHASE A: ROW 0 — separated because loop-count=0 is invalid
     * ================================================================ */

    /* --- Step 1: Conditional-add to find a non-zero pivot ----------- */
    sw x10, 0(x2)                  # Save matrix base pointer
    bn.lid x0, 0(x10++)            # w0 = row 0, low 32 bytes
    bn.lid x29, 0(x10++)           # w1 = row 0, high 32 bytes
    sw x10, 4(x2)                  # Save pointer to row 1 (read cursor)

    bn.rshi w6, w3, w2 >> 8        # w6 = solution shifted right 1 byte
                                    #       (bytes 1..32 of solution)
    bn.rshi w7, w31, w3 >> 8       # w7 = solution high shifted right 1 byte
                                    #       (bytes 33..44, rest zero)
    bn.and w10, w2, w30            # w10 = solution byte for row 0
    bn.xor w2, w10, w2             # Clear row-0 byte from solution

    loopi 44, 11                   # Search rows 1..44 for a non-zero pivot
        bn.lid x27, 0(x10++)      #   w4 = next row low
        bn.lid x28, 0(x10++)      #   w5 = next row high
        bn.and w29, w0, w30, FG0  #   w29 = pivot byte; FG0.z if zero
        bn.sel w4, w4, w31, FG0.z #   w4 = row if pivot==0, else 0
        bn.sel w5, w5, w31, FG0.z #   w5 = row high if pivot==0, else 0
        bn.sel w8, w6, w31, FG0.z #   w8 = solution byte if pivot==0
        bn.xor w0, w0, w4         #   Conditionally XOR low row
        bn.xor w1, w1, w5         #   Conditionally XOR high row
        bn.xor w10, w10, w8       #   Conditionally XOR solution byte
        bn.rshi w6, w7, w6 >> 8   #   Advance to next solution byte (low)
        bn.rshi w7, w31, w7 >> 8  #   Advance to next solution byte (high)

    bn.and w10, w10, w30           # Mask to single byte
    bn.or w2, w2, w10              # Merge selected solution byte back

    /* --- Step 2: Singularity check --------------------------------- */
    bn.and w29, w0, w30            # Extract final pivot byte
    bn.cmp w29, w31, FG0           # Check if pivot is still zero
    bn.sel w19, w21, w31, FG0.z    # w19 = all-ones if zero (singular)
    bn.or w20, w20, w19            # Latch into cumulative flag

    /* --- Step 3: Compute pivot inverse via Fermat (a^254) ---------- */
    bn.gfmul.8.vv w28, w29, w29   # w28 = a^2
    bn.gfmul.8.vv w27, w28, w28   # w27 = a^4
    bn.gfmul.8.vv w26, w27, w27   # w26 = a^8
    bn.gfmul.8.vv w25, w26, w26   # w25 = a^16
    bn.gfmul.8.vv w24, w25, w25   # w24 = a^32
    bn.gfmul.8.vv w23, w24, w24   # w23 = a^64
    bn.gfmul.8.vv w22, w23, w23   # w22 = a^128
    bn.gfmul.8.vv w29, w27, w28   # a^4 · a^2 = a^6
    bn.gfmul.8.vv w29, w26, w29   # a^8 · a^6 = a^14
    bn.gfmul.8.vv w29, w25, w29   # a^16 · a^14 = a^30
    bn.gfmul.8.vv w29, w24, w29   # a^32 · a^30 = a^62
    bn.gfmul.8.vv w29, w23, w29   # a^64 · a^62 = a^126
    bn.gfmul.8.vv w29, w22, w29   # a^128 · a^126 = a^254 = a^{-1}

    /* --- Step 4: Scale row 0 and solution byte by pivot inverse ---- */
    bn.gfmul.8 w0, w0, w29        # Row 0 low *= pivot^{-1}
    bn.gfmul.8 w1, w1, w29        # Row 0 high *= pivot^{-1}

    bn.and w4, w2, w30             # w4 = current solution byte
    bn.xor w2, w2, w4              # Clear it from solution
    bn.gfmul.8 w4, w4, w29        # Scale solution byte by pivot^{-1}
    bn.or w2, w2, w4               # Merge back

    /* --- Write back scaled row 0 in-place -------------------------- */
    lw x12, 0(x2)                  # Load matrix base
    bn.sid x0, 0(x12++)            # Store row 0 low
    bn.sid x29, 0(x12++)           # Store row 0 high (w29 still has inverse,
                                    #   but x29=1 → stores w1)
    sw x12, 0(x2)                  # Save pointer to row 1 (write cursor)

    /* --- Step 5: Eliminate column 0 from rows 1..44 ---------------- *
     * The 44 remaining rows are split into two sub-loops because the
     * solution update targets w2 for rows 1..31 and w3 for rows 32..44.
     *
     * w10 carries the "shifted solution contribution": after scaling
     * the current solution byte, it is shifted right 8 bits each
     * iteration to align with the next row's byte position.
     */
    bn.and w10, w2, w30            # w10 = scaled solution byte (byte 0)
    bn.rshi w10, w10, w31 >> 248   # Shift to prepare for byte 1 position

    lw x10, 4(x2)                 # Reload read cursor (row 1)

    /* Sub-loop A: eliminate into rows 1..31 (solution updates go to w2) */
    loopi 31, 12
        bn.lid x27, 0(x10++)      #   w4 = row j low
        bn.lid x28, 0(x10++)      #   w5 = row j high
        bn.and w29, w4, w30       #   w29 = column-0 byte of row j
        bn.gfmul.8 w8, w0, w29    #   w8 = row_0_low * byte_j
        bn.gfmul.8 w9, w1, w29    #   w9 = row_0_high * byte_j
        bn.gfmul.8 w11, w10, w29  #   w11 = sol_contribution * byte_j
        bn.xor w4, w4, w8         #   row_j_low ^= elimination term
        bn.xor w5, w5, w9         #   row_j_high ^= elimination term
        bn.sid x27, -64(x10)      #   Store row j low in-place
        bn.sid x28, -32(x10)      #   Store row j high in-place
        bn.xor w2, w2, w11        #   solution_low ^= contribution
        bn.rshi w10, w10, w31 >> 248  # Advance solution contribution

    /* Sub-loop B: eliminate into rows 32..44 (solution updates go to w3) */
    bn.and w10, w2, w30           # Reload solution contribution from w2
    loopi 13, 12
        bn.lid x27, 0(x10++)
        bn.lid x28, 0(x10++)
        bn.and w29, w4, w30
        bn.gfmul.8 w8, w0, w29
        bn.gfmul.8 w9, w1, w29
        bn.gfmul.8 w11, w10, w29
        bn.xor w4, w4, w8
        bn.xor w5, w5, w9
        bn.sid x27, -64(x10)
        bn.sid x28, -32(x10)
        bn.xor w3, w3, w11        #   solution_high ^= contribution
        bn.rshi w10, w10, w31 >> 248

    /* Advance pivot mask for next row */
    bn.rshi w30, w30, w31 >> 248   # w30 >>= 8 (mask moves one byte right)

    /* ================================================================
     * PHASE B: ROWS 1..30 — main loop for lower-half pivots
     * ================================================================ */
    li x23, 1                      # x23 = current row index
    li x24, 30                     # x24 = 31-k: rows k+1..31

    loopi 30, 83                   # Pivots k = 1..30

        /* --- Step 1: Extract solution byte & conditional-add ------- */
        bn.and w10, w2, w30       #   w10 = solution byte for current row
        bn.xor w2, w10, w2        #   Clear it from solution low
        bn.rshi w6, w3, w2 >> 8   #   Shifted solution (low) for scanning
        bn.rshi w7, w31, w3 >> 8  #   Shifted solution (high) for scanning

        lw x12, 0(x2)             #   Load write cursor (current row)
        bn.lid x0, 0(x12++)       #   w0 = current row low
        bn.lid x29, 0(x12++)      #   w1 = current row high

        addi x25, x24, 13         #   x25 = 44-k
        loop x25, 11              #   Search rows k+1..44 for a non-zero pivot
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.and w29, w0, w30, FG0  # Check pivot byte
            bn.sel w4, w4, w31, FG0.z
            bn.sel w5, w5, w31, FG0.z
            bn.sel w8, w6, w31, FG0.z
            bn.xor w0, w0, w4
            bn.xor w1, w1, w5
            bn.xor w10, w10, w8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8

        bn.and w10, w10, w30       #   Mask to single byte
        bn.or w2, w2, w10          #   Merge back

        /* --- Step 2: Singularity check ----------------------------- */
        bn.and w29, w0, w30
        bn.cmp w29, w31, FG0
        bn.sel w19, w21, w31, FG0.z
        bn.or w20, w20, w19

        /* --- Step 3: Compute pivot inverse (a^254) ----------------- */
        bn.gfmul.8.vv w28, w29, w29   # a^2
        bn.gfmul.8.vv w27, w28, w28   # a^4
        bn.gfmul.8.vv w26, w27, w27   # a^8
        bn.gfmul.8.vv w25, w26, w26   # a^16
        bn.gfmul.8.vv w24, w25, w25   # a^32
        bn.gfmul.8.vv w23, w24, w24   # a^64
        bn.gfmul.8.vv w22, w23, w23   # a^128
        bn.gfmul.8.vv w29, w27, w28   # a^6
        bn.gfmul.8.vv w29, w26, w29   # a^14
        bn.gfmul.8.vv w29, w25, w29   # a^30
        bn.gfmul.8.vv w29, w24, w29   # a^62
        bn.gfmul.8.vv w29, w23, w29   # a^126
        bn.gfmul.8.vv w29, w22, w29   # a^254 = a^{-1}

        /* Set mod1 = x23 so subsequent gfmul.8 vxs reads inverse at byte x23 */
        csrrw x0, mod1, x23

        /* --- Step 4: Scale row and solution by pivot inverse ------- */
        bn.gfmul.8 w0, w0, w29        # Row low *= w29[mod1=x23] = pivot^{-1}
        bn.gfmul.8 w1, w1, w29        # Row high *= w29[mod1=x23] = pivot^{-1}

        lw x12, 0(x2)                 # Load write cursor
        bn.sid x0, 0(x12++)           # Store scaled row low
        bn.sid x29, 0(x12++)          # Store scaled row high (x29=1 → w1)

        bn.and w10, w2, w30           # Extract solution byte
        bn.xor w2, w2, w10            # Clear from solution
        bn.gfmul.8 w10, w10, w29      # Scale by pivot^{-1}
        bn.or w2, w2, w10             # Merge back
        sw x12, 0(x2)                 # Save write cursor

        /* --- Step 5: Eliminate pivot column from remaining rows ----- *
         * Split into two sub-loops:
         *   loop x24: rows k+1..31 (solution byte in w2)
         *   loopi 13: rows 32..44 (solution byte in w3) */
        bn.rshi w10, w10, w31 >> 248  # Shift solution for next byte

        loop x24, 12                  # Eliminate from rows k+1..31
            bn.lid x27, 0(x12++)      #   w4 = row j low
            bn.lid x28, 0(x12++)      #   w5 = row j high
            bn.and w29, w4, w30       #   Column-k byte of row j (at byte x23)
            bn.gfmul.8 w8, w0, w29    #   w8 = w0 * w29[mod1=x23] = row contribution
            bn.gfmul.8 w9, w1, w29    #   Row high contribution
            bn.gfmul.8 w11, w10, w29  #   Solution contribution
            bn.xor w4, w4, w8
            bn.xor w5, w5, w9
            bn.xor w2, w2, w11        #   Update solution low
            bn.sid x27, -64(x12)
            bn.sid x28, -32(x12)
            bn.rshi w10, w10, w31 >> 248

        /* Prepare solution contribution for w3-region rows */
        bn.and w10, w2, w30
        loop x23, 1
            bn.rshi w10, w31, w10 >> 8

        loopi 13, 12                   # Eliminate from rows 32..44 (sol → w3)
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.and w29, w4, w30       #   Column-k byte of row j (at byte x23)
            bn.gfmul.8 w8, w0, w29    #   w8 = w0 * w29[mod1=x23]
            bn.gfmul.8 w9, w1, w29
            bn.gfmul.8 w11, w10, w29
            bn.xor w4, w4, w8
            bn.xor w5, w5, w9
            bn.xor w3, w3, w11        #   Update solution high
            bn.sid x27, -64(x12)
            bn.sid x28, -32(x12)
            bn.rshi w10, w10, w31 >> 248

        /* --- Advance counters and pivot mask ----------------------- */
        bn.rshi w30, w30, w31 >> 248   # w30 >>= 8
        addi x23, x23, 1              # x23++ (current row)
        addi x24, x24, -1             # x24-- (remaining rows)

    /* ================================================================
     * PHASE C: ROW 31 — separated because it's the last row whose
     * pivot lives in the lower WDR (w0), and the boundary between
     * elimination sub-loops changes (all remaining rows → w3).
     * ================================================================ */
    li x23, 31                     # Current row index
    li x24, 13                     # Remaining rows (32..44)

    /* --- Conditional-add ------------------------------------------- */
    bn.and w10, w2, w30
    bn.xor w2, w10, w2
    bn.rshi w6, w3, w2 >> 8
    bn.rshi w7, w31, w3 >> 8

    lw x12, 0(x2)
    bn.lid x0, 0(x12++)
    bn.lid x29, 0(x12++)

    loop x24, 11                   # Search rows 32..44
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.and w29, w0, w30, FG0
        bn.sel w4, w4, w31, FG0.z
        bn.sel w5, w5, w31, FG0.z
        bn.sel w8, w6, w31, FG0.z
        bn.xor w0, w0, w4
        bn.xor w1, w1, w5
        bn.xor w10, w10, w8
        bn.rshi w6, w7, w6 >> 8
        bn.rshi w7, w31, w7 >> 8

    bn.and w10, w10, w30
    bn.or w2, w2, w10

    /* --- Singularity check ----------------------------------------- */
    bn.and w29, w0, w30
    bn.cmp w29, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w20, w20, w19

    /* --- Pivot inverse (a^254) ------------------------------------- */
    bn.gfmul.8.vv w28, w29, w29
    bn.gfmul.8.vv w27, w28, w28
    bn.gfmul.8.vv w26, w27, w27
    bn.gfmul.8.vv w25, w26, w26
    bn.gfmul.8.vv w24, w25, w25
    bn.gfmul.8.vv w23, w24, w24
    bn.gfmul.8.vv w22, w23, w23
    bn.gfmul.8.vv w29, w27, w28
    bn.gfmul.8.vv w29, w26, w29
    bn.gfmul.8.vv w29, w25, w29
    bn.gfmul.8.vv w29, w24, w29
    bn.gfmul.8.vv w29, w23, w29
    bn.gfmul.8.vv w29, w22, w29

    /* Set mod1 = x23 (=31) so gfmul.8 vxs reads inverse at byte 31 */
    csrrw x0, mod1, x23

    /* --- Scale row 31 and solution --------------------------------- */
    bn.gfmul.8 w0, w0, w29        # Row low *= w29[mod1=31] = pivot^{-1}
    bn.gfmul.8 w1, w1, w29

    lw x12, 0(x2)
    bn.sid x0, 0(x12++)
    bn.sid x29, 0(x12++)

    bn.and w10, w2, w30
    bn.xor w2, w2, w10
    bn.gfmul.8 w10, w10, w29
    bn.or w2, w2, w10
    sw x12, 0(x2)

    /* --- Eliminate column 31 from rows 32..44 (all go to w3) ------- */
    bn.rshi w10, w31, w10 >> 248

    loop x24, 12
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.and w29, w4, w30           #   Column-31 byte of row j (at byte 31)
        bn.gfmul.8 w8, w0, w29        #   w8 = w0 * w29[mod1=31]
        bn.gfmul.8 w9, w1, w29
        bn.gfmul.8 w11, w10, w29
        bn.xor w4, w4, w8
        bn.xor w5, w5, w9
        bn.xor w3, w3, w11
        bn.sid x27, -64(x12)
        bn.sid x28, -32(x12)
        bn.rshi w10, w10, w31 >> 248

    /* Store solution low (w2) back to memory — done with w2 updates */
    bn.sid x30, 0(x11)             # x30=2 → stores w2

    bn.rshi w30, w31, w30 >> 248   # Advance mask into upper byte region

    /* ================================================================
     * PHASE D: ROW 32 — first row in the upper WDR half.
     * Separated because loop x23 with x23=0 would be invalid.
     * From here on, only the high WDR (w1, at offset +32) is needed
     * per row, and the "row" fits in a single WDR.
     * ================================================================ */
    li x24, 12                     # Remaining rows (33..44)
    li x28, 31                     # WDR index for storing → w31 placeholder
                                    #   (actually used as a WDR index value)

    /* --- Conditional-add ------------------------------------------- */
    lw x12, 0(x2)
    bn.lid x0, 32(x12)            # w0 = row 32 high WDR
    addi x12, x12, 64

    bn.and w10, w3, w30            # Extract solution byte for row 32
    bn.xor w3, w3, w10             # Clear from solution high
    bn.rshi w6, w31, w3 >> 8       # Shifted solution for scanning

    loop x24, 8                    # Search rows 33..44
        bn.lid x29, 32(x12)       #   w1 = next row high WDR
        addi x12, x12, 64
        bn.and w29, w0, w30, FG0   #   Check pivot byte
        bn.sel w1, w1, w31, FG0.z  #   Conditionally select row
        bn.sel w8, w6, w31, FG0.z  #   Conditionally select solution
        bn.xor w0, w0, w1
        bn.xor w10, w10, w8
        bn.rshi w6, w31, w6 >> 8

    bn.and w10, w10, w30           # Mask to single byte
    bn.or w2, w2, w10              # Park in w2 (scratch; w2 was already
                                    #   stored to memory at end of Phase C)

    /* --- Singularity check ----------------------------------------- */
    bn.and w29, w0, w30
    bn.cmp w29, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w20, w20, w19

    /* --- Pivot inverse --------------------------------------------- */
    bn.gfmul.8.vv w28, w29, w29
    bn.gfmul.8.vv w27, w28, w28
    bn.gfmul.8.vv w26, w27, w27
    bn.gfmul.8.vv w25, w26, w26
    bn.gfmul.8.vv w24, w25, w25
    bn.gfmul.8.vv w23, w24, w24
    bn.gfmul.8.vv w22, w23, w23
    bn.gfmul.8.vv w29, w27, w28
    bn.gfmul.8.vv w29, w26, w29
    bn.gfmul.8.vv w29, w25, w29
    bn.gfmul.8.vv w29, w24, w29
    bn.gfmul.8.vv w29, w23, w29
    bn.gfmul.8.vv w29, w22, w29

    /* Row 32's pivot is at byte 0 of the upper WDR — reset mod1 = 0
     * (it was set to 31 in Phase C and carries over). */
    csrrw x0, mod1, x0

    /* --- Scale row 32 and solution --------------------------------- */
    bn.gfmul.8 w0, w0, w29        # Row 32 *= w29[mod1=0] = pivot^{-1}

    lw x12, 0(x2)
    bn.sid x28, 0(x12++)          # Store low WDR (x28=31 → w31 = zeroes;
                                   #   row 32's low half is empty after transpose)
    bn.sid x0, 0(x12++)           # Store row 32 high (scaled)

    bn.gfmul.8 w10, w10, w29      # Scale solution byte
    bn.or w3, w3, w10              # Merge back into solution high
    bn.rshi w10, w10, w31 >> 248   # Prepare for next byte
    sw x12, 0(x2)

    /* --- Eliminate column 32 from rows 33..44 ---------------------- */
    loop x24, 9
        bn.lid x29, 32(x12)       #   w1 = row j high WDR
        bn.and w29, w1, w30       #   Column-32 byte of row j
        bn.gfmul.8 w8, w0, w29    #   Row contribution (single WDR)
        bn.xor w1, w1, w8         #   row_j ^= elimination term
        bn.sid x29, 32(x12)       #   Store back (x29=1 → w1)
        addi x12, x12, 64
        bn.gfmul.8 w11, w10, w29  #   Solution contribution
        bn.xor w3, w3, w11        #   solution_high ^= contribution
        bn.rshi w10, w10, w31 >> 248

    addi x24, x24, -1             # x24 = 11 (remaining after row 33)
    bn.rshi w30, w30, w31 >> 248   # Advance mask

    li x23, 1                      # Shift counter for positioning inverse

    /* ================================================================
     * PHASE E: ROWS 33..43 — main loop for upper-half pivots
     * ================================================================ */
    loopi 11, 57

        /* --- Conditional-add --------------------------------------- */
        lw x12, 0(x2)
        bn.lid x0, 32(x12)        #   w0 = current row high WDR
        addi x12, x12, 64

        bn.and w10, w3, w30       #   Extract solution byte
        bn.xor w3, w3, w10        #   Clear from solution
        bn.rshi w6, w31, w3 >> 8  #   Shifted solution for scanning

        loop x24, 8                # Search rows k+1..44
            bn.lid x29, 32(x12)
            addi x12, x12, 64
            bn.and w29, w0, w30, FG0
            bn.sel w1, w1, w31, FG0.z
            bn.sel w8, w6, w31, FG0.z
            bn.xor w0, w0, w1
            bn.xor w10, w10, w8
            bn.rshi w6, w31, w6 >> 8

        bn.and w10, w10, w30
        bn.or w2, w2, w10          # Park in w2 (scratch; already stored)

        /* --- Singularity check ------------------------------------- */
        bn.and w29, w0, w30
        bn.cmp w29, w31, FG0
        bn.sel w19, w21, w31, FG0.z
        bn.or w20, w20, w19

        /* --- Pivot inverse ----------------------------------------- */
        bn.gfmul.8.vv w28, w29, w29
        bn.gfmul.8.vv w27, w28, w28
        bn.gfmul.8.vv w26, w27, w27
        bn.gfmul.8.vv w25, w26, w26
        bn.gfmul.8.vv w24, w25, w25
        bn.gfmul.8.vv w23, w24, w24
        bn.gfmul.8.vv w22, w23, w23
        bn.gfmul.8.vv w29, w27, w28
        bn.gfmul.8.vv w29, w26, w29
        bn.gfmul.8.vv w29, w25, w29
        bn.gfmul.8.vv w29, w24, w29
        bn.gfmul.8.vv w29, w23, w29
        bn.gfmul.8.vv w29, w22, w29

        /* Set mod1 = x23 so gfmul.8 vxs reads inverse at byte x23 directly */
        csrrw x0, mod1, x23

        /* --- Scale row and solution -------------------------------- */
        bn.gfmul.8 w0, w0, w29        # Row *= w29[mod1=x23] = pivot^{-1}

        lw x12, 0(x2)
        bn.sid x28, 0(x12++)      #   Store low WDR (zeroes)
        bn.sid x0, 0(x12++)       #   Store scaled row high
        sw x12, 0(x2)

        bn.gfmul.8 w10, w10, w29
        bn.or w3, w3, w10
        bn.rshi w10, w10, w31 >> 248

        /* --- Eliminate from remaining rows ------------------------- */
        loop x24, 10               # Eliminate from rows k+1..44
            bn.lid x29, 32(x12)   #   w1 = row j high WDR
            bn.and w29, w1, w30   #   Column-k byte of row j (at byte x23)
            bn.gfmul.8 w8, w0, w29    #   w8 = w0 * w29[mod1=x23]
            bn.xor w1, w1, w8
            bn.sid x28, 0(x12)    #   Store low WDR (zeroes)
            bn.sid x29, 32(x12)   #   Store row j high (x29=1 → w1)
            addi x12, x12, 64
            bn.gfmul.8 w11, w10, w29
            bn.xor w3, w3, w11
            bn.rshi w10, w10, w31 >> 248

        /* --- Advance counters -------------------------------------- */
        addi x23, x23, 1
        addi x24, x24, -1
        bn.rshi w30, w30, w31 >> 248

    /* ================================================================
     * PHASE F: ROW 44 (last row) — only needs scaling, no elimination
     * ================================================================ */
    lw x12, 0(x2)
    bn.lid x0, 32(x12)            # w0 = last row high WDR

    /* --- Singularity check ----------------------------------------- */
    bn.cmp w0, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w20, w20, w19

    /* --- Pivot inverse --------------------------------------------- */
    bn.mov w29, w0
    bn.gfmul.8.vv w28, w29, w29
    bn.gfmul.8.vv w27, w28, w28
    bn.gfmul.8.vv w26, w27, w27
    bn.gfmul.8.vv w25, w26, w26
    bn.gfmul.8.vv w24, w25, w25
    bn.gfmul.8.vv w23, w24, w24
    bn.gfmul.8.vv w22, w23, w23
    bn.gfmul.8.vv w29, w27, w28
    bn.gfmul.8.vv w29, w26, w29
    bn.gfmul.8.vv w29, w25, w29
    bn.gfmul.8.vv w29, w24, w29
    bn.gfmul.8.vv w29, w23, w29
    bn.gfmul.8.vv w29, w22, w29

    /* --- Scale last row -------------------------------------------- */
    bn.gfmul.8.vv w0, w0, w29
    bn.sid x28, 0(x12)             # Store low WDR (zeroes; x28=31 → w31,
                                    #   row is empty in low half)
    bn.sid x0, 32(x12)            # Store scaled last row high

    /* --- Scale last solution byte and store ------------------------ */
    bn.and w4, w3, w30
    bn.xor w3, w3, w4
    bn.gfmul.8.vv w4, w4, w29
    bn.or w3, w3, w4

    bn.sid x31, 32(x11)           # Store solution high back (x31=3 → w3)

    addi x2, x2, 8                # Deallocate stack

    csrrw x0, mod1, x0            # reset mod1 = 0 so downstream bn.gfmul.8 vxs callers see clean state
ret

#else

/* =============== sw (SW gf256 multiply) =============== */
gaussian_elimination_45x45:

    bn.xor w19, w19, w19
    bn.xor w15, w15, w15
    bn.xor w21, w21, w21
    bn.not w21, w21
    bn.xor w31, w31, w31
    li x31, 0x11b
    csrrw x0, mod0, x31

    bn.addi w14, w31, 0xff

    /* Helper constants */
    la x4, msb_mask
    li x5, 16
    bn.lid x5, 0(x4)                /* w16 = msb_mask */
    bn.addi w17, w31, 0x1b          /* w17 = 0x1b */

    li x29, 1                        /* WDR idx for w1 */
    li x30, 2                        /* WDR idx for w2 */
    li x31, 3                        /* WDR idx for w3 */
    li x27, 4                        /* WDR idx for w4 */
    li x28, 5                        /* WDR idx for w5 */

    bn.lid x30, 0(x11)               /* w2 = solution low */
    bn.lid x31, 32(x11)              /* w3 = solution high */

    addi x2, x2, -128
    sw x0, 64(x2)
    sw x0, 68(x2)
    sw x0, 72(x2)
    sw x0, 76(x2)
    sw x0, 80(x2)
    sw x0, 84(x2)
    sw x0, 88(x2)
    sw x0, 92(x2)

    /* ================================================================ */
    /* PHASE A: ROW 0 (K=0)                                              */
    /* ================================================================ */
    sw x10, 0(x2)
    bn.lid x0, 0(x10++)
    bn.lid x29, 0(x10++)
    sw x10, 4(x2)

    bn.rshi w6, w3, w2 >> 8
    bn.rshi w7, w31, w3 >> 8
    bn.and w10, w2, w14
    bn.xor w2, w10, w2

    loopi 44, 11                      /* search rows 1..44 */
        bn.lid x27, 0(x10++)
        bn.lid x28, 0(x10++)
        bn.and w29, w0, w14, FG0
        bn.sel w4, w4, w31, FG0.z
        bn.sel w5, w5, w31, FG0.z
        bn.sel w8, w6, w31, FG0.z
        bn.xor w0, w0, w4
        bn.xor w1, w1, w5
        bn.xor w10, w10, w8
        bn.rshi w6, w7, w6 >> 8
        bn.rshi w7, w31, w7 >> 8

    bn.and w10, w10, w14
    bn.or w2, w2, w10

    bn.and w29, w0, w14
    bn.cmp w29, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w15, w15, w19

    jal x1, gf256_scalar_inv_sw

    /* Scale row 0 (low + high) and solution byte */
    bn.mov w0, w0
    bn.mov w1, w1
    bn.mov w19, w29
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.mov w0, w20
    bn.mov w1, w30
    bn.mov w12, w0
    bn.mov w13, w1

    bn.and w4, w2, w14
    bn.xor w2, w2, w4
    bn.mov w0, w4
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w4, w20
    bn.or w2, w2, w4

    bn.mov w0, w12
    bn.mov w1, w13
    lw x12, 0(x2)
    bn.sid x0, 0(x12++)
    bn.sid x29, 0(x12++)
    sw x12, 0(x2)

    bn.and w10, w2, w14
    bn.rshi w10, w10, w31 >> 248
    lw x10, 4(x2)

    /* Elim sub-loop A: rows 1..31 (sol -> w2). K=0 so w29 byte 0 directly. */
    loopi 31, 22
        bn.lid x27, 0(x10++)
        bn.lid x28, 0(x10++)
        bn.and w29, w4, w14
        bn.mov w0, w12
        bn.mov w1, w13
        bn.mov w19, w29
        bn.mov w20, w31
        bn.mov w30, w31
        jal x1, gf256_macc_dualvec_sw
        bn.mov w8, w20
        bn.mov w9, w30
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w11, w20
        bn.xor w4, w4, w8
        bn.xor w5, w5, w9
        bn.sid x27, -64(x10)
        bn.sid x28, -32(x10)
        bn.xor w2, w2, w11
        bn.rshi w10, w10, w31 >> 248

    /* Elim sub-loop B: rows 32..44 (sol -> w3). */
    bn.and w10, w2, w14
    loopi 13, 22
        bn.lid x27, 0(x10++)
        bn.lid x28, 0(x10++)
        bn.and w29, w4, w14
        bn.mov w0, w12
        bn.mov w1, w13
        bn.mov w19, w29
        bn.mov w20, w31
        bn.mov w30, w31
        jal x1, gf256_macc_dualvec_sw
        bn.mov w8, w20
        bn.mov w9, w30
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w11, w20
        bn.xor w4, w4, w8
        bn.xor w5, w5, w9
        bn.sid x27, -64(x10)
        bn.sid x28, -32(x10)
        bn.xor w3, w3, w11
        bn.rshi w10, w10, w31 >> 248

    bn.rshi w14, w14, w31 >> 248

    /* ================================================================ */
    /* PHASE B: ROWS 1..30 (K=x23, variable)                             */
    /* ================================================================ */
    li x23, 1
    li x24, 30                       /* x24 = 31-k: rows k+1..31 */

    loopi 30, 152                    /* pivots k = 1..30 */

        bn.and w10, w2, w14
        bn.xor w2, w10, w2
        bn.rshi w6, w3, w2 >> 8
        bn.rshi w7, w31, w3 >> 8

        lw x12, 0(x2)
        bn.lid x0, 0(x12++)
        bn.lid x29, 0(x12++)

        addi x25, x24, 13                /* x25 = 44-k */
        loop x25, 11                     /* search rows k+1..44 */
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.and w29, w0, w14, FG0
            bn.sel w4, w4, w31, FG0.z
            bn.sel w5, w5, w31, FG0.z
            bn.sel w8, w6, w31, FG0.z
            bn.xor w0, w0, w4
            bn.xor w1, w1, w5
            bn.xor w10, w10, w8
            bn.rshi w6, w7, w6 >> 8
            bn.rshi w7, w31, w7 >> 8

        bn.and w10, w10, w14
        bn.or w2, w2, w10

        bn.and w29, w0, w14
        bn.cmp w29, w31, FG0
        bn.sel w19, w21, w31, FG0.z
        bn.or w15, w15, w19        /* Byte-extract: byte x23 of w29 -> w29 byte 0 (x4/x5/x6 scratch) */
        li x5, 29
        bn.sid x5, 32(x2)
        add x4, x2, x23
        addi x4, x4, 32
        andi x6, x4, -4
        lw x6, 0(x6)
        andi x4, x4, 3
        slli x4, x4, 3
        srl x6, x6, x4
        andi x6, x6, 0xff
        sw x6, 64(x2)
        li x5, 29
        bn.lid x5, 64(x2)
        /* Restore WDR-idx GPRs clobbered by byte-extract (x5 = was 29). */
        li x29, 1
        li x27, 4
        li x28, 5

        jal x1, gf256_scalar_inv_sw
        bn.mov w0, w0
        bn.mov w1, w1
        bn.mov w19, w29
        bn.mov w20, w31
        bn.mov w30, w31
        jal x1, gf256_macc_dualvec_sw
        bn.mov w0, w20
        bn.mov w1, w30
        bn.mov w12, w0
        bn.mov w13, w1

        bn.mov w0, w12
        bn.mov w1, w13
        lw x12, 0(x2)
        bn.sid x0, 0(x12++)
        bn.sid x29, 0(x12++)

        bn.and w10, w2, w14
        bn.xor w2, w2, w10
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w10, w20
        bn.or w2, w2, w10
        sw x12, 0(x2)

        bn.rshi w10, w10, w31 >> 248

        loop x24, 38                     /* eliminate rows k+1..31 (sol -> w2) */
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.and w29, w4, w14            /* Byte-extract: byte x23 of w29 -> w29 byte 0 (x4/x5/x6 scratch) */
            li x5, 29
            bn.sid x5, 32(x2)
            add x4, x2, x23
            addi x4, x4, 32
            andi x6, x4, -4
            lw x6, 0(x6)
            andi x4, x4, 3
            slli x4, x4, 3
            srl x6, x6, x4
            andi x6, x6, 0xff
            sw x6, 64(x2)
            li x5, 29
            bn.lid x5, 64(x2)
            li x29, 1
            li x27, 4
            li x28, 5
            bn.mov w0, w12
            bn.mov w1, w13
            bn.mov w19, w29
            bn.mov w20, w31
            bn.mov w30, w31
            jal x1, gf256_macc_dualvec_sw
            bn.mov w8, w20
            bn.mov w9, w30
            bn.mov w0, w10
            bn.mov w19, w29
            bn.mov w20, w31
            jal x1, gf256_macc_sw
            bn.mov w11, w20
            bn.xor w4, w4, w8
            bn.xor w5, w5, w9
            bn.xor w2, w2, w11
            bn.sid x27, -64(x12)
            bn.sid x28, -32(x12)
            bn.rshi w10, w10, w31 >> 248
        bn.and w10, w2, w14
        loop x23, 1
            bn.rshi w10, w31, w10 >> 8

        loopi 13, 38                     /* eliminate rows 32..44 (sol -> w3) */
            bn.lid x27, 0(x12++)
            bn.lid x28, 0(x12++)
            bn.and w29, w4, w14            /* Byte-extract: byte x23 of w29 -> w29 byte 0 (x4/x5/x6 scratch) */
            li x5, 29
            bn.sid x5, 32(x2)
            add x4, x2, x23
            addi x4, x4, 32
            andi x6, x4, -4
            lw x6, 0(x6)
            andi x4, x4, 3
            slli x4, x4, 3
            srl x6, x6, x4
            andi x6, x6, 0xff
            sw x6, 64(x2)
            li x5, 29
            bn.lid x5, 64(x2)
            li x29, 1
            li x27, 4
            li x28, 5
            bn.mov w0, w12
            bn.mov w1, w13
            bn.mov w19, w29
            bn.mov w20, w31
            bn.mov w30, w31
            jal x1, gf256_macc_dualvec_sw
            bn.mov w8, w20
            bn.mov w9, w30
            bn.mov w0, w10
            bn.mov w19, w29
            bn.mov w20, w31
            jal x1, gf256_macc_sw
            bn.mov w11, w20
            bn.xor w4, w4, w8
            bn.xor w5, w5, w9
            bn.xor w3, w3, w11
            bn.sid x27, -64(x12)
            bn.sid x28, -32(x12)
            bn.rshi w10, w10, w31 >> 248
        bn.rshi w14, w14, w31 >> 248
        addi x23, x23, 1
        addi x24, x24, -1

    /* ================================================================ */
    /* PHASE C: ROW 31 (K=31, hardcoded; use immediate rshi >> 248)      */
    /* ================================================================ */
    li x24, 13

    bn.and w10, w2, w14
    bn.xor w2, w10, w2
    bn.rshi w6, w3, w2 >> 8
    bn.rshi w7, w31, w3 >> 8

    lw x12, 0(x2)
    bn.lid x0, 0(x12++)
    bn.lid x29, 0(x12++)

    loop x24, 11                     /* search rows 32..44 */
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.and w29, w0, w14, FG0
        bn.sel w4, w4, w31, FG0.z
        bn.sel w5, w5, w31, FG0.z
        bn.sel w8, w6, w31, FG0.z
        bn.xor w0, w0, w4
        bn.xor w1, w1, w5
        bn.xor w10, w10, w8
        bn.rshi w6, w7, w6 >> 8
        bn.rshi w7, w31, w7 >> 8

    bn.and w10, w10, w14
    bn.or w2, w2, w10

    bn.and w29, w0, w14
    bn.cmp w29, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w15, w15, w19

    /* Move byte 31 -> byte 0 (K=31, immediate rshi) */
    bn.rshi w29, w31, w29 >> 248

    jal x1, gf256_scalar_inv_sw
    bn.mov w0, w0
    bn.mov w1, w1
    bn.mov w19, w29
    bn.mov w20, w31
    bn.mov w30, w31
    jal x1, gf256_macc_dualvec_sw
    bn.mov w0, w20
    bn.mov w1, w30
    bn.mov w12, w0
    bn.mov w13, w1

    bn.mov w0, w12
    bn.mov w1, w13
    lw x12, 0(x2)
    bn.sid x0, 0(x12++)
    bn.sid x29, 0(x12++)

    bn.and w10, w2, w14
    bn.xor w2, w2, w10
    bn.mov w0, w10
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w10, w20
    bn.or w2, w2, w10
    sw x12, 0(x2)

    /* RIGHT shift sol_scaled byte 31 -> byte 0 (matches HW Phase C reload) */
    bn.rshi w10, w31, w10 >> 248

    loop x24, 23                     /* eliminate rows 32..44 */
        bn.lid x27, 0(x12++)
        bn.lid x28, 0(x12++)
        bn.and w29, w4, w14
        bn.rshi w29, w31, w29 >> 248
        bn.mov w0, w12
        bn.mov w1, w13
        bn.mov w19, w29
        bn.mov w20, w31
        bn.mov w30, w31
        jal x1, gf256_macc_dualvec_sw
        bn.mov w8, w20
        bn.mov w9, w30
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w11, w20
        bn.xor w4, w4, w8
        bn.xor w5, w5, w9
        bn.xor w3, w3, w11
        bn.sid x27, -64(x12)
        bn.sid x28, -32(x12)
        bn.rshi w10, w10, w31 >> 248

    bn.sid x30, 0(x11)
    bn.rshi w14, w31, w14 >> 248

    /* ================================================================ */
    /* PHASE D: ROW 32 (K=0 in upper WDR half)                           */
    /* ================================================================ */
    li x24, 12
    li x28, 31                       /* WDR idx for w31 (zeros) — for sid */

    lw x12, 0(x2)
    bn.lid x0, 32(x12)
    addi x12, x12, 64

    bn.and w10, w3, w14
    bn.xor w3, w3, w10
    bn.rshi w6, w31, w3 >> 8

    loop x24, 8                      /* search rows 33..44 */
        bn.lid x29, 32(x12)
        addi x12, x12, 64
        bn.and w29, w0, w14, FG0
        bn.sel w1, w1, w31, FG0.z
        bn.sel w8, w6, w31, FG0.z
        bn.xor w0, w0, w1
        bn.xor w10, w10, w8
        bn.rshi w6, w31, w6 >> 8

    bn.and w10, w10, w14
    bn.or w2, w2, w10

    bn.and w29, w0, w14
    bn.cmp w29, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w15, w15, w19

    /* K=0: w29 byte 0 already = pivot */
    jal x1, gf256_scalar_inv_sw
    bn.mov w0, w0
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w0, w20
    bn.mov w12, w0

    lw x12, 0(x2)
    bn.sid x28, 0(x12++)             /* low WDR = w31 = zeros */
    bn.sid x0, 0(x12++)              /* high WDR = scaled row */
    bn.mov w0, w10
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w10, w20
    bn.or w3, w3, w10
    bn.rshi w10, w10, w31 >> 248
    sw x12, 0(x2)

    loop x24, 18                     /* eliminate rows 33..44 */
        bn.lid x29, 32(x12)
        bn.and w29, w1, w14
        /* K=0: byte 0 already at byte 0 */
        bn.mov w0, w12
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w8, w20
        bn.xor w1, w1, w8
        bn.sid x28, 0(x12)
        bn.sid x29, 32(x12)
        addi x12, x12, 64
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w11, w20
        bn.xor w3, w3, w11
        bn.rshi w10, w10, w31 >> 248

    li x29, 1                        /* restore WDR idx */
    addi x24, x24, -1
    bn.rshi w14, w14, w31 >> 248
    li x23, 1

    /* ================================================================ */
    /* PHASE E: ROWS 33..43 (K=x23, variable)                            */
    /* ================================================================ */
    loopi 11, 93

        lw x12, 0(x2)
        bn.lid x0, 32(x12)
        addi x12, x12, 64

        bn.and w10, w3, w14
        bn.xor w3, w3, w10
        bn.rshi w6, w31, w3 >> 8

        loop x24, 8                  /* search rows k+1..44 */
            bn.lid x29, 32(x12)
            addi x12, x12, 64
            bn.and w29, w0, w14, FG0
            bn.sel w1, w1, w31, FG0.z
            bn.sel w8, w6, w31, FG0.z
            bn.xor w0, w0, w1
            bn.xor w10, w10, w8
            bn.rshi w6, w31, w6 >> 8

        bn.and w10, w10, w14
        bn.or w2, w2, w10

        bn.and w29, w0, w14
        bn.cmp w29, w31, FG0
        bn.sel w19, w21, w31, FG0.z
        bn.or w15, w15, w19        /* Byte-extract: byte x23 of w29 -> w29 byte 0 (x4/x5/x6 scratch) */
        li x5, 29
        bn.sid x5, 32(x2)
        add x4, x2, x23
        addi x4, x4, 32
        andi x6, x4, -4
        lw x6, 0(x6)
        andi x4, x4, 3
        slli x4, x4, 3
        srl x6, x6, x4
        andi x6, x6, 0xff
        sw x6, 64(x2)
        li x5, 29
        bn.lid x5, 64(x2)
        li x29, 1
        li x27, 4
        li x28, 31

        jal x1, gf256_scalar_inv_sw
        bn.mov w0, w0
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w0, w20
        bn.mov w12, w0

        lw x12, 0(x2)
        bn.sid x28, 0(x12++)
        bn.sid x0, 0(x12++)
        sw x12, 0(x2)
        bn.mov w0, w10
        bn.mov w19, w29
        bn.mov w20, w31
        jal x1, gf256_macc_sw
        bn.mov w10, w20
        bn.or w3, w3, w10
        bn.rshi w10, w10, w31 >> 248

        loop x24, 34                 /* eliminate rows k+1..44 */
            bn.lid x29, 32(x12)
            bn.and w29, w1, w14            /* Byte-extract: byte x23 of w29 -> w29 byte 0 (x4/x5/x6 scratch) */
            li x5, 29
            bn.sid x5, 32(x2)
            add x4, x2, x23
            addi x4, x4, 32
            andi x6, x4, -4
            lw x6, 0(x6)
            andi x4, x4, 3
            slli x4, x4, 3
            srl x6, x6, x4
            andi x6, x6, 0xff
            sw x6, 64(x2)
            li x5, 29
            bn.lid x5, 64(x2)
            li x29, 1
            li x27, 4
            li x28, 31
            bn.mov w0, w12
            bn.mov w19, w29
            bn.mov w20, w31
            jal x1, gf256_macc_sw
            bn.mov w8, w20
            bn.xor w1, w1, w8
            bn.sid x28, 0(x12)
            bn.sid x29, 32(x12)
            addi x12, x12, 64
            bn.mov w0, w10
            bn.mov w19, w29
            bn.mov w20, w31
            jal x1, gf256_macc_sw
            bn.mov w11, w20
            bn.xor w3, w3, w11
            bn.rshi w10, w10, w31 >> 248
        addi x23, x23, 1
        addi x24, x24, -1
        bn.rshi w14, w14, w31 >> 248

    /* ================================================================ */
    /* PHASE F: ROW 44 (last row; K=12, only scaling)                    */
    /* ================================================================ */
    lw x12, 0(x2)
    bn.lid x0, 32(x12)

    bn.cmp w0, w31, FG0
    bn.sel w19, w21, w31, FG0.z
    bn.or w15, w15, w19

    bn.mov w29, w0
    /* Move byte 12 -> byte 0 (K=12, immediate rshi >> 96) */
    bn.rshi w29, w31, w29 >> 96

    jal x1, gf256_scalar_inv_sw
    bn.mov w0, w0
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w0, w20

    bn.sid x28, 0(x12)                /* low WDR = zeros */
    bn.sid x0, 32(x12)                /* high WDR = scaled */

    bn.and w4, w3, w14
    bn.xor w3, w3, w4
    bn.mov w0, w4
    bn.mov w19, w29
    bn.mov w20, w31
    jal x1, gf256_macc_sw
    bn.mov w4, w20
    bn.or w3, w3, w4

    bn.sid x31, 32(x11)               /* store solution high (x31=3 → w3) */

    /* Copy cumulative singularity flag from w15 (preserved across helpers)
     * to w20 (the return reg checked by the orchestrator). */
    bn.mov w20, w15

    addi x2, x2, 128
    csrrw x0, mod1, x0
    ret



#endif

module acc_aes_bignum
  import acc_pkg::*;
(
  input  aes_bignum_operation_t operation_i,
  output logic [WLEN-1:0]       operation_result_o,

  input  aes_predec_bignum_t    aes_predec_bignum_i,

  input  logic                  aes_en_i
);

  logic [255:0] operand_a_blanked;
  logic [127:0] operand_b_blanked;

  logic [127:0] new_state_lo, new_state_hi;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(128)) u_operand_a_blanker_lo (
    .in_i (operation_i.operand_a[127:0]),
    .en_i (aes_predec_bignum_i.op_en),
    .out_o(operand_a_blanked[127:0])
  );

  prim_blanker #(.Width(128)) u_operand_a_blanker_hi (
    .in_i (operation_i.operand_a[255:128]),
    .en_i (aes_predec_bignum_i.op_en & ~aes_predec_bignum_i.key_expand),
    .out_o(operand_a_blanked[255:128])
  );

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(128)) u_operand_b_blanker (
    .in_i (operation_i.operand_b[WLEN/2-1:0]),
    .en_i (aes_predec_bignum_i.op_en),
    .out_o(operand_b_blanked)
  );

  aes_round_keyexpand u_aes_round_keyexpand_lo (
    .key_expand(operation_i.key_expand),      // 1: do key expansion, 0: encryption
    .final_round(operation_i.final_round),    // ignored if key_expand = 1
    .round_index(operation_i.round),          // used only in key expansion
    .state_i(operand_a_blanked[127:0]),       // AES state or previous round key
    .roundkey_i(operand_b_blanked[127:0]),    // round key input (used in encryption only)
    .state_o(new_state_lo)                    // AES state or next round key
  );

  aes_round_keyexpand u_aes_round_keyexpand_hi (
    .key_expand(1'b0),                        // 1: do key expansion, 0: encryption
    .final_round(operation_i.final_round),    // ignored if key_expand = 1
    .round_index(5'b00000),                   // used only in key expansion
    .state_i(operand_a_blanked[255:128]),     // AES state or previous round key
    .roundkey_i(operand_b_blanked[127:0]),    // round key input (used in encryption only)
    .state_o(new_state_hi)                    // AES state or next round key
  );

  function automatic logic [127:0] swap_counter32_be(
    input logic [127:0] data,
    input logic         swap_endian
  );
    logic [127:0] result;

    result = data;

    if (swap_endian) begin
      // Bytes 12–15 correspond to bits [127:96]
      result[127:120] = data[103:96];   // byte 15 <- byte 12
      result[119:112] = data[111:104];  // byte 14 <- byte 13
      result[111:104] = data[119:112];  // byte 13 <- byte 14
      result[103:96]  = data[127:120];  // byte 12 <- byte 15
    end

    return result;
  endfunction

  assign operation_result_o =
       operation_i.key_expand  ? {{128'b0}, new_state_lo} :
       operation_i.first_round ? {swap_counter32_be(operand_a_blanked[255:128], operation_i.swap_endian)
                                       ^ operand_b_blanked[127:0],
                                  swap_counter32_be(operand_a_blanked[127:0],   operation_i.swap_endian)
                                       ^ operand_b_blanked[127:0]} :
                                 {new_state_hi, new_state_lo};

  logic unused_ok;
  assign unused_ok = (^aes_en_i) ^ (^operation_i.operand_b[255:128]);

endmodule


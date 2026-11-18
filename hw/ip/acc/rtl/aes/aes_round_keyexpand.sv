module aes_round_keyexpand (
  input  logic         key_expand,     // 1: do key expansion, 0: encryption
  input  logic         final_round,    // ignored if key_expand = 1
  input  logic [4:0]   round_index,    // used only in key expansion
  input  logic [127:0] state_i,        // AES state or previous round key
  input  logic [127:0] roundkey_i,     // round key input (used in encryption only)
  output logic [127:0] state_o         // AES state or next round key
);

  // Shared 16 S-box instances
  logic [7:0] sbox_in[15:0];
  logic [7:0] sbox_out[15:0];

  for (genvar i = 0; i < 16; i++) begin : gen_sub_bytes
    aes_sbox_lut sbox_inst (
      .data_i(sbox_in[i]),
      .data_o(sbox_out[i]),
      .op_i(2'b01)
    );
  end

  ////////////////////////////////////////////
  // ENCRYPTION PATH (key_expand == 0)
  ////////////////////////////////////////////

  logic [3:0][3:0][7:0] state_bytes, sub_bytes, shift_rows_out, mix_columns_out;
  logic [3:0][3:0][7:0] final_state_bytes;
  logic [127:0] enc_out;

  // Deserialize input state to matrix form
  always_comb begin
    for (int col = 0; col < 4; col++) begin
      for (int row = 0; row < 4; row++) begin
        state_bytes[row][col] = state_i[((col * 4 + row) * 8) +: 8];
      end
    end
  end

  // Connect encryption input bytes to shared S-boxes
  always_comb begin
    for (int col = 0; col < 4; col++) begin
      for (int row = 0; row < 4; row++) begin
        sbox_in[col * 4 + row] = key_expand ? 8'h00 : state_bytes[row][col];
      end
    end
    // For key expansiom, feed RotWord bytes into S-boxes (positions 0...3)
    for (int i = 0; i < 4; i++) begin
      if (key_expand) begin
        sbox_in[i] = rotword[i * 8 +: 8];
      end
    end
  end

  // Capture S-box outputs for encryption
  always_comb begin
    for (int col = 0; col < 4; col++) begin
      for (int row = 0; row < 4; row++) begin
        sub_bytes[row][col] = sbox_out[col * 4 + row];
      end
    end
  end

  // ShiftRows & MixColumns
  aes_shift_rows shift_rows_inst (
    .data_i(sub_bytes),
    .data_o(shift_rows_out),
    .op_i(2'b01)
  );

  aes_mix_columns mix_columns_inst (
    .data_i(shift_rows_out),
    .data_o(mix_columns_out),
    .op_i(2'b01)
  );

  // Select final bytes after MixColumns or just ShiftRows
  always_comb begin
    final_state_bytes = final_round ? shift_rows_out : mix_columns_out;
    enc_out = 128'b0;
    for (int col = 0; col < 4; col++) begin
      for (int row = 0; row < 4; row++) begin
        enc_out[(row + col*4) * 8 +: 8] = final_state_bytes[row][col];
      end
    end
    enc_out = enc_out ^ roundkey_i;
  end

  ////////////////////////////////////////////
  // KEY EXPANSION PATH (key_expand == 1)
  ////////////////////////////////////////////

  logic [31:0] w0, w1, w2, w3, next_w0, next_w1, next_w2, next_w3;
  logic [31:0] rotword, subword;
  logic [7:0]  rcon;

  assign w0 = roundkey_i[31:0];
  assign w1 = roundkey_i[63:32];
  assign w2 = roundkey_i[95:64];
  assign w3 = roundkey_i[127:96];

  // RotWord: {w3[23:0], w3[31:24]}
  assign rotword = {w3[7:0], w3[31:8]};

//  // Feed RotWord bytes into S-boxes (positions 0...3)
//  always_comb begin
//    for (int i = 0; i < 4; i++) begin
//      if (key_expand) begin
//        sbox_in[i] = rotword[31 - i * 8 -: 8];
//      end
//    end
//  end

  // SubWord using S-box outputs
  assign subword = {sbox_out[3], sbox_out[2], sbox_out[1], sbox_out[0]};

  // Rcon lookup (for AES-128)
  always_comb begin
    case (round_index)
      5'h01: rcon = 8'h01;
      5'h02: rcon = 8'h02;
      5'h03: rcon = 8'h04;
      5'h04: rcon = 8'h08;
      5'h05: rcon = 8'h10;
      5'h06: rcon = 8'h20;
      5'h07: rcon = 8'h40;
      5'h08: rcon = 8'h80;
      5'h09: rcon = 8'h1B;
      5'h0A: rcon = 8'h36;
      default: rcon = 8'h00;
    endcase
  end

  // Key expansion steps
  assign next_w0 = w0 ^ subword ^ {24'b0, rcon};
  assign next_w1 = w1 ^ next_w0;
  assign next_w2 = w2 ^ next_w1;
  assign next_w3 = w3 ^ next_w2;

  ////////////////////////////////////////////
  // OUTPUT SELECTION
  ////////////////////////////////////////////

  always_comb begin
    if (key_expand)
      state_o = {next_w3, next_w2, next_w1, next_w0};
    else
      state_o = enc_out;
  end

endmodule


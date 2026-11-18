module gfmacc (
  input  logic [255:0] operand_a,
  input  logic [255:0] operand_b,
  input  logic         mode,       // mode: 0 - G(F16), 1 - GF(256)
  input  logic         vxv,        // 0: vector-scalar; 1: vector-vector
  input  logic         inc,
  input  logic [255:0] mod_i,
  output logic [255:0] mod_o,
  output logic         wr_mod_en,
  output logic [255:0] res
);

  logic [8:0] mod_poly8;
  logic [4:0] mod_poly4;

`ifdef MOD_REG_POLY
  assign mod_poly8 = mod_i[8:0];
  assign mod_poly4 = mod_i[4:0];
`else
  assign mod_poly8 = 9'b1_0001_1011; // Modular reduction by x^8 + x^4 + x^3 + x + 1
  assign mod_poly4 = 5'b1_0011;      // Modular reduction by x^4 + x + 1
`endif

  always_comb begin
    if (|mod_i[255:0]) begin
      // This disables UNUSEDSIGNAL warnings.
    end
  end

  logic [7:0]  a_words8 [31:0];
  logic [7:0]  b_words8 [31:0];

  logic [15:0] p_words8 [31:0];

  logic [255:0] res8;


  assign mod_o =
      mode == 1'b0 ? {mod_i[64 +: 192], {26{1'b0}}, mod_i[32 +: 6] + 6'b000001, mod_i[0 +: 32]}
                   : {mod_i[64 +: 192], {27{1'b0}}, mod_i[32 +: 5] +  5'b00001, mod_i[0 +: 32]};

  assign wr_mod_en = inc;

  // Unpack A
  genvar i;
  generate
    for (i = 0; i < 32; i++) begin
      assign a_words8[i] = operand_a[i*8 +: 8];
      //assign b_words8[i] = vxv ? operand_b[i*8 +: 8] : operand_b[0 +: 8];
      assign b_words8[i] = vxv ? operand_b[i*8 +: 8] : operand_b[{3'b000, mod_i[32 +: 5]}*8 +: 8];
    end
  endgenerate

  // Binary polynomial multiplication for each word
  generate
    for (i = 0; i < 32; i++) begin : GF2_MUL8
      integer j;
      always_comb begin
        p_words8[i] = 16'b0;
        for (j = 0; j < 8; j++) begin
          if (b_words8[i][j]) begin
            p_words8[i] ^= ({{8'b0}, a_words8[i]} << j);
          end
        end

        // Reduce degrees > 7
        for (j = 15; j >= 8; j--) begin
          if (p_words8[i][j]) begin
            p_words8[i] ^= ({7'b0, mod_poly8[8:0]} << (j - 8));
          end
        end
      end
    end
  endgenerate

  // Pack results into output vector
  generate
    for (i = 0; i < 32; i++) begin
      assign res8[i*8 +: 8] = p_words8[i][7:0];
    end
  endgenerate

  logic [3:0] a_words4 [63:0];
  logic [3:0] b_words4 [63:0];

  logic [7:0] p_words4 [63:0];

  logic [255:0] res4;

  // Unpack A
  generate
    for (i = 0; i < 64; i++) begin
      assign a_words4[i] = operand_a[i*4 +: 4];
      //assign b_words4[i] = vxv ? operand_b[i*4 +: 4] : operand_b[0 +: 4];
      assign b_words4[i] = vxv ? operand_b[i*4 +: 4] : operand_b[{2'b00, mod_i[32 +: 6]}*4 +: 4];
    end
  endgenerate

  // Binary polynomial multiplication for each word
  generate
    for (i = 0; i < 64; i++) begin : GF2_MUL4
      integer j;
      always_comb begin
        p_words4[i] = 8'b0;
        for (j = 0; j < 4; j++) begin
          if (b_words4[i][j]) begin
            p_words4[i] ^= ({{4'b0}, a_words4[i]} << j);
          end
        end

        // Reduce degrees > 4
        for (j = 7; j >= 4; j--) begin
          if (p_words4[i][j]) begin
            p_words4[i] ^= ({3'b0, mod_poly4[4:0]} << (j - 4));
          end
        end
      end
    end
  endgenerate

  // Pack results into output vector
  generate
    for (i = 0; i < 64; i++) begin
      assign res4[i*4 +: 4] = p_words4[i][3:0];
    end
  endgenerate

  assign res = mode == 1'b0 ? res4 : res8;

endmodule


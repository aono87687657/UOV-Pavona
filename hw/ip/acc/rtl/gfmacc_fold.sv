module gfmacc (
  input  logic [255:0] operand_a,
  input  logic [7:0]   operand_b,
  input  logic         mode,       // mode: 0 - G(F16), 1 - GF(256)
  output logic [255:0] res
);

  logic [7:0] a_words256 [31:0];

  logic [255:0] res256;

  // Unpack A
  genvar i;
  generate
    for (i = 0; i < 32; i++) begin
      assign a_words256[i] = operand_a[i*8 +: 8];
    end
  endgenerate

  // Binary polynomial multiplication for each word
  generate
    for (i = 0; i < 32; i++) begin : GF2_MUL
      integer j;
      logic [15:0] prod;
      logic [11:0] top1;
      logic [11:0] bot1;
      logic [7:0] top2;
      logic [7:0] bot2;

      always_comb begin
        prod = 16'b0;
        for (j = 0; j < 8; j++) begin
          if (operand_b[j]) begin
            prod ^= ({{8'b0}, a_words256[i]} << j);
          end
        end

        top1 = {{4'b0}, prod[8+:8]};
        bot1 = {{4'b0}, prod[0+:8]} ^ (top1 << 0) ^ (top1 << 1) ^ (top1 << 3) ^ (top1 << 4);

        top2 = {{4'b0}, bot1[8+:4]};
        bot2 = bot1[0+:8] ^ (top2 << 0) ^ (top2 << 1) ^ (top2 << 3) ^ (top2 << 4);

        res256[i*8 +: 8] = bot2;
      end
    end
  endgenerate

  logic [3:0] a_words16 [63:0];

  logic [255:0] res16;

  // Unpack A
  generate
    for (i = 0; i < 64; i++) begin
      assign a_words16[i] = operand_a[i*4 +: 4];
    end
  endgenerate

  // Binary polynomial multiplication for each word
  generate
    for (i = 0; i < 64; i++) begin : GF2_MUL16
      integer j;
      logic [7:0] prod;
      logic [5:0] top1;
      logic [5:0] bot1;
      logic [3:0] top2;
      logic [3:0] bot2;

      always_comb begin
        prod = 8'b0;
        for (j = 0; j < 4; j++) begin
          if (operand_b[j]) begin
            prod ^= ({{4'b0}, a_words16[i]} << j);
          end
        end

        top1 = {{2'b0}, prod[4+:4]};
        bot1 = {{2'b0}, prod[0+:4]} ^ (top1 << 0) ^ (top1 << 1);

        top2 = {{2'b0}, bot1[4+:2]};
        bot2 = bot1[0+:4] ^ (top2 << 0) ^ (top2 << 1);

        res16[i*4 +: 4] = bot2;
      end
    end
  endgenerate

  assign res = mode == 1'b0 ? res16 : res256;

endmodule


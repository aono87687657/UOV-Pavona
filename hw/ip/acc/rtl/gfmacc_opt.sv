module gfmacc (
  input  logic [255:0] operand_a,
  input  logic [7:0]   operand_b,
  input  logic         mode,       // mode: 0 - G(F16), 1 - GF(256)
  output logic [255:0] res
);

  logic [7:0] a_words256 [31:0];

  logic [7:0] b_word;

  assign b_word = operand_b; //{(mode ? operand_b[7:4] : operand_b[3:0]), operand_b[3:0]};

  logic [255:0] res256;

  // Unpack A
  genvar i;
  generate
    for (i = 0; i < 32; i++) begin
      assign a_words256[i] = operand_a[i*8 +: 8];
    end
  endgenerate

  logic [15:0] prod [31:0];

  // Binary polynomial multiplication for each word
  generate
    for (i = 0; i < 32; i++) begin : GF2_MUL
      integer j;
      logic [15:0] prod16;
      logic [11:0] top1;
      logic [11:0] bot1;
      logic [7:0] top2;
      logic [7:0] bot2;

      //logic [7:0] prod1;
      logic [7:0] prod2;
      logic [7:0] prod3;

      always_comb begin
        prod[i] = 16'b0;
        for (j = 0; j < 4; j++) begin
          if (b_word[j]) begin
            prod[i][7:0] ^= ({{4'b0}, a_words256[i][0+:4]} << j);
          end
        end

        //prod1 = 8'b0;
        for (j = 0; j < 4; j++) begin
          if (b_word[j]) begin
            prod[i][15:8] ^= ({{4'b0}, a_words256[i][4+:4]} << j);
            //prod1 ^= ({{4'b0}, a_words256[i][4+:4]} << j);
          end
        end

        prod2 = 8'b0;
        for (j = 0; j < 4; j++) begin
          if (b_word[j+4]) begin
            prod2 ^= ({{4'b0}, a_words256[i][0+:4]} << j);
          end
        end

        prod3 = 8'b0;
        for (j = 0; j < 4; j++) begin
          if (b_word[j+4]) begin
            //prod[i][15:8] ^= ({{4'b0}, a_words256[i][4+:4]} << j);
            prod3 ^= ({{4'b0}, a_words256[i][4+:4]} << j);
          end
        end

        //prod16 = {{8'b0}, prod[i][7:0]} ^ {{4'b0}, prod1, {4'b0}} ^ {{4'b0}, prod2, {4'b0}} ^ {prod[i][15:8], {8'b0}};
        prod16 = {{8'b0}, prod[i][7:0]} ^ 
                   {{4'b0}, prod[i][15:8], {4'b0}} ^ 
                   {{4'b0}, prod2, {4'b0}} ^ 
                   {prod3, {8'b0}};

        top1 = {{4'b0}, prod16[8+:8]};
        bot1 = {{4'b0}, prod16[0+:8]} ^ (top1 << 0) ^ (top1 << 1) ^ (top1 << 3) ^ (top1 << 4);

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
      logic [7:0] prod8;
      logic [5:0] top1;
      logic [5:0] bot1;
      logic [3:0] top2;
      logic [3:0] bot2;

      always_comb begin
        prod8 = prod[i >> 1][i[0]*8 +: 8];

        top1 = {{2'b0}, prod8[4+:4]};
        bot1 = {{2'b0}, prod8[0+:4]} ^ (top1 << 0) ^ (top1 << 1);

        top2 = {{2'b0}, bot1[4+:2]};
        bot2 = bot1[0+:4] ^ (top2 << 0) ^ (top2 << 1);

        res16[i*4 +: 4] = bot2;
      end
    end
  endgenerate

  assign res = mode == 1'b0 ? res16 : res256;

endmodule


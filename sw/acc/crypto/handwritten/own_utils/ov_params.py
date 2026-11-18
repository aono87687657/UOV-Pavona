"""
OV Parameter Sets

Centralizes all OV scheme constants so test scripts only need to select
a parameter set rather than redefine every constant.

Covers both verify and sign flows, including per-component DMEM layouts,
ELF paths, dimension constants, and computed properties.
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class OVParams:
    """Complete parameter set for one OV variant."""
    # Scheme name
    name: str
    # Short tag used in ELF paths and labels ("Is" / "Ip" / "Ip3").  No default:
    # every param set must state it, so a new set cannot silently route to
    # another set's binaries.
    short: str
    # Galois field: 16 or 256
    gf: int
    # Core parameters
    pub_n: int        # Total variables
    pub_m: int        # Output polynomials
    v: int            # Vinegar variables
    o: int            # Oil variables

    # Derived byte sizes
    pub_m_byte: int   # Bytes per output vector
    pub_n_byte: int   # Bytes per input vector
    salt_bytes: int   # Salt size (always 16)

    # Key/signature sizes (logical, before alignment padding)
    max_message_size: int  # Max message (always 0x400)

    # PKC (compressed public key) parameters
    pkc_seed_size: int = 16  # AES-128 seed

    # ------------------------------------------------------------------ #
    #  Classic publicmap DMEM layout (verify flow)
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    #  Sign-specific sizes
    # ------------------------------------------------------------------ #
    len_skseed: int = 32       # sk_seed length (always 32 bytes)
    len_pkseed: int = 16       # pk_seed length (always 16 bytes)

    # O matrix: v * o elements.  For GF16 each element is a nibble so
    # O_SIZE = v * o // 2; for GF256 each element is a byte so O_SIZE = v * o.
    # Stored here as the *byte* size of the O matrix.
    o_size: int = 0
    # Total stored bytes of O.  With o_slot_bytes == 0 this is o_size rounded
    # up to the next 32-byte boundary (one trailing pad).  With o_slot_bytes
    # > 0 each column gets its own slot and the pad is interleaved.
    o_size_padded: int = 0
    o_slot_bytes: int = 0      # per-column slot stride; 0 = contiguous O

    # ------------------------------------------------------------------ #
    #  expandsk DMEM layout
    # ------------------------------------------------------------------ #
    expandsk_skseed_addr: int = 0
    expandsk_pkseed_addr: int = 0
    expandsk_o_addr: int = 0
    default_expandsk_elf: str = ""

    # ------------------------------------------------------------------ #
    #  P1P1TO (trimat_2trimat_madd) DMEM layout
    # ------------------------------------------------------------------ #
    p1p1to_aes128_key_addr: int = 0
    p1p1to_o_matrix_addr: int = 0
    p1p1to_result_addr: int = 0
    default_p1p1to_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Keygen: P1*O + P2 and P3 DMEM layout
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    #  Transpose DMEM layout & dimensions
    # ------------------------------------------------------------------ #
    transpose_input_addr: int = 0
    transpose_input_rows: int = 0
    transpose_input_cols: int = 0
    transpose_output_rows: int = 0
    transpose_output_cols: int = 0
    default_transpose_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Hash (hash_salted_msg) DMEM layout
    # ------------------------------------------------------------------ #
    hash_msg_len_addr: int = 0
    hash_msg_addr: int = 0x20
    default_hash_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Gaussian elimination DMEM layout
    # ------------------------------------------------------------------ #
    ge_input_matrix_addr: int = 0
    ge_input_vector_addr: int = 0
    ge_row_padding: int = 0       # 0 for GF16 (32-byte rows), 64 for GF256
    ge_status_wdr: str = ""       # WDR name holding GE success flag (e.g. "w24")
    default_ge_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Back-substitution DMEM layout
    # ------------------------------------------------------------------ #
    backsub_input_matrix_addr: int = 0
    backsub_input_vector_addr: int = 0
    backsub_output_vector_addr: int = 0
    default_backsub_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Small matvec (O * oil_solution) DMEM layout
    # ------------------------------------------------------------------ #
    small_matvec_matrix_addr: int = 0
    small_matvec_vector_addr: int = 0
    small_matvec_accum_addr: int = 0      # GF256 only; 0 for GF16
    small_matvec_result_wdrs: Tuple[str, ...] = ()
    default_small_matvec_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Large matvec (trimat * vinegar) DMEM layout
    # ------------------------------------------------------------------ #
    large_matvec_matrix_addr: int = 0
    large_matvec_accum_addr: int = 0
    large_matvec_n_a_byte_addr: int = 0
    large_matvec_n_a_width_addr: int = 0
    large_matvec_vector_addr: int = 0
    default_large_matvec_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Trimat eval (batch_quad_trimat_eval) DMEM layout
    # ------------------------------------------------------------------ #
    trimat_eval_pkseed_addr: int = 0
    trimat_eval_vinegar_addr: int = 0
    trimat_eval_result_addr: int = 0
    default_trimat_eval_elf: str = ""

    # ------------------------------------------------------------------ #
    #  Full sign DMEM layout
    # ------------------------------------------------------------------ #
    sign_skseed_addr: int = 0
    sign_msg_len_addr: int = 0
    sign_msg_addr: int = 0
    sign_sig_addr: int = 0
    sign_y_addr: int = 0
    sign_l_matrix_addr: int = 0
    sign_vinegar_addr: int = 0
    sign_target_addr: int = 0
    sign_salt_addr: int = 0
    sign_s_output_addr: int = 0
    sign_pkseed_output_addr: int = 0
    sign_o_output_addr: int = 0
    sign_salt_input_addr: int = 0        # DMEM slot for testvec salt (only in -DUSE_TESTVEC_SALT ELFs)
    sign_testvec_offset: int = 0         # +bytes applied to post-sig sign_*_addr when reading testvec ELF
    sign_ldirect_scratch: int = 0        # L-direct wrapper scratch reserved in place of the S buffer (exact stack peak)
    default_sign_elf: str = ""

    # ================================================================== #
    #  Computed properties
    # ================================================================== #

    @property
    def pub_m_byte_padded(self) -> int:
        """pub_m_byte rounded up to next 32-byte boundary."""
        return ((self.pub_m_byte + 31) // 32) * 32

    @property
    def needs_column_padding(self) -> bool:
        """True when pub_m_byte is not a multiple of 32 (i.e. GF256/OV-Ip)."""
        return self.pub_m_byte % 32 != 0

    @property
    def signature_bytes(self) -> int:
        return self.pub_n_byte + self.salt_bytes

    @property
    def trimat_size(self) -> int:
        return ((self.v * (self.v + 1)) // 2
                + self.v * self.o
                + (self.o * (self.o + 1)) // 2) * self.pub_m_byte

    @property
    def p1_size(self) -> int:
        return (self.v * (self.v + 1) // 2) * self.pub_m_byte

    @property
    def p2_size(self) -> int:
        return (self.v * self.o) * self.pub_m_byte

    @property
    def p3_size(self) -> int:
        return (self.o * (self.o + 1) // 2) * self.pub_m_byte

    @property
    def cpk_size(self) -> int:
        return self.pkc_seed_size + self.p3_size


OV_IS = OVParams(
    name="OV16_160_64",
    short="Is",
    gf=16,
    pub_n=160, pub_m=64, v=96, o=64,
    pub_m_byte=32,   # PUB_M // 2 for GF16
    pub_n_byte=80,   # PUB_N // 2 for GF16
    salt_bytes=16,
    max_message_size=0x400,
    # --- Keygen ---
    # --- Sign sizes ---
    o_size=96 * 64 // 2,       # 3072 bytes (GF16: nibble-packed v*o/2)
    o_size_padded=((96 * 64 // 2 + 31) // 32) * 32,  # 3072 (already aligned)
    # --- expandsk ---
    expandsk_skseed_addr=0x0,
    expandsk_pkseed_addr=0x20,
    expandsk_o_addr=0x40,
    default_expandsk_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/expandsk_ret_O_pkseed_test.elf",
    # --- P1P1TO ---
    p1p1to_aes128_key_addr=0x30c00,
    p1p1to_o_matrix_addr=0x30000,
    p1p1to_result_addr=0x0,
    default_p1p1to_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Is-skc/gf16trimat_2trimat_madd_96_48_64_32_test.elf",
    # --- Transpose ---
    transpose_input_addr=0x0,
    transpose_input_rows=64,
    transpose_input_cols=64,
    transpose_output_rows=64,
    transpose_output_cols=64,
    default_transpose_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/gf16_transpose_64_64_test.elf",
    # --- Hash ---
    hash_msg_len_addr=0x00,
    hash_msg_addr=0x20,
    default_hash_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/hash_salted_msg_test.elf",
    # --- Gaussian elimination ---
    ge_input_matrix_addr=0x0,
    ge_input_vector_addr=0x800,
    ge_row_padding=0,
    ge_status_wdr="w24",
    default_ge_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/gaussian_elimination_64x64_test.elf",
    # --- Back-substitution ---
    backsub_input_matrix_addr=0x0,
    backsub_input_vector_addr=0x800,
    backsub_output_vector_addr=0x800,
    default_backsub_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/back_substitution_64x64_test.elf",
    # --- Small matvec (O * oil_solution, 48x64) ---
    small_matvec_matrix_addr=0x0,
    small_matvec_vector_addr=0xC00,
    small_matvec_accum_addr=0,
    small_matvec_result_wdrs=("w7", "w8"),
    default_small_matvec_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/gf16mat_prod_48_64_test.elf",
    # --- Large matvec (trimat * vinegar, 2048x96) ---
    large_matvec_matrix_addr=0x800,
    large_matvec_accum_addr=0x0,
    large_matvec_n_a_byte_addr=0x30800,
    large_matvec_n_a_width_addr=0x30804,
    large_matvec_vector_addr=0x30820,
    default_large_matvec_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Is-skc/gf16_matvec_2048_96_test.elf",
    # --- Trimat eval ---
    trimat_eval_pkseed_addr=0x20,
    trimat_eval_vinegar_addr=0x40,
    trimat_eval_result_addr=0x80,
    default_trimat_eval_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Is-skc/batch_quad_trimat_eval_gf16_test.elf",
    # --- Full sign ---
    sign_skseed_addr=0xe0,
    sign_msg_len_addr=0x100,
    sign_msg_addr=0x120,
    sign_sig_addr=0x520,
    sign_y_addr=0xa00,
    sign_l_matrix_addr=0xa20,
    sign_vinegar_addr=0x1220,
    sign_target_addr=0x1280,
    sign_salt_addr=0x12a0,
    sign_s_output_addr=0x12c0,
    sign_pkseed_output_addr=0x312c0,
    sign_o_output_addr=0x312e0,
    sign_salt_input_addr=0x520,          # testvec ELF: salt_input between msg and sig (Is bngfonly/sw)
    sign_ldirect_scratch=2208,           # L-direct: exact stack peak (sw tier 8736 B) replaces the 196608 B S slot
    sign_testvec_offset=32,              # post-msg labels (incl. sig) shift +0x20 in testvec ELF
    default_sign_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Is-skc/ov-Is-sign_ldirect_bngfaes.elf",
)

OV_IP = OVParams(
    name="OV256_112_44",
    short="Ip",
    gf=256,
    pub_n=112, pub_m=44, v=68, o=44,
    pub_m_byte=44,   # PUB_M for GF256 (1 element = 1 byte)
    pub_n_byte=112,  # PUB_N for GF256
    salt_bytes=16,
    max_message_size=0x400,
    # --- Keygen ---
    # --- Sign sizes ---
    o_size=68 * 44,            # 2992 bytes (GF256: 1 byte per element)
    o_size_padded=((68 * 44 + 31) // 32) * 32,  # 3008 bytes
    # --- expandsk ---
    expandsk_skseed_addr=0x0000,
    expandsk_pkseed_addr=0x0020,
    expandsk_o_addr=0x0040,
    default_expandsk_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/expandsk_ret_O_pkseed_test.elf",
    # --- P1P1TO ---
    p1p1to_aes128_key_addr=0x20,
    p1p1to_o_matrix_addr=0x40,
    p1p1to_result_addr=0xc00,
    default_p1p1to_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Ip-skc/gf256trimat_2trimat_madd_68_68_44_44_test.elf",
    # --- Transpose ---
    transpose_input_addr=0x0,
    transpose_input_rows=64,
    transpose_input_cols=44,
    transpose_output_rows=44,
    transpose_output_cols=64,
    default_transpose_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/gf256_transpose_44_44_test.elf",
    # --- Hash ---
    hash_msg_len_addr=0x0,
    hash_msg_addr=0x20,
    default_hash_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/hash_salted_msg_test.elf",
    # --- Gaussian elimination ---
    ge_input_matrix_addr=0x0,
    ge_input_vector_addr=0x1000,
    ge_row_padding=64,
    ge_status_wdr="w20",
    default_ge_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/gaussian_elimination_44x44_test.elf",
    # --- Back-substitution ---
    backsub_input_matrix_addr=0x0,
    backsub_input_vector_addr=0x1000,
    backsub_output_vector_addr=0x1000,
    default_backsub_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/back_substitution_44x44_test.elf",
    # --- Small matvec (O * oil_solution, 68x44) ---
    small_matvec_matrix_addr=0x0,
    small_matvec_vector_addr=0xBC0,
    small_matvec_accum_addr=0xC00,
    small_matvec_result_wdrs=("w28", "w29", "w30"),
    default_small_matvec_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/gf256mat_prod_68_44_test.elf",
    # --- Large matvec (trimat * vinegar, 2816x68) ---
    large_matvec_matrix_addr=0x0,
    large_matvec_accum_addr=0x2EC00,
    large_matvec_n_a_byte_addr=0x2F760,
    large_matvec_n_a_width_addr=0x2F764,
    large_matvec_vector_addr=0x2F700,
    default_large_matvec_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/sign_sprec/ov-Ip-skc/gf256_matvec_2816_68_test.elf",
    # --- Trimat eval ---
    trimat_eval_pkseed_addr=0x0,
    trimat_eval_vinegar_addr=0x20,
    trimat_eval_result_addr=0x80,
    default_trimat_eval_elf="bazel-bin/sw/acc/crypto/handwritten/uov/shared/sign/ov-Ip-skc/batch_quad_trimat_eval_gf256_test.elf",
    # --- Full sign ---
    sign_skseed_addr=0x0a0,
    sign_msg_len_addr=0xc0,
    sign_msg_addr=0xe0,
    sign_sig_addr=0x4e0,
    sign_y_addr=0x860,
    sign_l_matrix_addr=0x8a0,
    sign_vinegar_addr=0x18a0,
    sign_target_addr=0x1920,
    sign_salt_addr=0x1960,
    sign_s_output_addr=0x1980,
    sign_pkseed_output_addr=0x30580,
    sign_o_output_addr=0x305a0,
    sign_salt_input_addr=0x4e0,          # testvec ELF: salt_input between msg and sig
    sign_ldirect_scratch=4320,           # L-direct: exact stack peak (sw tier 12544 B) replaces the 191488 B S slot
    sign_testvec_offset=32,              # post-msg labels (incl. sig) shift +0x20 in testvec ELF
    default_sign_elf="bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip-skc/ov-Ip-sign_ldirect_bngfaes.elf",
)

# ---------------------------------------------------------------------- #
# OV-Ip3 (Round 3, OV256_119_45): kernels live in sign_ldirect/ov-Ip3-skc.
# Built from scratch, NOT replace(OV_IP): a replace()-derived set inherits all
# 44-derived DMEM addresses and every R2 ELF path, so an unported test would
# run an R2 binary on R2 data and PASS. Fields whose R3 value is not yet
# established keep the dataclass default (0 / ""), which fails loudly.
# Populated so far: dimensions, O sizes, GE, back-substitution, small matvec,
# transpose, and (2026-08-18) the full-sign addresses, read off the R3 harness
# ELF rather than derived from the R2 map. NOT populated: verify/PKC/publicmap
# (the R3 verify is the stream kernel in verify_stream/ov-Ip3-pkc, which
# carries its own layout in its own driver), keygen, P1P1TO, large matvec,
# trimat eval.
# ---------------------------------------------------------------------- #
_IP3_DIR = "bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/sign_ldirect/ov-Ip3-skc"

OV_IP3 = OVParams(
    name="OV256_119_45",
    short="Ip3",
    gf=256,
    pub_n=119, pub_m=45, v=74, o=45,
    pub_m_byte=45,   # PUB_M for GF256 (1 element = 1 byte)
    pub_n_byte=119,  # PUB_N for GF256
    salt_bytes=16,
    max_message_size=0x400,
    # --- Sign sizes ---
    o_size=74 * 45,                              # 3330 bytes
    # Padded-96: one 3-WDR slot per column, low 74 B data, 22 B zero slack.
    o_slot_bytes=96,
    o_size_padded=96 * 45,                       # 4320 bytes
    # --- Gaussian elimination (45x45): mat .zero 4096 then solution ---
    ge_input_matrix_addr=0x0,
    ge_input_vector_addr=0x1000,
    ge_row_padding=64,           # 45 <= 64, rows stay 2 WDRs
    ge_status_wdr="w20",
    default_ge_elf=f"{_IP3_DIR}/gaussian_elimination_45x45_test.elf",
    # --- Back-substitution (45x45): same harness layout, output in place ---
    backsub_input_matrix_addr=0x0,
    backsub_input_vector_addr=0x1000,
    backsub_output_vector_addr=0x1000,
    default_backsub_elf=f"{_IP3_DIR}/back_substitution_45x45_test.elf",
    # --- Small matvec (O * oil_solution, 74x45) ---
    # No standalone ELF is configured. ceil(74/32) = 3 result WDRs.
    small_matvec_matrix_addr=0, small_matvec_vector_addr=0,
    small_matvec_accum_addr=0,
    small_matvec_result_wdrs=("w28", "w29", "w30"),
    default_small_matvec_elf="",
    # --- Transpose: 64x45 col-major in -> 45x64 row-major out, data 45x45 ---
    transpose_input_addr=0x0,
    transpose_input_rows=64,
    transpose_input_cols=45,
    transpose_output_rows=45,
    transpose_output_cols=64,
    default_transpose_elf=f"{_IP3_DIR}/gf256_transpose_45_45_test.elf",
    # --- Full sign: every address read off ov-Ip3-sign_ldirect_bngfaes.elf
    # (acc_objdump -t), never hand-derived from the R2 map. The testvec ELF
    # inserts salt_input before sig, shifting sig and everything after it +32.
    sign_skseed_addr=0x0a0,
    sign_msg_len_addr=0x0c0,
    sign_msg_addr=0x0e0,
    sign_sig_addr=0x4e0,
    sign_y_addr=0xa80,
    sign_l_matrix_addr=0xac0,
    sign_vinegar_addr=0x1ac0,
    sign_target_addr=0x1b40,
    sign_salt_addr=0x1b80,
    sign_s_output_addr=0x1ba0,
    sign_pkseed_output_addr=0x2c40,
    sign_o_output_addr=0x2c60,
    sign_salt_input_addr=0x4e0,          # testvec ELF only
    sign_ldirect_scratch=4256,           # S slot = pk_seed - S
    sign_testvec_offset=32,
    default_sign_elf=f"{_IP3_DIR}/ov-Ip3-sign_ldirect_bngfaes.elf",
)


"""
OV Key Generation Test Utilities

Shared functions for testing key generation sub-operations on the ACC simulator.
Supports both OV-Is (GF16) and OV-Ip (GF256).

Two computations:

1. P1*O + P2  (no symmetrization — differs from P1P1TO which uses (P1+P1^T)*O + P2)
   For row i:
       result[i, j] = sum_{k=i}^{V-1} P1[i,k] * O[k,j] + P2[i,j]   for all j
   P1 is upper triangular, so only k >= i contributes.

2. P3 = Upper(O^T * (P1*O + P2))
   The Oil-Oil block of the public key, folding the full matrix product
   into upper-triangular form.
"""

from gf_arithmetic import (
    gf16v_madd,
    gf256v_madd,
    gfv_get_ele_gf16,
)
from ov_params import OVParams


# ------------------------------------------------------------------ #
#  Reference computation: P3 = Upper(O^T * (P1*O + P2))
#
#  Moved from gf_arithmetic.py — these are keygen operations.
# ------------------------------------------------------------------ #

def compute_p3_reference(
    p1: bytes,
    p2: bytes,
    o_matrix: bytes,
    v: int,
    o: int,
    m_bytes: int,
) -> bytearray:
    """
    Compute P3 = Upper(O^T * (P1*O + P2)) for GF16.

    In characteristic 2, this is equivalent to the specification formula:
        P3_i = Upper(-O^T * P1_i * O - O^T * P2_i)
    since -1 = 1 in GF(2^k).

    Matches the C reference: calculate_P3() in ov_keypair_computation.c:
        buffer_F2 = P2
        batch_trimat_madd(buffer_F2, P1, O)  ->  buffer_F2 = P2 + P1*O
        batch_upper_matTr_x_mat(P3, O, buffer_F2) -> P3 = UT(O^T * buffer_F2)

    Args:
        p1: Upper-triangular V*V batch matrix, row-major flat.
            P1[i,k] (k >= i) at offset: (i*V - i*(i-1)//2 + (k-i)) * m_bytes
            Size: V*(V+1)/2 * m_bytes bytes
        p2: Full V*O batch matrix, row-major flat.
            P2[i,j] at offset: (i*O + j) * m_bytes
            Size: V*O * m_bytes bytes
        o_matrix: Secret O matrix, column-major packed GF16.
            Column j: bytes [j*v_byte : (j+1)*v_byte], each byte has 2 GF16 elements.
            O[row, col] = gfv_get_ele_gf16(o_matrix[col*v_byte:], row)
            Size: (V//2) * O bytes
        v: Number of vinegar variables
        o: Number of oil variables
        m_bytes: Bytes per batch entry (= m//2 for GF16)

    Returns:
        P3: Upper-triangular O*O batch matrix, row-major flat.
            Diagonal: P3[r,r] = M[r,r]
            Off-diagonal: P3[r,c] = M[r,c] + M[c,r]  (r < c)
            where M = O^T * (P1*O + P2).
            Storage order: (0,0),(0,1),...,(0,O-1),(1,1),...
            Size: O*(O+1)/2 * m_bytes bytes
    """
    v_byte = v // 2

    # Pre-extract all O matrix scalar elements for fast inner-loop access.
    o_elems = []
    for j in range(o):
        col_bytes = o_matrix[j * v_byte:(j + 1) * v_byte]
        col = [gfv_get_ele_gf16(col_bytes, k) for k in range(v)]
        o_elems.append(col)

    # Step 1: temp = P1 * O + P2  (V*O matrix of m_bytes batch entries)
    temp = []
    for i in range(v):
        row = []
        p1_row_start = i * v - i * (i - 1) // 2
        for j in range(o):
            p2_offset = (i * o + j) * m_bytes
            entry = bytearray(p2[p2_offset:p2_offset + m_bytes])
            for k in range(i, v):
                p1_flat_idx = p1_row_start + (k - i)
                p1_offset = p1_flat_idx * m_bytes
                p1_entry = p1[p1_offset:p1_offset + m_bytes]
                o_kj = o_elems[j][k]
                if o_kj != 0:
                    gf16v_madd(entry, p1_entry, o_kj)
            row.append(entry)
        temp.append(row)

    # Step 2: P3 = Upper(O^T * temp)
    p3_num_entries = (o * (o + 1)) // 2
    p3 = bytearray(p3_num_entries * m_bytes)

    p3_offset = 0
    for r in range(o):
        for c in range(r, o):
            entry = bytearray(m_bytes)
            for i in range(v):
                o_ir = o_elems[r][i]
                if o_ir != 0:
                    gf16v_madd(entry, temp[i][c], o_ir)
            if r != c:
                for i in range(v):
                    o_ic = o_elems[c][i]
                    if o_ic != 0:
                        gf16v_madd(entry, temp[i][r], o_ic)
            p3[p3_offset:p3_offset + m_bytes] = entry
            p3_offset += m_bytes

    return p3


def compute_p3_reference_gf256(
    p1: bytes,
    p2: bytes,
    o_matrix: bytes,
    v: int,
    o: int,
    m_bytes: int,
) -> bytearray:
    """
    Compute P3 = Upper(O^T * (P1*O + P2)) for GF256.

    Same algorithm as compute_p3_reference but for GF(256):
    - O matrix is column-major, 1 byte per element (not packed nibbles)
    - Uses gf256v_madd instead of gf16v_madd

    Args:
        p1: Upper-triangular V*V batch matrix, row-major flat.
            Size: V*(V+1)/2 * m_bytes bytes
        p2: Full V*O batch matrix, row-major flat.
            Size: V*O * m_bytes bytes
        o_matrix: Secret O matrix, column-major, 1 byte/element.
            Column j: bytes [j*v : (j+1)*v]
            Size: V * O bytes
        v: Number of vinegar variables
        o: Number of oil variables
        m_bytes: Bytes per batch entry (= m for GF256)

    Returns:
        P3: Upper-triangular O*O batch matrix, row-major flat.
            Size: O*(O+1)/2 * m_bytes bytes
    """
    o_elems = []
    for j in range(o):
        col_bytes = o_matrix[j * v:(j + 1) * v]
        o_elems.append(list(col_bytes))

    # Step 1: temp = P1 * O + P2
    temp = []
    for i in range(v):
        row = []
        p1_row_start = i * v - i * (i - 1) // 2
        for j in range(o):
            p2_offset = (i * o + j) * m_bytes
            entry = bytearray(p2[p2_offset:p2_offset + m_bytes])
            for k in range(i, v):
                p1_flat_idx = p1_row_start + (k - i)
                p1_offset = p1_flat_idx * m_bytes
                p1_entry = p1[p1_offset:p1_offset + m_bytes]
                o_kj = o_elems[j][k]
                if o_kj != 0:
                    gf256v_madd(entry, p1_entry, o_kj)
            row.append(entry)
        temp.append(row)

    # Step 2: P3 = Upper(O^T * temp)
    p3_num_entries = (o * (o + 1)) // 2
    p3 = bytearray(p3_num_entries * m_bytes)

    p3_offset = 0
    for r in range(o):
        for c in range(r, o):
            entry = bytearray(m_bytes)
            for i in range(v):
                o_ir = o_elems[r][i]
                if o_ir != 0:
                    gf256v_madd(entry, temp[i][c], o_ir)
            if r != c:
                for i in range(v):
                    o_ic = o_elems[c][i]
                    if o_ic != 0:
                        gf256v_madd(entry, temp[i][r], o_ic)
            p3[p3_offset:p3_offset + m_bytes] = entry
            p3_offset += m_bytes

    return p3


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point for the keygen orchestrator (run_test.py keygen calls keygen_main).
# ─────────────────────────────────────────────────────────────────────────────
import os as _os
import re as _re
import subprocess as _subprocess
import sys as _sys

def _kg_repo_root() -> str:
    # own_utils/ -> handwritten/ -> crypto/ -> acc/ -> sw/ -> <repo root>
    return _os.path.abspath(_os.path.join(_os.path.dirname(__file__), *['..'] * 5))


def _kg_objdump_syms(elf: str) -> dict:
    """Return {symbol: addr} from acc_objdump.py -t (authoritative addresses)."""
    root = _kg_repo_root()
    out = _subprocess.run(
        [_sys.executable, _os.path.join(root, "hw/ip/acc/util/acc_objdump.py"), "-t", elf],
        capture_output=True, text=True, check=True).stdout
    syms = {}
    for ln in out.splitlines():
        m = _re.match(r"^([0-9a-f]{8})\s+\S+\s+\S+\s+[0-9a-f]{8}\s+(\S+)$", ln)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    return syms


def _kg_parse_pkc_skc(path: str):
    """testvectors-*-pkc-skc: 3 lines/case (cpk, sk, sm). Returns [(cpk, sk_seed), ...]."""
    L = [x.strip() for x in open(path) if x.strip()]
    if not L or len(L) % 3:
        raise ValueError(f"{path}: {len(L)} lines, not whole cpk/sk/sm records")
    return [(bytes.fromhex(L[i]), bytes.fromhex(L[i + 1])[:32])
            for i in range(0, len(L), 3)]


def keygen_main(params: OVParams) -> int:
    """CLI entry point for the on-ACC keygen ORCHESTRATOR (the sign/verify mirror).

    Injects a KAT sk_seed, runs the single-binary ov_keygen on the ACC, extracts the
    produced cpk + csk, byte-matches the KAT, and reports cycle counts.

    Args:  params: OV parameter set (OV_IS or OV_IP)
    Returns: exit code 0 if all cases pass.
    """
    from acc_sim_utils import create_common_argparser, elf_tier, run_acc_test
    from dmem_utils import extract_bytes_from_dmem, bytes_to_dmem_words

    short = params.short
    root = _kg_repo_root()
    # --elf is required: keygen min/sp (dmem_large/keygen_min, keygen_sp) and full (dmem_large/keygen_full)
    # share this contract; the stream keygen has its own harness in dmem32k/keygen_stream/tests/.
    parser = create_common_argparser(
        f"OV_{short} keygen orchestrator (KAT-validated, all tiers)", default_iterations=1)
    parser.add_argument('--tier', choices=['bngfaes', 'bngfonly', 'bnaesonly', 'sw'],
                        help="fail unless the ELF's symbol fingerprint is this tier; it names the output and "
                             "the stats file (default: the fingerprint)")
    parser.add_argument('--cases', default='0',
                        help="comma-separated KAT case indices, or 'all' (default 0)")
    parser.add_argument('--test-data-file', default=None,
                        help='testvectors-{Is,Ip}-pkc-skc KAT file (default: canonical path)')
    args = parser.parse_args()
    elf = args.elf
    kat_file = args.test_data_file or _os.path.join(
        root, f"sw/acc/crypto/handwritten/test_data/testvectors-{short}-pkc-skc")
    if not _os.path.exists(elf):
        print(f"[ERROR] missing ELF: {elf}\n  build it with bazel first.")
        return 1
    if args.output_dir:
        _os.makedirs(args.output_dir, exist_ok=True)

    cases = _kg_parse_pkc_skc(kat_file)
    from acc_sim_utils import parse_cases
    idxs = range(len(cases)) if args.cases == 'all' else parse_cases(args.cases)
    s = _kg_objdump_syms(elf)
    tier = elf_tier(s)
    if args.tier and args.tier != tier:
        print(f"[ERROR] ELF fingerprint says {tier}, --tier {args.tier}")
        return 1

    npass = nfail = 0
    cyc0 = None
    for c in idxs:
        kat_cpk, sk_seed = cases[c]
        words = bytes_to_dmem_words(data=bytearray(sk_seed), base_addr=s["sk_seed"])
        statsf = _os.path.join(args.output_dir or "/tmp",
                               f"keygen_stats_{short}_{tier}_{c}.txt")
        with open(statsf, "w") as fh:
            ok, dmem, sim = run_acc_test(elf_path=elf, dmem_words=words,
                                         verbose=args.verbose, dump_stats_file=fh)
        if not ok or sim is None:
            print(f"[FAIL] {short}/{tier} case{c}: sim failed"); nfail += 1; continue
        cpk = bytes(extract_bytes_from_dmem(dmem, s["cpk"], len(kat_cpk)))
        csk = bytes(extract_bytes_from_dmem(dmem, s["csk"], 32))
        m = _re.search(r"executed \d+ instructions in (\d+) cycles", open(statsf).read())
        cyc = int(m.group(1)) if m else None
        if cpk != kat_cpk:
            print(f"[FAIL] {short}/{tier} case{c}: cpk != KAT"); nfail += 1; continue
        if csk != sk_seed:
            print(f"[FAIL] {short}/{tier} case{c}: csk != sk_seed"); nfail += 1; continue
        if c == 0:
            cyc0 = cyc
        print(f"[PASS] {short}/{tier} case{c}: cpk==KAT ({len(cpk):,}B) csk==sk  "
              f"cycles={cyc:,}" if cyc else f"[PASS] {short}/{tier} case{c}")
        npass += 1

    print(f"\n=== {short}/{tier}: {npass} pass, {nfail} fail ===")
    if cyc0 is not None:
        print(f"    cycles (case 0): {cyc0:,}")
    return 0 if nfail == 0 else 1

# Generates ldirect_test_inputs.s + ldirect_expected.bin for the gf256_ldirect_74_45
# kernel KAT (multi-case: zero/identity/boundary seeds, gfmul table, S-route check).
# O is emitted in the padded-96 layout: one 96-byte slot per column, low 74 B the
# column, the 22 slack bytes NONZERO -- the consumers must stay slack-agnostic, so
# a zero pad here would let an over-read multiply by zero and pass silently.
# Run: python3 gen_ldirect_test_inputs.py [--case N]
import sys, os, argparse
_D = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_D, '..', '..', '..', '..', 'own_utils'))
from ov_expandsk_test_utils import compute_expandsk_reference
from ov_pk_utils import expand_p1p2_from_pkseed
from ov_params import OV_IP3

V, M = 74, 45
O_SLOT = 96                       # padded-96: 96 B per O column
L_BUF  = 4096                     # caller's L allocation (unchanged from R2)

def _gfmul(a, b, poly=0x11B):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= poly
        b >>= 1
    return r
GFTAB = [[_gfmul(a, b) for b in range(256)] for a in range(256)]

SEED_A = bytes(range(32))
SEED_B = bytes(255 - i for i in range(32))
VIN_BASE = bytes((i*7 + 3) % 251 + 1 for i in range(V))      # nonzero pattern

def vin_with_zeros():
    v = bytearray(VIN_BASE)
    for i in (0, 5, 33, 72): v[i] = 0
    return bytes(v)

def vin_unit(i):
    v = bytearray(V); v[i] = 1
    return bytes(v)

def vin_high():
    # every byte 0x80 or 0xff (worst-case carries in gfmul reduction)
    return bytes(0x80 if i % 2 == 0 else 0xFF for i in range(V))

# case = (sk_seed, vinegar, pad_sentinel(byte applied to vinegar bytes 74..95),
#         dirty_L(prefill byte for ld_L_out or None), check_S_route)
CASES = {
    0: (SEED_A, VIN_BASE,        None, None, True ),  # baseline (original KAT)
    1: (SEED_A, vin_with_zeros(),None, None, False),  # embedded zero vinegar bytes
    2: (SEED_A, bytes(V),        None, None, False),  # all-zero vinegar -> L = 0
    3: (SEED_B, VIN_BASE,        None, None, True ),  # second seed (S-route checked)
    4: (SEED_A, vin_unit(0),     None, None, False),  # sparse unit at row 0
    5: (SEED_A, vin_unit(73),    None, None, False),  # sparse unit at last row
    6: (SEED_A, vin_unit(7),     None, None, False),  # unit at diag-boundary row
    7: (SEED_A, vin_high(),      None, None, False),  # 0x80 / 0xff stress
    8: (SEED_A, VIN_BASE,        0xA5, None, False),  # sentinels in pad bytes 74..95
    9: (SEED_A, VIN_BASE,        None, 0xAA, False),  # dirty prefilled L buffer
}

def smul(s, e):
    t = GFTAB[s]
    return bytes(t[x] for x in e)
def vxor(p, q): return bytes(a ^ b for a, b in zip(p, q))
ZERO = bytes(M)

_seed_cache = {}
def expand_seed(sk_seed):
    if sk_seed not in _seed_cache:
        pk_seed, O_packed = compute_expandsk_reference(sk_seed, OV_IP3)
        p1p2 = expand_p1p2_from_pkseed(bytearray(pk_seed), OV_IP3)
        P1_BYTES = V*(V+1)//2*M           # 124,875
        P1s, P2s = bytes(p1p2[:P1_BYTES]), bytes(p1p2[P1_BYTES:])
        assert len(P2s) == V*M*M
        ENT = {}
        i = 0
        for a in range(V):
            for b in range(a, V):
                ENT[(a, b)] = P1s[i*M:(i+1)*M]; i += 1
        _seed_cache[sk_seed] = (pk_seed, O_packed, ENT, P2s)
    return _seed_cache[sk_seed]

def compute_y(sk_seed, vin):
    """y = vin^T P1 vin = XOR_{i<=j} vin[i]*vin[j]*P1[i][j]  (M bytes).

    The kernel fuses this into its single P1 pass (off-diagonal via the
    ACC/ACCH chain, diagonal as P1[r][r]*vin[r]^2), so it is the one output of
    gf256_ldirect that no other check touches: a wrong y still produces a
    signature, just not a valid one.
    """
    _, _, ENT, _ = expand_seed(sk_seed)
    y = ZERO
    for a in range(V):
        if not vin[a]:
            continue
        for b in range(a, V):
            if vin[b]:
                y = vxor(y, smul(GFTAB[vin[a]][vin[b]], ENT[(a, b)]))
    return y


def compute_L(sk_seed, vin, check_S_route):
    pk_seed, O_packed, ENT, P2s = expand_seed(sk_seed)
    def P2e(r, c): off = (r*M + c)*M; return P2s[off:off+M]
    def O_at(k, c): return O_packed[c*V + k]

    # Route H: t = (P1+P1^T) vin, then L = t^T O + vin^T P2
    t = [ZERO]*V
    for a in range(V):
        if not any(vin[a:]): break
        for b in range(a+1, V):
            e = ENT[(a, b)]
            if vin[a]: t[b] = vxor(t[b], smul(vin[a], e))
            if vin[b]: t[a] = vxor(t[a], smul(vin[b], e))
    L_h = [ZERO]*M
    for c in range(M):
        for k in range(V):
            s = O_at(k, c)
            if s and t[k] != ZERO: L_h[c] = vxor(L_h[c], smul(s, t[k]))
    for r in range(V):
        if vin[r]:
            for c in range(M):
                L_h[c] = vxor(L_h[c], smul(vin[r], P2e(r, c)))

    if check_S_route:
        # Route 1 (reference): S = (P1+P1^T)O + P2, then L[c] = sum_r vin[r]*S[r][c]
        S = [[ZERO]*M for _ in range(V)]
        for r in range(V):
            for k in range(V):
                if r == k: continue
                e = ENT[(min(r, k), max(r, k))]
                for c in range(M):
                    s = O_at(k, c)
                    if s: S[r][c] = vxor(S[r][c], smul(s, e))
            for c in range(M):
                S[r][c] = vxor(S[r][c], P2e(r, c))
        L_ref = [ZERO]*M
        for r in range(V):
            if vin[r]:
                for c in range(M):
                    L_ref[c] = vxor(L_ref[c], smul(vin[r], S[r][c]))
        assert L_ref == L_h, "route mismatch!"
        print("python routes agree")
    return pk_seed, L_h

def words(b):
    return ['0x' + b[i:i+4][::-1].hex() for i in range(0, len(b), 4)]

def pad_O_96(o_packed):
    """Column-major packed O (V B/col) -> one O_SLOT-byte slot per column.

    Slack bytes are NONZERO and column-dependent: the producer (expandsk) zeroes
    them, but every consumer must be slack-agnostic, so the rig feeds garbage.
    """
    assert len(o_packed) == V * M
    buf = bytearray((0xC3 + 7 * i) & 0xFF or 0x5A for i in range(O_SLOT * M))
    for c in range(M):
        buf[O_SLOT * c: O_SLOT * c + V] = o_packed[V * c: V * c + V]
    return bytes(buf)


def emit(label, data, pad_to=None, pad_byte=0):
    if pad_to: data = data + bytes([pad_byte])*(pad_to - len(data))
    lines = ['.balign 32', f'.global {label}', f'{label}:']
    w = words(data)
    for i in range(0, len(w), 8):
        lines.append('    .word ' + ', '.join(w[i:i+8]))
    return '\n'.join(lines)

def main():
    ap = argparse.ArgumentParser(
        description='Writes ldirect_test_inputs.s and the expected L and y (ldirect_expected*.bin) of one '
                    'gf256_ldirect_74_45 KAT case, beside this script.')
    ap.add_argument('--case', type=int, default=0, choices=sorted(CASES))
    args = ap.parse_args()
    sk_seed, vin, pad_sent, dirty_L, check_S = CASES[args.case]
    pk_seed, L = compute_L(sk_seed, vin, check_S)

    # expected L in padded 64B layout (45 data + 19 zero); kernel zeroes padding
    exp = b''.join(e + bytes(64 - M) for e in L)
    open(os.path.join(_D, 'ldirect_expected.bin'), 'wb').write(exp)
    y = compute_y(sk_seed, vin)
    open(os.path.join(_D, 'ldirect_expected_y.bin'), 'wb').write(y + bytes(64 - len(y)))

    if dirty_L is not None:
        l_out = [emit('ld_L_out', bytes([dirty_L])*L_BUF)]
    else:
        l_out = ['.balign 32', '.global ld_L_out', 'ld_L_out:', f'    .zero {L_BUF}']

    src = [f'/* generated test inputs for gf256_ldirect_74_45 KAT, case {args.case}, 2026-08-18 */',
           '.section .data',
           emit('ld_pk_seed', pk_seed, 32),
           emit('ld_vinegar', vin, 96, pad_byte=(pad_sent or 0)),
           emit('ld_O', pad_O_96(expand_seed(sk_seed)[1])),
           *l_out,
           '.balign 32', '.global ld_y_out', 'ld_y_out:',
           '    .zero 64                       /* fused ldirect y = vin^T P1 vin (64B) */',
           '.balign 32', 'ld_stack:', '    .zero 8192',
           '.global ld_stack_end', 'ld_stack_end:', '    .zero 32', '']
    open(os.path.join(_D, 'ldirect_test_inputs.s'),
         'w').write('\n'.join(src))
    print(f"case {args.case}: inputs + expected written")

if __name__ == '__main__':
    main()

#!/bin/bash
# Build the three checkers: Ip3 and Is from the pqov reference code, Round-2 Ip from the pqm4 reference.
# No reference source is changed; refcheck.c supplies randombytes() and wraps the signer's Gaussian elimination
# (GNU ld --wrap). Stops unless both reference trees are clean checkouts of the named commits.
# Usage: build.sh PQOV_DIR MUPQ_DIR OUT_DIR
#   PQOV_DIR  clone of https://github.com/pqov/pqov at fac2ec1fe6
#   MUPQ_DIR  the mupq submodule of https://github.com/mupq/pqm4 (pqm4 cc2c1b9, mupq ddccced, its pqclean included)
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 PQOV_DIR MUPQ_DIR OUT_DIR"; exit 2; }
Q=$(cd "$1" && pwd)
P=$(cd "$2" && pwd)
mkdir -p "$3"
B=$(cd "$3" && pwd)
D=$(cd "$(dirname "$0")" && pwd)
R=$P/crypto_sign/ov-Ip-pkc-skc/ref
rm -f "$B/refcheck-Ip" "$B/refcheck-Ip3" "$B/refcheck-Is"
[ "$(git -C "$Q" rev-parse HEAD)" = fac2ec1fe6d8ea508eab4b98eb5341e1eed930a4 ] || { echo "pqov is not at fac2ec1fe6"; exit 1; }
[ "$(git -C "$P" rev-parse HEAD)" = ddcccedb2db9d0250856bd58ee5c46c61e506c5d ] || { echo "mupq is not at ddccced"; exit 1; }
for t in "$Q" "$P"; do
  [ -z "$(git -C "$t" status --porcelain --untracked-files=all --ignore-submodules=none)" ] \
    || { echo "$t has local changes"; exit 1; }
done
mapfile -t SRCS < <(ls "$Q"/src/ref/*.c "$Q"/src/*.c "$Q"/utils/*.c | grep -v utils_randombytes.c)
INC=(-I"$Q/src" -I"$Q/src/ref" -I"$Q/utils")
G=pqov_uov_Ip_pkc_skc_ref_gf256mat_gaussian_elim
gcc -O2 -std=gnu99 -DGE=$G -Wl,--wrap=$G -D_OV256_119_45 -D_OV_PKC_SKC "${INC[@]}" "${SRCS[@]}" "$D/refcheck.c" \
  -lcrypto -o "$B/refcheck-Ip3"
G=pqov_uov_Is_pkc_skc_ref_gf16mat_gaussian_elim
gcc -O2 -std=gnu99 -DGE=$G -Wl,--wrap=$G -D_OV16_160_64 -D_OV_PKC_SKC "${INC[@]}" "${SRCS[@]}" "$D/refcheck.c" \
  -lcrypto -o "$B/refcheck-Is"
G=gf256mat_gaussian_elim
gcc -O2 -std=gnu99 -DGE=$G -Wl,--wrap=$G -DPQM4 -I"$R" -I"$P/common" -I"$P/pqclean/common" "$R"/*.c \
  "$P/common/fips202.c" "$P/common/keccakf1600.c" "$P/pqclean/common/aes.c" "$D/refcheck.c" -o "$B/refcheck-Ip"
sha256sum "$B/refcheck-Ip" "$B/refcheck-Ip3" "$B/refcheck-Is"

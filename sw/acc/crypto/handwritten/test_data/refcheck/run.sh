#!/bin/bash
# Re-sign the -pkc-skc vector files of test_data with the checkers that
# build.sh made. Every file is checked against its full list of expected attempts, so a missing or extra case fails:
# ladders and .nistkat 1 each (Is ladder case 11: 2), retry files 1, 2, 3, retry grids as the index lists them.
# Usage: run.sh BUILD_DIR   (exit 0 only if every file passes)
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: $0 BUILD_DIR"; exit 2; }
B=$(cd "$1" && pwd)
T=$(cd "$(dirname "$0")/.." && pwd)
rc=0
one() {  # set, file, attempts
  local out
  out=$("$B/refcheck-$1" "$T/$2" "$3") || rc=1
  echo "$1 $2: $(tail -1 <<< "$out")"
}
ones() {  # n ones, comma-separated
  printf '1%.0s,' $(seq "$1") | sed 's/,$//'
}
grid() {  # attempts of one set from the index, by case number; fails unless cases 0..35 are all there once
  awk -F, -v p="$1" '
    NR == 1 { if ($0 != "param,case,key_file,key_case,msg_len,attempts") { bad = 1; exit } next }
    $1 == p { if ($2 !~ /^[0-9]+$/ || $6 !~ /^[1-9][0-9]*$/ || ($2 in a)) { bad = 1; exit } a[$2] = $6; n++ }
    END {
      if (bad || n != 36) exit 1
      for (i = 0; i < 36; i++) { if (!(i in a)) exit 1; printf "%s%s", (i ? "," : ""), a[i] }
    }' "$T/testvectors-retrygrid-index.csv"
}
for p in Ip Ip3; do
  one $p testvectors-$p-pkc-skc "$(ones 12)"
  one $p testvectors-$p-pkc-skc.nistkat "$(ones 12)"
  one $p testvectors-$p-pkc-skc.retryctrl 1
  one $p testvectors-$p-pkc-skc.retry2 2
  one $p testvectors-$p-pkc-skc.retry3 3
done
one Is testvectors-Is-pkc-skc "$(ones 11),2"
for p in Ip Ip3 Is; do
  if att=$(grid $p); then
    one $p testvectors-$p-pkc-skc.retrygrid "$att"
  else
    echo "$p testvectors-retrygrid-index.csv: not 36 valid cases"
    rc=1
  fi
done
exit $rc

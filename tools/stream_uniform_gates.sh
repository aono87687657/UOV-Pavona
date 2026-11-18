#!/usr/bin/env bash
# stream_uniform_gates.sh — reproducible fairness gates for a stream-uniform
# (backend-ablation) family. The ablation claim ("arm ratios isolate the
# backend") is only trustworthy if the OUTER object is provably identical
# across arms and each arm's opcode set matches its tier. This script builds
# every arm FIRST (stale-object safety) then checks:
#   0. each arm's ELF and outer object are read once: every instruction word
#      decodes with the instruction DB (tools/acc_disasm.py), objdump lists the
#      outer's relocations and the ELF's symbols. The gates below read only these
#      texts, so a read that fails stops the run.
#   1. outer loaded sections identical across arms: each section's name, type,
#      flags, address, size, alignment and bytes
#   2. outer RELOCATION tables identical across arms, for every loaded section  <- a
#      JAL can retarget a different symbol with identical placeholder bytes, so (1)
#      alone is insufficient; (2) pins the call graph.
#   3. shared host-visible symbol addresses identical across arms
#   4. exactly one provider for each backend_* symbol per arm
#   5. opcode policy per arm (outer: none; sw: bn.mulv only — the repo sw-tier
#      x0x1b-reduce baseline; bngfonly: gfmul only; bngfaes: gfmul+aes128;
#      bnaesonly: aes128 + software GF, zero gfmul); the mnemonic prefix covers
#      every suffix. Every 32 KiB family has all four arms.
#   6. check_loop clean
# NOT covered here (needs a running sim): the dynamic event manifest and the
# per-phase acc/target checkpoints — those live in the per-op test drivers.
#
#   tools/stream_uniform_gates.sh keygen           # 4 arms, Ip
#   tools/stream_uniform_gates.sh verify Is        # 4 arms, Is
#   tools/stream_uniform_gates.sh sign Ip          # sign: outer = the (now cpp-free)
#                                               # orchestrator lib object; the 4
#                                               # helper seams are the backend ABI
set -uo pipefail
OP="${1:-keygen}"
PARAM="${2:-Ip}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OBJDUMP="$REPO/hw/ip/acc/util/acc_objdump.py"   # relocations and symbol tables
DISASM="$REPO/tools/acc_disasm.py"              # instructions
BAZEL="$REPO/bazelisk.sh"
PY() { python3 "$@"; }

# default path shapes (keygen/verify); sign overrides below
outer_obj() { echo "$BASE/${STEM}_$1.o"; }
elf_path()  { echo "$BASE/${STEM}_$1.elf"; }
BUILD_TARGETS=""   # empty -> //...$PKG:all

case "$PARAM" in Ip|Is|Ip3) ;; *) echo "usage: $0 keygen|verify|sign [Ip|Is|Ip3]"; exit 2 ;; esac
case "$OP" in
  keygen) PKG="keygen_stream_uniform/ov-$PARAM-pkc+skc"; STEM="ov-$PARAM-keygen_stream_uniform"
          if [ "$PARAM" = "Is" ]; then
            # Is ABI: row-wide backend (pair loop incl. inline P2 AES) + group fold
            SYMS="backend_init_once backend_window_init backend_row backend_fold_group"
            SHARED='^(ctrl|sk_seed|pk_seed|slice|slice_end|o_ctx|p1buf|gbuf01|gbuf23|frame|winend)$'
          else
            SYMS="backend_init_once backend_window_init backend_aes_ctr_batch backend_gf256_reduce_entries backend_gf256_fold4_entries"
            SHARED='^(ctrl|sk_seed|pk_seed|slice|slice_end|o_aligned|p1buf|group_buf|frame|p2buf)$'
          fi
          if [ "$PARAM" = "Ip3" ]; then
            # R3 rig (2026-08-26): 4 arms, canonical (ctr,phase) AES seam, true
            # 2-row tail fold as a sixth seam symbol.
            SYMS="$SYMS backend_gf256_fold2_entries"
          fi ;;
  verify) PKG="verify_stream_uniform/ov-$PARAM-pkc"; STEM="ov-$PARAM-verify_stream_uniform"
          SYMS="backend_verify_p1p2 backend_verify_p3_rows"
          SHARED='^(ctrl|initdone|acc|oil|target|sig|seed|msgwin|winend)$'
          if [ "$PARAM" = "Ip3" ]; then
            # R3 rig; caprows is a new outer .data table (per-row_start window
            # bounds) - pinning its address across arms is exactly gate 3's job.
            SHARED='^(ctrl|initdone|acc|oil|target|sig|seed|msgwin|winend|caprows)$'
          fi ;;
  sign)   STEM="ov-$PARAM-skc-sign"
          # seams = the per-tier helper entry points (fused ldirect made the
          # orchestrator tier-neutral for both params; the split falls on
          # existing symbols). Is spells gaussian_elemination as in its source.
          if [ "$PARAM" = "Is" ]; then
            SYMS="gf16_ldirect_96_64 gaussian_elemination_64x64 back_substitution gf16_matvec_48_64"
          else
            SYMS="gf256_ldirect_68_44 gaussian_elimination_44x44 back_substitution gf256mat_prod_68_44"
          fi
          SHARED=''   # host I/O is register-passed + harness-owned: gate 3 N/A
          PKG="sign_ldirect/ov-$PARAM-skc"; LIBS="${STEM}_bngfaes_testvec ${STEM}_bngfonly_testvec ${STEM}_sw_testvec"
          outer_obj() { local a="$1"; [ "$a" = "bnaesonly" ] && a="sw"; echo "$BASE/${STEM}_${a}_testvec.o"; }
          elf_path()  { echo "$BASE/ov-$PARAM-sign_ldirect_testvec_$1.elf"; }
          if [ "$PARAM" = "Ip3" ]; then
            # R3: 4 arms. The bngfaes testvec lib is UNSUFFIXED, and bnaesonly links the SAME sw
            # testvec object (the AES leaf swap lives in the dep list, not the orchestrator).
            LIBS="${STEM}_testvec ${STEM}_bngfonly_testvec ${STEM}_sw_testvec"
            SYMS="gf256_ldirect_74_45 gaussian_elimination_45x45 back_substitution gf256mat_prod_74_45"
            outer_obj() { case "$1" in bngfaes) echo "$BASE/${STEM}_testvec.o" ;;
                                       bnaesonly) echo "$BASE/${STEM}_sw_testvec.o" ;;
                                       *) echo "$BASE/${STEM}_$1_testvec.o" ;; esac; }
          fi
          for t in $LIBS ov-$PARAM-sign_ldirect_testvec_{bngfaes,bngfonly,sw,bnaesonly}; do
            BUILD_TARGETS="$BUILD_TARGETS //sw/acc/crypto/handwritten/uov/dmem32k/$PKG:$t"
          done ;;
  *) echo "usage: $0 keygen|verify|sign [Ip|Is|Ip3]"; exit 2 ;;
esac
BASE="$REPO/bazel-bin/sw/acc/crypto/handwritten/uov/dmem32k/$PKG"

echo "== build all $OP stream_uniform arms first (stale-object safety)"
if [ -n "$BUILD_TARGETS" ]; then
  "$BAZEL" build $BUILD_TARGETS >/dev/null 2>&1 || { echo "BUILD FAIL"; exit 1; }
else
  "$BAZEL" build "//sw/acc/crypto/handwritten/uov/dmem32k/$PKG:all" >/dev/null 2>&1 || { echo "BUILD FAIL"; exit 1; }
fi
ARMS=(); for a in bngfaes bngfonly bnaesonly sw; do [ -f "$(outer_obj $a)" ] && ARMS+=("$a"); done
echo "   arms present: ${ARMS[*]}"
tmp=$(mktemp -d) || { echo "no temporary directory"; exit 1; }
trap 'rm -rf "$tmp"' EXIT; fail=0
WANT=4
[ "${#ARMS[@]}" -eq "$WANT" ] || { echo "   FAIL: family needs all $WANT arms (found ${#ARMS[@]}) - partial runs cannot PASS"; fail=1; }

# A step of this script itself (awk, sort, sha256sum ...) that exits nonzero fails the gates, whatever it printed:
# every value below is assigned with its status checked.
broke() { echo "   FAIL: $1 could not be computed (a step of this script failed)"; fail=1; }
# the relocation rows ($1: objdump -r text) of the loaded sections ($2: decoded text), each block under its section line
reloc_text() { awk 'NR == FNR { if ($1 == "section") { n = $2; sub(/:$/, "", n); loaded[n] = 1 } next }
                    /^RELOCATION RECORDS FOR \[/ { n = $0; sub(/^RELOCATION RECORDS FOR \[/, "", n); sub(/\]:.*$/, "", n)
                                                   f = (n in loaded); if (f) print; next }
                    f && /R_RISCV/' "$2" "$1"; }
# the bytes of a decoded file, without symbol names and rendering: section lines, address and word or hex
bytes_text() { awk -F'\t' '/^section / {print} NF > 1 {print $1 "\t" $2}' "$1"; }
# of a decoded file: the instruction lines, and how many of them are bn.gfmul*, bn.aes128*, bn.mulv*
counts() { awk -F'\t' 'NF == 3 { n++; if (index($3, "bn.gfmul") == 1) g++; else if (index($3, "bn.aes128") == 1) x++
                                 else if (index($3, "bn.mulv") == 1) m++ }
                       END { print n+0, g+0, x+0, m+0 }' "$1"; }

echo "== gate 0: every arm's ELF and outer object are read: instructions decode, tables list"
# Read once per arm into $tmp/<arm>.{elf.dis,o.dis,o.rel,elf.sym}: the instructions
# from the file's own bytes with the instruction DB, the outer's relocations and
# the ELF's symbols from objdump. A word without a decoding or a tool that exits
# nonzero leaves text the gates below must not read: stop.
unread=0
for a in "${ARMS[@]}"; do
  if PY "$DISASM" --elf "$(elf_path $a)" > "$tmp/$a.elf.dis" 2> "$tmp/$a.err" &&
     PY "$DISASM" --elf "$(outer_obj $a)" > "$tmp/$a.o.dis" 2>> "$tmp/$a.err" &&
     PY "$OBJDUMP" -r "$(outer_obj $a)" > "$tmp/$a.o.rel" 2>> "$tmp/$a.err" &&
     PY "$OBJDUMP" -t "$(elf_path $a)" > "$tmp/$a.elf.sym" 2>> "$tmp/$a.err"; then
    ce=$(counts "$tmp/$a.elf.dis") && co=$(counts "$tmp/$a.o.dis") || broke "the instruction count of $a"
    echo "   PASS $a (${ce%% *} ELF + ${co%% *} outer instructions)"
  else
    echo "   FAIL $a: $(tail -n 1 "$tmp/$a.err")"; unread=1
  fi
done
[ "$unread" -eq 0 ] || { echo; echo "GATES FAILED ($OP): not every arm could be read"; exit 1; }

echo "== gate 1+2: outer loaded sections AND their relocation tables identical across arms"
if [ "${#ARMS[@]}" -ge 2 ]; then
  # one hash of each kind per arm ("B"ytes, "R"elocations): an arm whose text cannot be extracted or hashed
  # counts as a failure, it does not drop out of the comparison
  : > "$tmp/h"
  for a in "${ARMS[@]}"; do
    { b=$(bytes_text "$tmp/$a.o.dis") && [ -n "$b" ] && bh=$(sha256sum <<< "$b") && echo "B ${bh%% *} $a" >> "$tmp/h"; } ||
      { echo "   FAIL $a: the outer's sections could not be hashed"; fail=1; }
    { r=$(reloc_text "$tmp/$a.o.rel" "$tmp/$a.o.dis") && rh=$(sha256sum <<< "$r") && echo "R ${rh%% *} $a" >> "$tmp/h"; } ||
      { echo "   FAIL $a: the outer's relocations could not be hashed"; fail=1; }
    # section lines alone are no relocation table: identical empty tables must not PASS
    grep -q R_RISCV <<< "$r" || { echo "   FAIL $a: no relocation row for a loaded section"; fail=1; }
  done
  nb=$(awk '$1 == "B" {n++} END {print n+0}' "$tmp/h") && n1=$(awk '$1 == "B" {print $2}' "$tmp/h" | LC_ALL=C sort -u | wc -l) ||
    broke "the comparison of the outer's sections"
  nr=$(awk '$1 == "R" {n++} END {print n+0}' "$tmp/h") && n2=$(awk '$1 == "R" {print $2}' "$tmp/h" | LC_ALL=C sort -u | wc -l) ||
    broke "the comparison of the outer's relocations"
  { [ "$nb" -eq "${#ARMS[@]}" ] && [ "$n1" -eq 1 ] && echo "   PASS text+data identical"; } ||
    { echo "   FAIL text+data ($n1 hashes from $nb of ${#ARMS[@]} arms)"; fail=1; }
  { [ "$nr" -eq "${#ARMS[@]}" ] && [ "$n2" -eq 1 ] && echo "   PASS relocations identical"; } ||
    { echo "   FAIL relocations ($n2 hashes from $nr of ${#ARMS[@]} arms)"; fail=1; }
else echo "   SKIP (only ${#ARMS[@]} arm — no cross-arm comparison yet)"; fi

echo "== gate 3: shared host-visible symbol addresses identical across arms"
if [ -z "$SHARED" ]; then echo "   N/A ($OP: host I/O is register-passed; no DMEM address ABI)";
elif [ "${#ARMS[@]}" -ge 2 ]; then
  for a in "${ARMS[@]}"; do
    awk -v re="$SHARED" '$NF ~ re {print $NF,$1}' "$tmp/$a.elf.sym" | LC_ALL=C sort > "$tmp/$a.addr" || broke "the shared symbols of $a"
  done
  # empty lists compare equal - require the shared-symbol manifest is populated
  [ -s "$tmp/${ARMS[0]}.addr" ] || { echo "   FAIL shared-symbol list empty (manifest regex matched nothing)"; fail=1; }
  same=1; for a in "${ARMS[@]:1}"; do cmp -s "$tmp/${ARMS[0]}.addr" "$tmp/$a.addr" || same=0; done
  { [ "$same" -eq 1 ] && echo "   PASS addresses identical"; } || { echo "   FAIL addresses differ"; fail=1; }
else echo "   SKIP"; fi

echo "== gate 4: exactly one provider per backend_* symbol"
for a in "${ARMS[@]}"; do
  for s in $SYMS; do
    c=$(awk -v s="$s" '$NF==s{n++} END{print n+0}' "$tmp/$a.elf.sym") || broke "the providers of $s in $a"
    [ "$c" -eq 1 ] || { echo "   FAIL $a $s = $c providers"; fail=1; }
  done
done
[ "$fail" -eq 0 ] && echo "   PASS single-provider all arms"

echo "== gate 5: opcode policy (the mnemonic prefix covers every suffix)"
for a in "${ARMS[@]}"; do
  c=$(counts "$tmp/$a.o.dis") || broke "the opcode counts of outer($a)"; read -r _ g x m <<< "$c"
  { [ "$g$x$m" = "000" ] && echo "   PASS outer($a) clean"; } || { echo "   FAIL outer($a) gfmul=$g aes=$x mulv=$m"; fail=1; }
  c=$(counts "$tmp/$a.elf.dis") || broke "the opcode counts of $a"; read -r _ g x m <<< "$c"
  # sw-arm bn.mulv is REPORTED, not banned: the repo's sw tier baseline uses
  # bn.mulv.l for the GF256 x0x1b reduce (gf256_sw_helpers, gf256_mul_pqc_
  # w16safe) - same definition as the tuned sw kernels the ratios are read
  # against. The ablation axes are gfmul/aes128 only; hw arms must not smuggle
  # mulv (they have gfmul).
  case "$a" in
    bngfaes)  ok=$([ "$g" -gt 0 ] && [ "$x" -gt 0 ] && [ "$m" -eq 0 ] && echo 1 || echo 0) ;;
    bngfonly) ok=$([ "$g" -gt 0 ] && [ "$x" -eq 0 ] && [ "$m" -eq 0 ] && echo 1 || echo 0) ;;
    # Software GF256 uses mulv; software GF16 does not.
    bnaesonly) ok=$([ "$g" -eq 0 ] && [ "$x" -gt 0 ] &&
                   { { [ "$PARAM" = Is ] && [ "$m" -eq 0 ]; } ||
                     { [ "$PARAM" != Is ] && [ "$m" -gt 0 ]; }; } && echo 1 || echo 0) ;;
    sw)       ok=$([ "$g" -eq 0 ] && [ "$x" -eq 0 ] && echo 1 || echo 0) ;;
  esac
  { [ "$ok" -eq 1 ] && echo "   PASS $a ELF gfmul=$g aes=$x mulv=$m"; } || { echo "   FAIL $a ELF gfmul=$g aes=$x mulv=$m"; fail=1; }
done

echo "== gate 6: check_loop"
for a in "${ARMS[@]}"; do
  PY "$REPO/hw/ip/acc/util/check_loop.py" "$(elf_path $a)" >/dev/null 2>&1 && echo "   PASS $a" || { echo "   FAIL $a"; fail=1; }
done

echo; [ "$fail" -eq 0 ] && echo "ALL GATES PASS ($OP)" || echo "GATES FAILED ($OP)"
exit $fail

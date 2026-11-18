#!/usr/bin/env bash
# RTL campaign for the UOV chip tests on the Verilator chip model, one DMEM profile per run.
#
#   tools/rtl_campaign.sh --profile 32|128 [--cells "a b"] [--jobs N] [--threads T]
#                         [--output-base DIR] [--hold-file PATH] [--dry-run] [--collect-only DIR]
#   tools/rtl_campaign.sh --verify-only DIR
#
#   --profile       32: the 32 KiB matrix, 60 measured cells ("meters v2" lines, gated against
#                   sw/device/tests/acc_uov/expected_insn_counts_32k.csv);
#                   128: the 36 one-shot cells of its list (keygen _sp/_min, verify); the tree must be
#                   at that profile (in a clone of its own: python3 tools/uov.py profile --profile N)
#   --cells         space-separated target basenames (acc_uov_..._test); default: every cell
#   --jobs          simulations at once (default 1 at 32 KiB, 2 at 128 KiB)
#   --threads       Verilator threads per simulation (default 4)
#   --output-base   a separate bazel output base for this lane
#   --hold-file     created at launch and removed when the run is archived (admission control)
#   --dry-run       preflight, build and manifest only, no test runs
#   --collect-only  re-read a finished run directory: refused unless its DONE is clean and
#                   evidence.sha256 still names exactly its archived files, unchanged
#   --verify-only   those two checks on a finished run directory (absolute path, or relative to
#                   the repo root) and nothing else: exit 0 or 3, nothing is written
#
# 1. preflight: a snapshot of the tree (HEAD, tracked changes, untracked files, local rc file);
#    the profile; every firmware embeds exactly its ACC apps byte for byte and prints exactly its
#    own meters identity (gather_chip_matrix.py firmware); every generated header equals its generator's output
#    for every consumer ELF; the snapshot again after the build.
# 2. manifest.txt: every hash (snapshot, sources, firmware, ACC ELFs, every runfile the simulation
#    loads); content-addressed copies of all of those binaries in bin/.
# 3. detached: tools/gather_chip_matrix.py --run into results/ (bound to this invocation's bazel
#    event log), then the postcheck (snapshot, every live hash, every archived copy), then
#    evidence.sha256 over the archived evidence and DONE with the exits.
# The run passed when DONE reads collector_exit=0 postcheck_exit=0 archive_exit=0.
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"   # also from the frozen copy in a run dir
REPO=$PWD
PROFILE=""; CELLS=""; JOBS=""; THREADS=4; OB=""; HOLD=""; DRY=0; COLLECT=""; VERIFY=""; POSTCHECK=""; ARCHIVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2;;
    --cells) CELLS="$2"; shift 2;;
    --jobs) JOBS="$2"; shift 2;;
    --threads) THREADS="$2"; shift 2;;
    --output-base) OB="$2"; shift 2;;
    --hold-file) HOLD="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    --collect-only) COLLECT="$2"; shift 2;;
    --verify-only) VERIFY="$2"; shift 2;;
    --postcheck) POSTCHECK="$2"; shift 2;;          # internal: run by the detached job at the end
    --archive) ARCHIVE="$2"; shift 2;;              # internal: the detached job's evidence inventory
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument $1 (--help lists them)" >&2; exit 2;;
  esac
done

# HEAD, every tracked change, every untracked file and the local rc file, as one hash; prints
# nothing and fails if any part cannot be read (an absent rc file or no untracked file is fine)
snapshot() {
  local f h="" rc=0
  f=$(mktemp) || return 1
  { git rev-parse HEAD && git diff HEAD --binary \
      && git ls-files --others --exclude-standard | awk '!/__pycache__\//' | LC_ALL=C sort | xargs -r -d '\n' sha256sum \
      && if [ -e .bazelrc-site ]; then sha256sum .bazelrc-site; fi; } > "$f" || rc=1
  if [ $rc = 0 ]; then h=$(sha256sum < "$f") || rc=1; fi
  rm -f "$f"
  [ $rc = 0 ] && [ ${#h} -ge 64 ] || return 1
  echo "${h:0:64}"
}

# the archived evidence of a run directory: every file but the ones collection rewrites (contract2.csv, oneshot.csv:
# their names in runs before the rename)
evidence_files() {
  (cd "$1" && find . -type f ! -name DONE ! -name evidence.sha256 ! -name 'evidence.sha256.*' ! -name campaign.log \
     ! -path ./results/results_32k.csv ! -path ./results/results_128k.csv \
     ! -path ./results/contract2.csv ! -path ./results/oneshot.csv ! -path ./results/status.json | LC_ALL=C sort)
}

# write evidence.sha256 for a run directory; it only appears when every file was hashed
archive() {
  local tmp="$1/evidence.sha256.partial"
  evidence_files "$1" > "$tmp.list" && (cd "$1" && xargs -r -d '\n' sha256sum < evidence.sha256.partial.list) > "$tmp" \
    && [ "$(wc -l < "$tmp")" = "$(wc -l < "$tmp.list")" ] && rm -f "$tmp.list" && mv "$tmp" "$1/evidence.sha256"
}

# the inventory names exactly the archived files and every hash still matches
evidence_ok() {
  [ -f "$1/evidence.sha256" ] && diff -q <(evidence_files "$1") <(sed 's/^[0-9a-f]\{64\}  //' "$1/evidence.sha256") >/dev/null \
    && (cd "$1" && sha256sum --quiet --strict -c evidence.sha256)
}

# DONE of a run that collected, postchecked and archived cleanly: that one complete line and nothing else
done_ok() {
  [ "$(wc -l 2>/dev/null < "$1/DONE")" = 1 ] && [ "$(grep -c '' "$1/DONE")" = 1 ] \
    && grep -qx 'collector_exit=0 postcheck_exit=0 archive_exit=0 finished=[0-9TZ]*' "$1/DONE"
}

if [ -n "$ARCHIVE" ]; then archive "$ARCHIVE"; exit $?; fi

if [ -n "$VERIFY" ]; then
  done_ok "$VERIFY" || { echo "$VERIFY: DONE is not the one line collector_exit=0 postcheck_exit=0 archive_exit=0" >&2; exit 3; }
  evidence_ok "$VERIFY" || { echo "$VERIFY: archived evidence differs from evidence.sha256" >&2; exit 3; }
  exit 0
fi

# the recorded state again: the snapshot, every live file the run used, every archived copy
if [ -n "$POSTCHECK" ]; then
  bad=0
  [ "$(snapshot)" = "$(awk '$1 == "snapshot" {print $2}' "$POSTCHECK/manifest.txt")" ] || { echo "postcheck: the tree changed (snapshot)"; bad=1; }
  while read -r path sum; do
    [ -f "$path" ] && [ "$(sha256sum "$path" | cut -c1-64)" = "$sum" ] || { echo "postcheck: $path changed or missing"; bad=1; }
    case "$path" in /*) [ "$(sha256sum "$POSTCHECK/bin/$sum" 2>/dev/null | cut -c1-64)" = "$sum" ] \
      || { echo "postcheck: archived copy bin/$sum of $path changed or missing"; bad=1; };; esac
  done < <(awk '$1 ~ /^(firmware|elf|runfile|fixture|source)$/ && $3 == "sha256" {print $2, $4}' "$POSTCHECK/manifest.txt" | LC_ALL=C sort -u)
  [ $bad = 0 ] && echo "postcheck: snapshot, every recorded hash and every archived copy unchanged"
  exit $bad
fi

case "$PROFILE" in
  32) MODE=--dmem32k; JOBS=${JOBS:-1}; BASELINE=sw/device/tests/acc_uov/expected_insn_counts_32k.csv;;
  128) MODE=--dmem128k; JOBS=${JOBS:-2}; BASELINE="";;
  *) echo "--profile 32 or --profile 128 (--help lists the options)" >&2; exit 2;;
esac

if [ -n "$COLLECT" ]; then
  # only a run that collected, postchecked and archived cleanly, with every archived file intact
  done_ok "$COLLECT" || { echo "$COLLECT: DONE does not read collector_exit=0 postcheck_exit=0 archive_exit=0; not re-read" >&2; exit 3; }
  evidence_ok "$COLLECT" || { echo "$COLLECT: archived evidence differs from evidence.sha256; not re-read" >&2; exit 3; }
  exec python3 tools/gather_chip_matrix.py $MODE --strict --collect "$COLLECT/results"
fi

ALL=$(python3 -c "import sys; sys.path.insert(0, 'tools'); import gather_chip_matrix as g
print(' '.join(g.target(*c)[:-len('_sim_verilator')] for c in (g.CELLS if $PROFILE == 32 else g.ONESHOT_CELLS)))")
CELLS=${CELLS:-$ALL}
for c in $CELLS; do case " $ALL " in *" $c "*) ;; *) echo "not a $PROFILE KiB cell: $c" >&2; exit 2;; esac; done
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=chip-matrix/rtl-${PROFILE}k-$STAMP
[ ! -e "$OUT" ] || { echo "$OUT exists" >&2; exit 2; }
TIMEOUT=604800   # Ip3 _min bngfonly ran ~44 h over three legs
BZ="./bazelisk.sh${OB:+ --output_base=$OB}"
BFLAGS="--//hw:make_options=-j,8 --//hw:verilator_options=--threads,$THREADS${OB:+ --experimental_convenience_symlinks=ignore}"
TFLAG="--test_arg=--verilator-args=+ibex_tracer_enable=0"
GATHER="python3 tools/gather_chip_matrix.py $MODE --strict --cells $(echo $CELLS | tr ' ' ',') --jobs $JOBS --make-options=-j,8 --test-timeout $TIMEOUT --bazel-flag=--//hw:verilator_options=--threads,$THREADS --bazel-flag=$TFLAG${OB:+ --bazel-startup=--output_base=$OB --bazel-flag=--experimental_convenience_symlinks=ignore}${BASELINE:+ --expected-insn-counts $BASELINE}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

profile_check() {
  local skip items rows off size span
  if [ "$PROFILE" = 32 ]; then skip=0x18000 items=7936 rows=32768 off="17'h ?18000" size="'h ?7c00" span=0x20000u
  else skip=0x80000 items=32512 rows=131072 off="20'h ?80000" size="'h ?1fc00" span=0x100000u; fi
  grep -q "skipto: \"$skip\"" hw/ip/acc/data/acc.hjson && grep -q "items: \"$items\"" hw/ip/acc/data/acc.hjson \
    && grep -q "$rows / 32" hw/ip/acc/dv/memutil/acc_memutil.cc \
    && grep -q "RegisterMemoryArea(\"dmem\", $skip" hw/ip/acc/dv/memutil/acc_memutil.cc \
    && grep -qE "ACC_DMEM_OFFSET *= *$off" hw/ip/acc/rtl/acc_reg_pkg.sv \
    && grep -qE "ACC_DMEM_SIZE *= *$size" hw/ip/acc/rtl/acc_reg_pkg.sv \
    && grep -qE "TOP_EGRET_ACC_SIZE_BYTES $span" hw/top_egret/sw/autogen/top_egret.h \
    && grep -qE "DmemScratchSizeByte *= *1024" hw/ip/acc/rtl/acc_pkg.sv \
    || { echo "the tree is not at the $PROFILE KiB profile (in a clone of its own: python3 tools/uov.py profile --profile $PROFILE)" >&2; exit 3; }
  echo "== profile $PROFILE KiB: DMEM $skip, $items bus words + 1 KiB scratch; memutil, register package, top span agree"
}

# acc_uov_<op>_<family>_<param>_<tier>_test -> the identity its meters line prints (uov_test.bzl)
meter_id() {
  local x=${1#acc_uov_}; x=${x%_test}
  local op=${x%%_*} rest=${x#*_}; local tier=${rest##*_}; rest=${rest%_*}
  local param=${rest##*_} fam=${rest%_*}; [ "$fam" = "$param" ] && fam=ldirect
  echo "op=$op param=$param family=$fam tier=$tier"
}

# cell -> its firmware, the ACC apps the build graph gives it, and every file in its runfiles
resolve() {
  local c=$1 fb lab elf f
  fb=$($BZ cquery $BFLAGS --output=files "//sw/device/tests/acc_uov:${c}_sim_verilator" 2>/dev/null | grep '\.bash$' | head -1)
  [ -n "$fb" ] || { echo "no test script for $c" >&2; exit 4; }
  echo "fw $EXEC/${fb%.bash}.elf"
  echo "sim $(readlink -f "$EXEC/$fb.runfiles/_main/hw/build.verilator_real/lowrisc_dv_top_egret_chip_verilator_sim_0.1/sim-verilator/Vchip_sim_tb")"
  for lab in $($BZ cquery $BFLAGS "kind(\"acc_binary\", deps(//sw/device/tests/acc_uov:${c}_sim_verilator))" --output=label 2>/dev/null | sed 's/ (.*//'); do
    elf=$($BZ cquery $BFLAGS --output=files "\"$lab\"" 2>/dev/null | grep '\.elf$' | head -1)
    [ -n "$elf" ] || { echo "no ELF for $lab" >&2; exit 4; }
    echo "app ${lab##*:} $lab $EXEC/$elf"
  done
  # what the simulation loads: wrapper, simulator, opentitantool, flash/ROM/OTP images
  (cd "$EXEC/$fb.runfiles" && find -L . -type f ! -name MANIFEST ! -name _repo_mapping -printf '%P\n') | LC_ALL=C sort | while read -r f; do
    echo "runfile $f $(readlink -f "$EXEC/$fb.runfiles/$f")"
  done
}

headers_128() {
  # one-shot: geometry header per app (from that app's ELF), vector header per parameter
  local c p a u lab h t kinds="" kind g v kp lp
  while read -r c p a u; do
    if [ "${c#acc_uov_verify}" != "$c" ]; then kind=verify; g=sw/device/tests/acc_uov/verify_oneshot_geom_$u.h
      python3 sw/device/tests/acc_uov/gen_verify_oneshot_testvec.py --geom --app "$u" --elf "$a" > "$TMP/geom_$u.h"
    else kind=keygen; g=sw/device/tests/acc_uov/keygen_oneshot_geom_$u.h
      python3 sw/device/tests/acc_uov/gen_keygen_oneshot_testvec.py --geom --param "$p" --app "$u" --elf "$a" > "$TMP/geom_$u.h"
    fi
    cmp -s "$TMP/geom_$u.h" "$g" || { echo "$g is stale (regenerate it from $a)" >&2; exit 4; }
    lab=$(awk -v u="$u" '$1 == "app" && $2 == u {print $3}' "$TMP/res_$c")
    h=$(echo "$u" | sed 's/_/-/; s/_/-/')      # ov_Ip_keygen_sp_bngfaes -> ov-Ip-keygen_sp_bngfaes
    $BZ build $BFLAGS "${lab%%:*}:$h" >/dev/null
    t=$EXEC/$($BZ cquery $BFLAGS --output=files "\"${lab%%:*}:$h\"" 2>/dev/null | grep '\.elf$' | head -1)
    python3 tools/gather_chip_matrix.py firmware --same-image "$a" "$t" || { echo "$u and its ISS twin $h carry different images" >&2; exit 4; }
    echo "elf $t sha256 $(sha256sum "$t" | cut -c1-64) twin-of $u cell $c" >> "$TMP/fixtures"
    echo "fixture $g sha256 $(sha256sum "$g" | cut -c1-64) cell $c" >> "$TMP/fixtures"
    kinds="$kinds $kind:$p"
  done < "$TMP/apps_128"
  for kp in $(echo $kinds | tr ' ' '\n' | LC_ALL=C sort -u); do
    kind=${kp%%:*}; p=${kp#*:}; lp=$(echo "$p" | tr 'A-Z' 'a-z')
    if [ "$kind" = keygen ]; then python3 sw/device/tests/acc_uov/gen_keygen_oneshot_testvec.py --vectors --param "$p" > "$TMP/v.h"
      v=sw/device/tests/acc_uov/keygen_oneshot_${lp}_testvec.h
    else python3 sw/device/tests/acc_uov/gen_verify_oneshot_testvec.py --vectors --param "$p" > "$TMP/v.h"
      v=sw/device/tests/acc_uov/verify_oneshot_${lp}_testvec.h
    fi
    cmp -s "$TMP/v.h" "$v" || { echo "$v is stale (regenerate it)" >&2; exit 4; }
    echo "fixture $v sha256 $(sha256sum "$v" | cut -c1-64)" >> "$TMP/fixtures"
  done
}

# header -> the generator command that writes it; the ELF argument comes from the consumer cell
gen_cmd() {
  local G=sw/device/tests/acc_uov
  case $1 in
    keygen_stream_ip_*_testvec.h) echo "$G/gen_keygen_stream_testvec.py --case 0 --param Ip --elf";;
    keygen_stream_ip3_*_testvec.h) echo "$G/gen_keygen_stream_testvec.py --case 0 --param Ip3 --elf";;
    keygen_stream_is_*_testvec.h) echo "$G/gen_keygen_stream_testvec.py --case 0 --param Is --elf";;
    verify_ip_testvec.h) echo "$G/gen_verify_ip_testvec.py --case 11 --param Ip --elf";;
    verify_ip3_testvec.h) echo "$G/gen_verify_ip_testvec.py --case 11 --param Ip3 --elf";;
    verify_stream_is_testvec.h|verify_stream_is_sw_testvec.h|verify_stream_uniform_is_testvec.h) echo "$G/gen_verify_is_testvec.py --case 11 --elf";;
    sign_ip_testvec.h) echo "$G/gen_sign_chip_testvec.py --param Ip --case 0";;
    sign_is_testvec.h) echo "$G/gen_sign_chip_testvec.py --param Is --case 0";;
    sign_ip3_testvec.h) echo "$G/gen_sign_chip_testvec.py --param Ip3 --case 0";;
    *) return 1;;
  esac
}

# the deployed bngfaes verify kernels export no msgwin/winend: their window header is checked
# against the sibling app that does
borrow() {
  local K=//sw/acc/crypto/handwritten/uov/dmem32k
  case $1 in
    ov_Ip_verify_stream_bngfaes) echo "$K/verify_stream_uniform/ov-Ip-pkc:ov_Ip_verify_stream_uniform_bngfaes";;
    ov_Ip3_verify_stream_bngfaes) echo "$K/verify_stream_uniform/ov-Ip3-pkc:ov_Ip3_verify_stream_uniform_bngfaes";;
    ov_Is_verify_stream_bngfaes) echo "$K/verify_stream/ov-Is-pkc:ov_Is_verify_stream_bngfonly";;
    *) return 1;;
  esac
}

headers_32() {
  # each cell's own header (from the build graph), regenerated from every app it embeds
  local c hl h cmd name lab elf b w
  for c in $CELLS; do
    hl=$($BZ cquery $BFLAGS "filter('_testvec\\.h\$', deps(//sw/device/tests/acc_uov:${c}_sim_verilator))" --output=label 2>/dev/null | sed 's/ (.*//')
    [ "$(echo "$hl" | grep -c .)" = 1 ] || { echo "$c: expected one test-vector header, got: $hl" >&2; exit 4; }
    h=${hl##*:}
    cmd=$(gen_cmd "$h") || { echo "$c: no generator known for $h" >&2; exit 4; }
    if [ "${cmd% --elf}" = "$cmd" ]; then
      python3 $cmd > "$TMP/h" 2>/dev/null || { echo "$c: the generator of $h failed" >&2; exit 4; }
      cmp -s "$TMP/h" "sw/device/tests/acc_uov/$h" || { echo "sw/device/tests/acc_uov/$h is stale (regenerate it)" >&2; exit 4; }
    else
      while read -r name lab elf; do
        if b=$(borrow "$name"); then
          $BZ build $BFLAGS "$b" >/dev/null
          elf=$EXEC/$($BZ cquery $BFLAGS --output=files "\"$b\"" 2>/dev/null | grep '\.elf$' | head -1)
          echo "elf $elf sha256 $(sha256sum "$elf" | cut -c1-64) window-reference-for $name cell $c" >> "$TMP/fixtures"
        fi
        if [ "${cmd#*gen_verify_}" != "$cmd" ]; then
          # the verify generators read the window from msgwin/winend; the Is one would fall back silently
          w=$(python3 tools/gather_chip_matrix.py firmware --symbols "$elf" msgwin winend) || { echo "$c: $elf exports no msgwin/winend" >&2; exit 4; }
          [ $(( $(echo "$w" | sed -n 's/^winend=//p') > $(echo "$w" | sed -n 's/^msgwin=//p') )) = 1 ] \
            || { echo "$c: empty window in $elf" >&2; exit 4; }
        fi
        python3 $cmd "$elf" > "$TMP/h" 2>/dev/null || { echo "$c: the generator of $h failed on $elf" >&2; exit 4; }
        cmp -s "$TMP/h" "sw/device/tests/acc_uov/$h" || { echo "sw/device/tests/acc_uov/$h is stale for $name ($elf)" >&2; exit 4; }
      done < <(awk '$1 == "app" {print $2, $3, $4}' "$TMP/res_$c")
    fi
    echo "fixture sw/device/tests/acc_uov/$h sha256 $(sha256sum "sw/device/tests/acc_uov/$h" | cut -c1-64) cell $c" >> "$TMP/fixtures"
  done
}

preflight() {
  SNAP=$(snapshot)
  profile_check
  TARGETS=$(for c in $CELLS; do echo -n "//sw/device/tests/acc_uov:${c}_sim_verilator "; done)
  echo "== build: $(echo $CELLS | wc -w) cells and the chip model they run"
  $BZ build $BFLAGS $TARGETS >/dev/null
  EXEC=$($BZ info $BFLAGS execution_root 2>/dev/null)
  SIM=""
  : > "$TMP/apps_128"; : > "$TMP/fixtures"
  for c in $CELLS; do
    resolve "$c" > "$TMP/res_$c"
    s=$(awk '$1 == "sim" {print $2}' "$TMP/res_$c")
    [ -f "$s" ] || { echo "no simulator in the runfiles of $c" >&2; exit 4; }
    [ -z "$SIM" ] || [ "$s" = "$SIM" ] || { echo "cells run different simulators: $SIM, $s" >&2; exit 4; }
    SIM=$s
    args=$(awk '$1 == "app" {printf " --app %s=%s", $2, $4}' "$TMP/res_$c")
    [ -n "$args" ] || { echo "$c embeds no ACC app" >&2; exit 4; }
    python3 tools/gather_chip_matrix.py firmware --firmware "$(awk '$1 == "fw" {print $2}' "$TMP/res_$c")" $args --meter-id="$(meter_id "$c")" > "$TMP/firmware_kernel_check_$c.json" \
      || { echo "$c: firmware does not embed exactly its apps or its meters identity (gather_chip_matrix.py firmware)" >&2; exit 4; }
    if [ "$PROFILE" = 128 ]; then
      p=$(echo "$c" | sed -E 's/.*_(ip3|ip|is)_[a-z]+_test$/\1/' | sed 's/ip3/Ip3/; s/^ip$/Ip/; s/^is$/Is/')
      awk -v c="$c" -v p="$p" '$1 == "app" {print c, p, $4, $2}' "$TMP/res_$c" >> "$TMP/apps_128"
    fi
  done
  echo "== every firmware embeds exactly its ACC apps and its own meters identity; one simulator: $SIM"
  if [ "$PROFILE" = 128 ]; then headers_128; else headers_32; fi
  echo "== every generated header matches its generator"
  [ "$(snapshot)" = "$SNAP" ] || { echo "the tree changed during the preflight" >&2; exit 4; }
}

manifest() {
  mkdir -p "$OUT/bin" "$OUT/firmware_kernel_checks"
  {
    echo "stamp $STAMP"
    echo "generation chip-meters-g4"
    echo "profile $PROFILE"
    echo "head $(git rev-parse HEAD)"
    echo "branch $(git rev-parse --abbrev-ref HEAD)"
    echo "snapshot $SNAP"
    echo "dirty_tracked $(git status --short --untracked-files=no | wc -l) untracked $(git status --short | grep -c '^??' || true)"
    # no startup options here: bazel refuses --version after them
    re='^bazel [0-9]+\.[0-9]+\.[0-9]+'
    if ! v=$(./bazelisk.sh --version 2>&1) || ! [[ "$(printf '%s\n' "$v" | tail -1)" =~ $re ]]; then
      echo "bazelisk.sh --version failed or printed no version: $v" >&2; exit 4
    fi
    echo "bazel $(printf '%s\n' "$v" | tail -1)"
    echo "output_base ${OB:-default}"
    echo "flags --test_timeout=$TIMEOUT --cache_test_results=no --local_test_jobs=$JOBS $BFLAGS $TFLAG"
    echo "collector $GATHER"
    echo "cells $CELLS"
    for f in .bazelrc .bazelrc-site .bazelversion MODULE.bazel.lock tools/rtl_campaign.sh tools/gather_chip_matrix.py $BASELINE; do
      [ -f "$f" ] && echo "source $f sha256 $(sha256sum "$f" | cut -c1-64)"
    done
    for f in sw/device/tests/acc_uov/*_test.c sw/device/tests/acc_uov/gen_*_testvec.py sw/device/tests/acc_uov/BUILD sw/device/tests/acc_uov/uov_test.bzl; do
      echo "source $f sha256 $(sha256sum "$f" | cut -c1-64)"
    done
    for c in $CELLS; do
      while read -r kind a b c3; do
        case $kind in
          fw) echo "firmware $a sha256 $(sha256sum "$a" | cut -c1-64) cell $c";;
          app) echo "elf $c3 sha256 $(sha256sum "$c3" | cut -c1-64) app $a label $b cell $c";;
          runfile) echo "runfile $b sha256 $(sha256sum "$b" | cut -c1-64) as $a cell $c";;
        esac
      done < "$TMP/res_$c"
      cp "$TMP/firmware_kernel_check_$c.json" "$OUT/firmware_kernel_checks/$c.json"
    done
    cat "$TMP/fixtures"
  } > "$OUT/manifest.txt"
  # the bytes, not only their hashes: one content-addressed copy of every binary the run used
  awk '$1 ~ /^(firmware|elf|runfile)$/ && $3 == "sha256" {print $2, $4}' "$OUT/manifest.txt" | LC_ALL=C sort -u -k2,2 | while read -r f sum; do
    [ -e "$OUT/bin/$sum" ] || cp "$f" "$OUT/bin/$sum"
  done
  git diff HEAD > "$OUT/tracked-changes.patch"
  git ls-files --others --exclude-standard | grep -v '__pycache__/' > "$OUT/untracked-files.txt" || true
  tar czf "$OUT/untracked-files.tgz" -T "$OUT/untracked-files.txt"
  cp "$0" "$OUT/rtl_campaign.sh"     # the detached job finishes with this frozen copy
  echo "== manifest -> $OUT/manifest.txt; $(ls "$OUT/bin" | wc -l) binaries -> $OUT/bin/"
}

preflight
manifest
if [ "$DRY" = 1 ]; then echo "dry run: no test launched ($OUT)"; exit 0; fi
LOG=$OUT/campaign.log
[ -z "$HOLD" ] || echo "$OUT" > "$HOLD"
echo "== run (detached): log $LOG"
# the exits of collection, postcheck and archiving all land in DONE; the hold is released only
# once the evidence is archived
setsid nohup bash -c "set -o pipefail; cd $REPO && $GATHER --run --out $OUT/results > $LOG 2>&1; ce=\$?; echo collector_exit=\$ce >> $LOG
  bash $OUT/rtl_campaign.sh --postcheck $OUT >> $LOG 2>&1; pe=\$?; echo postcheck_exit=\$pe >> $LOG
  bash $OUT/rtl_campaign.sh --archive $OUT >> $LOG 2>&1; ae=\$?; echo archive_exit=\$ae >> $LOG
  echo collector_exit=\$ce postcheck_exit=\$pe archive_exit=\$ae finished=\$(date -u +%Y%m%dT%H%M%SZ) > $OUT/DONE
  if [ \$ae = 0 ]; then ${HOLD:+rm -f -- '$HOLD';} :; fi" </dev/null >/dev/null 2>&1 &
echo "campaign pid $!; results land in $OUT/results; DONE records the exits"

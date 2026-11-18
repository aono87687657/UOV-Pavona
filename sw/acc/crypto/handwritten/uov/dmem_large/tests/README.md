# dmem_large/tests: the restart driver of the one-shot keygens

Last updated: 2026-10-21: one driver for keygen_min and keygen_sp and all three parameter sets (it replaces five).

## TL;DR
Symbol-driven: the driver writes the KAT `sk_seed`, runs one EXECUTE per key, compares `cpk` and `csk` byte for
byte with the test vectors, then runs more keys on the same simulator without reloading the ELF. That restart is
the negative control: a stale accumulator or leaked loop state fails the compare. `_min` runs A -> B (Ip3:
A -> A -> B -> A), `_sp` runs A -> B -> A; B is the next KAT case for Ip and Is and the first key of `--vectors2`
for Ip3.

## How to run
In a clone of its own at the 128 KiB profile (`python3 tools/uov.py profile --profile 128`, never committed),
from its root:
```
./bazelisk.sh build //sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/...
python3 sw/acc/crypto/handwritten/uov/dmem_large/tests/test_oneshot_keygen.py --variant min --param Ip \
  --elf bazel-bin/sw/acc/crypto/handwritten/uov/dmem_large/keygen_min/ov-Ip-pkc+skc/ov-Ip-keygen_min_bngfaes.elf \
  --cases 0 --tier bngfaes --poison --stats
```
`--variant min|sp` and `--param Ip|Is|Ip3` name the kernel; the other options, `--poison-return` (`_sp`) and
`--vectors2` (Ip3) included, are explained in `../keygen_min/README.md` (How to run, step 3); `--help` lists them.
The driver applies no DMEM cap: the ISS runs the DMEM profile of the tree.

## Files
| file | role |
|---|---|
| `test_oneshot_keygen.py` | the driver of `_min` and `_sp` for Ip, Is and Ip3: cpk 43,576 (Ip), 66,576 (Is) and 46,591 (Ip3) B, the 8 B guard after cpk (Ip, Ip3), the buffers `--poison` fills per kernel |

## Notes
- cpk is read back through the simulator's DMEM dump, not through a modelled bus transaction.

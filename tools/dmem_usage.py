#!/usr/bin/env python3
"""DMEM bytes the ACC reads or writes in one KAT case of each 32 KiB UOV cell (input of uov.py mem-usage).

  python3 tools/dmem_usage.py run --elf-root DIR --out DIR [--ops/--params/--tiers/--variants ..] [--case N] [--keep]
"""
import argparse
import hashlib
import json
import os
import runpy
import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
WIDTH = {'load_u32': ('r', 4), 'store_u32': ('w', 4), 'load_u256': ('r', 32), 'store_u256': ('w', 32)}


def ranges(addrs):
    """Sorted [lo, hi] (inclusive) runs of a set of byte addresses."""
    out = []
    for a in sorted(addrs):
        if out and out[-1][1] == a - 1:
            out[-1][1] = a
        else:
            out.append([a, a])
    return out


def spread(accesses):
    """The byte addresses of a set of (address, width) accesses."""
    return {a + i for a, w in accesses for i in range(w)}


def observe(out, driver, args):
    """Run one driver in this process with the DMEM hooked; write the touched bytes to out."""
    sys.path[:0] = [REPO, os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils')]
    import galois                                  # numba (under galois) must load before the simulator
    del galois
    from hw.ip.acc.dv.accsim.sim import dmem as dmem_mod
    from hw.ip.acc.dv.accsim.sim import standalonesim
    running, seen, phases = [False], {'r': set(), 'w': set()}, [0]
    for name, (kind, width) in WIDTH.items():
        orig = getattr(dmem_mod.Dmem, name)

        def hook(self, addr, *rest, _orig=orig, _k=kind, _w=width):
            if running[0]:
                seen[_k].add((addr, _w))
            return _orig(self, addr, *rest)
        setattr(dmem_mod.Dmem, name, hook)
    run = standalonesim.StandaloneSim.run

    def observed_run(self, *a, **kw):
        phases[0] += 1
        running[0] = True
        try:
            return run(self, *a, **kw)
        finally:
            running[0] = False
    standalonesim.StandaloneSim.run = observed_run
    elf = args[args.index('--elf') + 1] if '--elf' in args else None
    os.chdir(REPO)
    sys.argv = [driver] + args
    sys.path.insert(0, os.path.dirname(os.path.abspath(driver)))
    rc = 0
    try:
        runpy.run_path(driver, run_name='__main__')
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        rc = 1
        raise
    finally:
        with open(out, 'w') as fh:
            json.dump({'driver': os.path.relpath(driver, REPO), 'args': args, 'exit': rc, 'phases': phases[0],
                       'elf_sha256': hashlib.sha256(open(elf, 'rb').read()).hexdigest() if elf else None,
                       'read': ranges(spread(seen['r'])), 'written': ranges(spread(seen['w']))}, fh)
    return rc


LOCAL = threading.local()


def wrap(orig):
    """gather_kat_stats.drive, with each driver script run under observe (the out path is per thread)."""
    def drive(cmd):
        if len(cmd) > 1 and cmd[1].endswith('.py') and 'acc_objdump' not in cmd[1]:
            cmd = [cmd[0], os.path.abspath(__file__), 'observe', '--out', LOCAL.obs, '--', *cmd[1:]]
        return orig(cmd)
    return drive


def run_cell(gks, out_dir, op, p, t, v, case):
    """One cell through gather_kat_stats' own runner, its driver wrapped by observe."""
    name = f'{op}_{v}_{p}_{t}'
    obs = LOCAL.obs = os.path.join(out_dir, f'{name}.observe.json')
    work = tempfile.mkdtemp(prefix=name + '-', dir=out_dir)
    runner = {'keygen': gks.run_keygen, 'sign': gks.run_sign, 'verify': gks.run_verify}[op]
    kat, _ = runner(p, t, v, case, work)
    rec = json.load(open(obs)) if os.path.exists(obs) else {}
    rec.update({'op': op, 'variant': v, 'param': p, 'tier': t, 'case': case, 'verdict': kat,
                'elf': gks.elf_of(op, p, t, v)})
    with open(os.path.join(out_dir, f'{name}.json'), 'w') as fh:
        json.dump(rec, fh)
    if os.path.exists(obs):
        os.remove(obs)
    shutil.rmtree(work, ignore_errors=True)
    print(f'{op} {v} {p} {t}: {kat}', flush=True)
    return kat


def main():
    if sys.argv[1:2] == ['observe']:
        ap = argparse.ArgumentParser()
        ap.add_argument('--out', required=True)
        ap.add_argument('driver')
        ap.add_argument('args', nargs=argparse.REMAINDER)
        a = ap.parse_args(sys.argv[2:])
        args = a.args[1:] if a.args[:1] == ['--'] else a.args
        return observe(a.out, a.driver, args)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='observe the selected 32 KiB cells')
    r.add_argument('--elf-root', required=True, help='tree of built ELFs laid out like bazel-bin')
    r.add_argument('--out', required=True, help='directory for the per-cell JSON files')
    for f in ('ops', 'params', 'tiers', 'variants'):
        r.add_argument(f'--{f}', default='', help='comma list (default all)')
    r.add_argument('--case', type=int, default=0, help='KAT case (default 0)')
    r.add_argument('--workers', type=int, default=8)
    r.add_argument('--keep', action='store_true', help='skip the cells that already have a passing file in --out')
    a = ap.parse_args()
    sys.path.insert(0, os.path.join(REPO, 'tools'))
    import gather_kat_stats as gks
    gks.BAZEL_BIN = os.path.abspath(a.elf_root)
    gks.TIMEOUT = 6 * 3600
    gks.drive = wrap(gks.drive)   # module global: the runners call drive() by name
    pick = {f: set(getattr(a, f).split(',')) - {''} for f in ('ops', 'params', 'tiers', 'variants')}
    cells = [(op, p, t, v) for (pr, op, v), (params, tiers) in gks.CAMPAIGN.items() if pr == 32
             for p in params for t in tiers
             if all(not pick[f] or x in pick[f] for f, x in (('ops', op), ('params', p), ('tiers', t), ('variants', v)))]
    os.makedirs(a.out, exist_ok=True)
    if a.keep:
        done = lambda c: os.path.exists(f := os.path.join(a.out, f'{c[0]}_{c[3]}_{c[1]}_{c[2]}.json')) \
            and json.load(open(f)).get('verdict') == 'PASS'
        cells = [c for c in cells if not done(c)]
    slow = {'sw': 0, 'bngfonly': 1, 'bnaesonly': 2, 'bngfaes': 3}
    cells.sort(key=lambda c: (c[0] != 'keygen', slow[c[2]]))      # slowest first
    with ThreadPoolExecutor(a.workers) as ex:
        verdicts = list(ex.map(lambda c: run_cell(gks, a.out, c[0], c[1], c[2], c[3], a.case), cells))
    bad = [c for c, k in zip(cells, verdicts) if k != 'PASS']
    print(f'{len(cells) - len(bad)} of {len(cells)} cells passed' + (f'; failed: {bad}' if bad else ''))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())

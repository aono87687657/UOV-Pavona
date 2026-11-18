#!/usr/bin/env python3
"""One entry point for UOV measurements: campaign definition, cohort runs, records, tables.

  python3 tools/uov.py campaign-init --name NAME --publish-to CHECKOUT [--profiles 32,128,512]
  python3 tools/uov.py iss --campaign NAME --cohort keygen/full/bngfaes/Ip --publish-to CHECKOUT
  python3 tools/uov.py campaign-run --campaign NAME --profile 512 --publish-to CHECKOUT
  python3 tools/uov.py publish --run chip-matrix/<run> --publish-to CHECKOUT
  python3 tools/uov.py rtl-init --name NAME --measured-at COMMIT --bazelrc-site FILE --publish-to CHECKOUT
  python3 tools/uov.py rtl-import --campaign NAME --archive DIR [--archive DIR ...] --publish-to CHECKOUT
  python3 tools/uov.py tables [--check]
  python3 tools/uov.py profile --profile 128
  python3 tools/uov.py paper --out DIR
  python3 tools/uov.py retry --kernel ldirect --publish-to CHECKOUT [--vectors retrygrid] [--params Ip,Ip3,Is]
  python3 tools/uov.py mem-usage --elf-root DIR --observed DIR

campaign-init, run in a clean tree at the tooling commit, writes
CHECKOUT/sw/acc/crypto/handwritten/uov/results/campaigns/NAME.json: every catalog cohort of the
named profiles (op, variant, tier, param, cases 0-11, measurement protocol, driver scripts), the
tooling commit, each profile's DMEM overlay and the local Bazel configuration, by hash. Commit it in
CHECKOUT before running cohorts; every run binds to its hash.
iss runs one cohort in this tree, which must be the tooling commit plus exactly that profile's
overlay: it builds the cohort's ELF, freezes a copy in chip-matrix/<run>/bin, runs
gather_kat_stats.py on it (--workers cases at once, --timeout per case) and accepts the run only if
every case passes, every count re-derives from its evidence file and no input, overlay,
configuration, HEAD or frozen ELF changed. The record is finalised in chip-matrix/<run>/record, then
published under CHECKOUT's lock to results/<run> and entered in results/campaigns/NAME.completed.json.
A cohort is published once per campaign; a failed one is retried by a new run.
campaign-run runs one profile's unpublished cohorts one after another, slowest first; it continues
after a failed or timed-out cohort and stops on drift, broken campaign state or a publication to
finish (exit 0: all published, 1: some cohort failed, 2: stopped). Every refusal exits 2.
publish finishes the publication of a finalised run without rerunning it.
rtl-init registers chip-RTL measurements made by tools/rtl_campaign.sh: the commit they ran at, each
profile's DMEM overlay, the local Bazel configuration, the baseline ledger and every cell of the
collector's catalog (96: 60 at 32 KiB, 36 at 128 KiB), written to results/campaigns/NAME.json. The
runs may be older than the definition; they did not bind it. Commit it in CHECKOUT before importing.
rtl-import takes finished run directories of one or both profiles, from a clean tree at the definition's
tooling commit. Each must verify (rtl_campaign.sh --verify-only), carry that commit, overlay,
configuration and the recorded sources, and re-read to the csv it holds; the re-read uses a private
copy whose bytes equal the run's evidence.sha256. A profile is published only whole and once: every
cell from exactly one run, results/<run>/{manifest.json, results.csv} per run, then one update of
results/campaigns/NAME.completed.json. An RTL record in a checkout proves identity, completeness and
integrity; re-reading its numbers needs the run directory, which manifest.json names by the sha256
of its evidence.sha256. Exit status 0: published (or already there); 2: refused or stopped. A stop
during the installation can leave records under results/ that the completion list does not name:
they are not published, and the same rtl-import call again finishes it.
tables rewrites every table marked in a tracked Markdown file (<!-- table:NAME --> ... <!-- /table:NAME -->)
from the published ISS and RTL records; --check only reports what would change (exit 1). A table whose
cells are not all published stays as it is and is reported (exit 2).
paper writes every published number as a \\DefineVar line (vars.tex) and the generated LaTeX tabulars into
the paper's tables directory (--out), from the same records and with the same case convention as tables, and
the newest observe record of each kind (trace equality of the sign kernels, DMEM bytes touched per kernel);
retry runs one sign kernel (ldirect at 32 KiB, sprec at 512 KiB; bngfaes) on a vector set with a known number of
retries per case (test_data/testvectors-<P>-pkc-skc.VECTORS, index testvectors-VECTORS-index.csv) in this tree, a commit
plus exactly that profile's overlay; it accepts only if every case passes, every count re-derives, the attempt counter
equals the index and nothing changed, and publishes results/retry-<profile>-<stamp>-<id>, outside every campaign; paper
reads the one retry record of each kernel.
mem-usage writes the IMEM and DMEM usage of every 32 KiB cell (from tools/dmem_usage.py) for paper.
profile switches the DMEM profile of this tree: only in a clone of its own, never committed. 32 is the shipped
part; 128 is the one-shot measurement profile; 512 is ISS only (chip RTL runs at 32 and 128 KiB only).
"""
import argparse
import csv
import re
import datetime
import fcntl
import hashlib
import io
import json
import math
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import traceback
from zoneinfo import ZoneInfo

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path[:0] = [os.path.join(REPO, 'tools'), os.path.join(REPO, 'hw/ip/acc/util'), os.path.join(REPO, 'util'),
                os.path.join(REPO, 'sw/acc/crypto/handwritten/own_utils')]
import gather_chip_matrix as gcm
import gather_kat_stats as gks
import ov_params

RESULTS = 'sw/acc/crypto/handwritten/uov/results'
RUNS = 'chip-matrix'
LOCK = 'chip-matrix/.uov-results.lock'
KAT_CASES = 12
# directories whose bytes decide a result besides the cohort's targets, drivers and vectors: hashed whole
INPUT_DIRS = ('hw/ip/acc/dv/accsim', 'hw/ip/acc/util', 'hw/ip/acc/data', 'sw/acc/crypto/handwritten/own_utils')
# README -> tables rendered into it from published records


class Refused(Exception):
    pass

def fail(msg):
    print(f'uov.py: {msg}', file=sys.stderr)
    sys.exit(2)

def now():
    return datetime.datetime.now(ZoneInfo('Europe/Berlin')).isoformat(timespec='seconds')

def read(path, newline=None):
    with open(path, newline=newline) as fh:
        return fh.read()

def write_atomic(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        fh.write(text)
    os.replace(tmp, path)

def sha256(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()

def tidy(text):
    """Evidence as published: LF line ends, no trailing blanks, no blank first or last line. Git's whitespace
    check and util/fix_trailing_whitespace.py leave this form alone unless the first line is indented."""
    lines = [line.rstrip() for line in text.split('\n')]
    while lines and not lines[0]:
        del lines[0]
    while lines and not lines[-1]:
        del lines[-1]
    return '\n'.join(lines) + '\n'

def expected_layout(profile):
    skipto, items, _ = PROFILES[profile]
    return {'dmem_address': int(skipto, 16), 'dmem_bus_bytes': int(items) * 4, 'dmem_bytes': int(items) * 4 + 1024}

def actual_layout():
    from shared.mem_layout import get_memory_layout
    m = get_memory_layout()
    return {'dmem_address': m.dmem_address, 'dmem_bus_bytes': m.dmem_bus_size_bytes, 'dmem_bytes': m.dmem_size_bytes}

EVIDENCE = (('', '.stats.txt'), ('.log', '.driver.txt'))

def cell_stem(op, p, t, v, c):
    return gks.stats_name(op, p, t, v, c)[:-len('.txt')]

def evidence_names(cells):
    """The files every published bundle holds besides manifest.json."""
    names = {'results.csv'}
    for cell in cells:
        names |= {f'cells/{cell_stem(*cell)}{pub}' for _, pub in EVIDENCE}
    return names

def label_of(rel_elf):
    d, f = os.path.split(rel_elf)
    return f'//{d}:{f[:-len(".elf")]}'

def git(*args):
    return subprocess.run(['git', *args], cwd=REPO, check=True, capture_output=True, text=True).stdout

def in_git():
    """False where git finds no repository (a downloaded zip): `profile` and `mem-usage` still work there."""
    try:
        return subprocess.run(['git', 'rev-parse', '--git-dir'], cwd=REPO, capture_output=True).returncode == 0
    except OSError:                           # git is not installed
        return False

def bazel(*args, log=None):
    r = subprocess.run(['./bazelisk.sh', *args], cwd=REPO, capture_output=True, text=True)
    if log:
        with open(log, 'a') as fh:
            fh.write(f'$ bazel {" ".join(args)}\n{r.stdout}{r.stderr}\n')
    if r.returncode:
        raise Stop(f'bazel {args[0]} failed (exit {r.returncode}); see {log}')
    return r.stdout

def build_options(bep):
    """Bazel's own effective command line for the build (rc files included), local paths blanked."""
    for line in read(bep).splitlines():
        ev = json.loads(line)
        if 'optionsParsed' in ev.get('id', {}):
            return [re.sub(r'(?<==)/(?!/)\S*', '<local>', o) for o in ev['optionsParsed'].get('cmdLine', [])]
    raise Refused('the build event file has no optionsParsed record')

def build_inputs(labels, log):
    """Repository files the selected targets are built from: sources and BUILD/.bzl files."""
    expr = 'deps(set(' + ' '.join(f'"{lab}"' for lab in labels) + '))'
    out = bazel('query', f'kind("source file", {expr}) + buildfiles({expr})', '--output=label', log=log)
    paths = set()
    for lab in out.split():
        if lab.startswith('//'):
            pkg, name = lab[2:].split(':')
            paths.add(os.path.join(pkg, name))
    return paths

def pick_elves(cquery_files, labels):
    """Exactly one .elf named after each target among cquery's output files."""
    out = {}
    for lab in labels:
        name = '/' + lab.split(':')[1] + '.elf'
        hits = [f for f in cquery_files if f.endswith(name)]
        if len(hits) != 1:
            raise Stop(f'{lab}: {len(hits)} built ELF candidates')
        out[lab] = hits[0]
    return out

def elf_facts(path):
    from elftools.elf.elffile import ELFFile
    with open(path, 'rb') as fh:
        e = ELFFile(fh)
        syms = {s.name: s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols()}
        segs = [[seg['p_paddr'], seg['p_memsz'], hashlib.sha256(seg.data()).hexdigest()]
                for seg in e.iter_segments() if seg['p_type'] == 'PT_LOAD']
        entry = e.header['e_entry']
    facts = {'entry': entry, 'segments': segs, 'dmem_bss_end': syms['_dmem_bss_end']}
    if 'stack' in syms and 'stack_end' in syms:
        facts['stack_reserved'] = syms['stack_end'] - syms['stack']
    return facts

def accept(rows, cells, collector_exit):
    """Problems that block acceptance; empty means accepted."""
    problems = [] if collector_exit == 0 else [f'collector exit {collector_exit}']
    want = {(op, p, t, v, str(c)) for op, p, t, v, c in cells}
    seen = [(r['op'], r['param'], r['tier'], r['variant'], r['case']) for r in rows]
    if len(seen) != len(set(seen)):
        problems.append('duplicate cells')
    if set(seen) != want:
        problems.append(f'cells missing {sorted(want - set(seen))} extra {sorted(set(seen) - want)}')
    for r in rows:
        if r['kat'] != 'PASS' or not r['instructions'].isdigit() or not r['cycles'].isdigit():
            problems.append(f'{r["param"]} case {r["case"]}: {r["kat"]}')
    return problems

def locked(lock_path):
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    fh = open(lock_path, 'w')
    fcntl.flock(fh, fcntl.LOCK_EX)
    return fh

# ---------------------------------------------------------------------------------------------
# Campaigns: a committed definition, one cohort per run, a frozen record, then publication.

CAMPAIGNS = f'{RESULTS}/campaigns'
# ignored local Bazel configuration (it can override external repositories): pinned by hash
CONFIG_FILES = ('.bazelrc-site',)
REQUIRED_FILES = ('tools/uov.py', 'tools/gather_kat_stats.py',
                  'util/acc_build.py', 'rules/acc.bzl', 'MODULE.bazel', 'MODULE.bazel.lock', '.bazelrc', '.bazelversion',
                  'bazelisk.sh')
# DMEM profiles of a clone (uov.py profile)
HJSON = 'hw/ip/acc/data/acc.hjson'
MEMUTIL = 'hw/ip/acc/dv/memutil/acc_memutil.cc'
# KiB -> (skipto, items, items comment)
PROFILES = {
    32: ('0x18000', '7936', '31 kiB visible over bus (1 kiB scratch) -> 32 kiB total'),
    128: ('0x80000', '32512', '127 kiB visible over bus (1 kiB scratch) -> 128 kiB total'),
    512: ('0x80000', '130816', '511 kiB visible over bus (1 kiB scratch) -> 512 kiB total'),
}
RE_SKIP = re.compile(r'\{ skipto: "(0x[0-9a-f]+)" \}')
RE_ITEMS = re.compile(r'items: "(\d+)", // [^\n]*')
TIER_ORDER = {'sw': 0, 'bngfonly': 1, 'bnaesonly': 2, 'bngfaes': 3}   # slowest first
RUN_ID = re.compile(r'iss-\d+-\d{8}T\d{6}Z-[0-9a-f]{8}')
OP_ORDER = {'keygen': 0, 'sign': 1, 'verify': 2}


class Stop(Exception):
    """Drift, broken campaign state or a publication to finish: stops a campaign lane."""


def cohort_key(c):
    return f'iss:{c["op"]}/{c["variant"]}/{c["tier"]}/{c["param"]}@{c["profile"]}'


def cohort_cells(c):
    return [(c['op'], c['param'], c['tier'], c['variant'], case) for case in c['cases']]


def canonical(checkout):
    """The publication checkout's top directory; it must be a git checkout and not this tree."""
    path = os.path.realpath(checkout)
    r = subprocess.run(['git', 'rev-parse', '--show-toplevel'], cwd=path, capture_output=True, text=True)
    if r.returncode or os.path.realpath(r.stdout.strip()) != path:
        fail(f'{checkout} is not the top of a git checkout')
    if path == os.path.realpath(REPO):
        fail('publish into a separate checkout: publishing here would change this tree before its next run')
    return path


def campaign_files(checkout, name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
        fail(f'bad campaign name {name!r}')
    d = os.path.join(checkout, CAMPAIGNS)
    return os.path.join(d, f'{name}.json'), os.path.join(d, f'{name}.completed.json')


def load_definition(checkout, name):
    """(definition, sha256 of its bytes)."""
    path, _ = campaign_files(checkout, name)
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
        d = json.loads(raw)
    except (OSError, ValueError) as e:
        raise Stop(f'campaign definition {path}: {e}')
    keys = {'schema', 'name', 'created', 'tooling_commit', 'config', 'overlays', 'cohorts'}
    if not isinstance(d, dict) or set(d) != keys or d['schema'] != 1 or d['name'] != name \
            or not re.fullmatch(r'[0-9a-f]{40}', str(d['tooling_commit'])) or not isinstance(d['cohorts'], list) \
            or not all(isinstance(c, dict) for c in d['cohorts']) \
            or len({cohort_key(c) for c in d['cohorts']}) != len(d['cohorts']):
        raise Stop(f'{path} is not a campaign definition')
    for c in d['cohorts']:
        cat = gks.CAMPAIGN.get((c.get('profile'), c.get('op'), c.get('variant')))
        if cat is None or c.get('param') not in cat[0] or c.get('tier') not in cat[1] or c != canonical_cohort(c, layout_of(d)) \
                or str(c['profile']) not in d['overlays']:
            raise Stop(f'{path}: {cohort_key(c)} is not a catalog cohort with its canonical fields')
    if head_blob(checkout, os.path.relpath(path, checkout)) != raw:
        raise Stop(f'{path} is not committed in {checkout} as it stands')
    return d, hashlib.sha256(raw).hexdigest()


def head_blob(checkout, rel):
    """rel as committed at the checkout's HEAD; None if it is not there."""
    r = subprocess.run(['git', 'cat-file', 'blob', f'HEAD:{rel}'], cwd=checkout, capture_output=True)
    return None if r.returncode else r.stdout


# The rounds measured before the 2026-10-19 folder reorg, by name and tooling commit: their definitions and records
# name the folders of that time (gather_kat_stats layout "flat"); every other round must name the current ones.
FLAT_LAYOUT = {'iss-2026-10b': 'ea4d5d4eecc9ca3089205670969a438ba974c36a',
               'iss-2026-10e': '9fe312874c0410b2d40575ef44a3b1a60f925946',
               'iss-2026-10f': 'c5ef6d2a46b1d9f23b2703989ca7614158d25678'}


def layout_of(defn):
    """The folder layout a campaign definition was measured in."""
    return 'flat' if FLAT_LAYOUT.get(defn['name']) == defn['tooling_commit'] else 'current'


def canonical_cohort(c, layout='current'):
    """A definition's cohort as campaign-init writes it from the catalog (in that layout's folders)."""
    return {'profile': c['profile'], 'op': c['op'], 'variant': c['variant'], 'tier': c['tier'], 'param': c['param'],
            'cases': list(range(KAT_CASES)), 'protocol': gks.PROTOCOL[(c['op'], c['variant'])],
            'drivers': gks.driver_of(c['op'], c['param'], c['variant'], layout)}


def load_completed(checkout, name, dsha):
    """cohort key -> {run, manifest} of the cohorts published in this campaign."""
    _, path = campaign_files(checkout, name)
    if not os.path.exists(path):
        return {}
    try:
        done = json.loads(read(path))
        ok = (isinstance(done, dict) and set(done) == {'campaign', 'definition', 'cohorts'} and done['campaign'] == name
              and isinstance(done['cohorts'], dict))
    except ValueError:
        ok = False
    if not ok:
        raise Stop(f'{path} is not a completion list')
    if done['definition'] != dsha:
        raise Stop(f'{path} belongs to another version of campaign {name}')
    return done['cohorts']


def completed_records(checkout, name, defn, dsha):
    """The completion list, each entry checked against its published bundle; Stop on any inconsistency."""
    done = load_completed(checkout, name, dsha)
    keys = {cohort_key(c) for c in defn['cohorts']}
    for key, e in done.items():
        if key not in keys or not isinstance(e, dict) or set(e) != {'run', 'manifest'} \
                or not RUN_ID.fullmatch(str(e['run'])) or not re.fullmatch(r'[0-9a-f]{64}', str(e['manifest'])):
            raise Stop(f'completion list of {name}: bad entry {key}')
        bundle = os.path.join(checkout, RESULTS, e['run'])
        try:
            with open(os.path.join(bundle, 'manifest.json'), 'rb') as fh:
                raw = fh.read()
        except OSError:
            raw = b''
        if hashlib.sha256(raw).hexdigest() != e['manifest']:
            raise Stop(f'completion list of {name}: {key} names {e["run"]}, which is missing or altered')
        try:
            m = validate_record(bundle, defn, dsha, raw)
        except Refused as err:
            raise Stop(f'completion list of {name}: {key}: {err}')
        if cohort_key(m['cohort']) != key or m['run'] != e['run']:
            raise Stop(f'completion list of {name}: {key} names a record of {cohort_key(m["cohort"])}, run {m["run"]}')
    return done


def tree_overlay(tree):
    """Tracked files that differ from HEAD: path -> [sha256 (None: deleted), git mode]."""
    out = {}
    names = subprocess.run(['git', 'diff', '--name-only', 'HEAD'], cwd=tree, check=True, capture_output=True,
                           text=True).stdout.split()
    for p in names:
        f = os.path.join(tree, p)
        if os.path.islink(f) or (os.path.exists(f) and not os.path.isfile(f)):
            out[p] = ['not a regular file', None]
        elif os.path.exists(f):
            out[p] = [sha256(f), '100755' if os.stat(f).st_mode & 0o111 else '100644']
        else:
            out[p] = [None, None]
    return out


def tree_config(tree):
    return {f: (sha256(os.path.join(tree, f)) if os.path.isfile(os.path.join(tree, f)) else None) for f in CONFIG_FILES}


def profile_overlays(head, profiles):
    """profile -> what uov.py profile --profile changes on a clean checkout of head ({} for the committed one)."""
    committed = [current(git('show', f'{head}:{HJSON}'))]
    overlays = {p: {} for p in committed}
    need = [p for p in profiles if p not in committed]
    if need:
        tmp = tempfile.mkdtemp(prefix='uov-overlay-')
        tree = os.path.join(tmp, 'tree')
        git('worktree', 'add', '--detach', tree, head)
        try:
            for p in need:
                subprocess.run([sys.executable, 'tools/uov.py', 'profile', '--profile', str(p)], cwd=tree, check=True,
                               capture_output=True)
                overlays[p] = tree_overlay(tree)
        finally:
            git('worktree', 'remove', '--force', tree)
            shutil.rmtree(tmp, ignore_errors=True)
    return {str(p): overlays[p] for p in sorted(profiles)}


def campaign_init(a):
    checkout = canonical(a.publish_to)
    path, done = campaign_files(checkout, a.name)
    if os.path.exists(path) or os.path.exists(done):
        fail(f'{path} exists; a campaign definition is never rewritten')
    if git('status', '--porcelain', '--untracked-files=no').strip():
        fail('this tree has tracked changes; campaign-init records a clean tooling commit')
    profiles = sorted({int(x) for x in a.profiles.split(',')})
    if any(p not in PROFILES for p in profiles):
        fail(f'--profiles: known profiles are {sorted(PROFILES)}')
    head = git('rev-parse', 'HEAD').strip()
    cohorts = [{'profile': prof, 'op': op, 'variant': v, 'tier': t, 'param': p, 'cases': list(range(KAT_CASES)),
                'protocol': gks.PROTOCOL[(op, v)], 'drivers': gks.driver_of(op, p, v)}
               for (prof, op, v), (params, tiers) in sorted(gks.CAMPAIGN.items()) if prof in profiles
               for t in tiers for p in params]
    defn = {'schema': 1, 'name': a.name, 'created': now(), 'tooling_commit': head, 'config': tree_config(REPO),
            'overlays': profile_overlays(head, profiles), 'cohorts': cohorts}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'x') as fh:
        json.dump(defn, fh, indent=1, sort_keys=True)
        fh.write('\n')
    print(f'wrote {path}: {len(cohorts)} cohorts, tooling commit {head[:10]}; commit it in {checkout}, then run cohorts')


def provenance(defn, profile):
    """Problems with this tree as the campaign's execution tree for one profile."""
    problems = []
    if git('rev-parse', 'HEAD').strip() != defn['tooling_commit']:
        problems.append('HEAD is not the campaign tooling commit')
    if git('diff', '--cached', '--name-only').strip():
        problems.append('staged changes')
    if str(profile) not in defn['overlays'] or tree_overlay(REPO) != defn['overlays'][str(profile)]:
        problems.append(f'tracked changes are not exactly the campaign\'s {profile} KiB overlay '
                        f'(python3 tools/uov.py profile --profile {profile} on a clean tree)')
    if tree_config(REPO) != defn['config']:
        problems.append('the local Bazel configuration differs from the campaign\'s')
    if actual_layout() != expected_layout(profile):
        problems.append(f'the tree is not at the {profile} KiB profile')
    return problems


def input_paths(cohort, labels, log):
    """Every file whose bytes decide the cohort's result; a missing required file stops the run."""
    required = set(REQUIRED_FILES) | set(gks.driver_of(cohort['op'], cohort['param'], cohort['variant']))
    required.add(os.path.relpath(gks.testvec_path(cohort['param']), REPO))
    required.update(os.path.relpath(p, REPO) for p in gks.aux_inputs(cohort['op'], cohort['param'], cohort['variant']))
    missing = sorted(p for p in required if not os.path.isfile(os.path.join(REPO, p)))
    if missing:
        raise Stop(f'required inputs missing: {missing}')
    paths = required | build_inputs(labels, log) | {f for f in CONFIG_FILES if os.path.isfile(os.path.join(REPO, f))}
    for d in INPUT_DIRS:
        for root, dirs, files in os.walk(os.path.join(REPO, d)):
            dirs[:] = sorted(x for x in dirs if x != '__pycache__')
            paths.update(os.path.relpath(os.path.join(root, f), REPO) for f in files if not f.endswith('.pyc'))
    return sorted(p for p in paths if os.path.isfile(os.path.join(REPO, p)))


def hash_inputs(paths):
    return {p: sha256(os.path.join(REPO, p)) for p in paths}


def untracked(paths):
    """Inputs git does not track, ignored ones included (the pinned configuration files aside)."""
    tracked = set(git('ls-files').split())
    return sorted(set(paths) - tracked - set(CONFIG_FILES))


def collector_completed(run, rows, cohort):
    """The collector ran to its end and reported exactly the cohort's cases (passing or not)."""
    log = read(os.path.join(run, 'collector.log')) if os.path.exists(os.path.join(run, 'collector.log')) else ''
    want = sorted((op, p, t, v, str(c)) for op, p, t, v, c in cohort_cells(cohort))
    have = sorted((r['op'], r['param'], r['tier'], r['variant'], r['case']) for r in rows)
    return have == want and re.search(r'^DONE \d+/\d+ ', log, re.M) is not None


def count_problems(stats_dir, rows, name_of, cohort):
    """Each published count must re-derive from its evidence file with the route's measurement rule."""
    out = []
    for r in rows:
        cell = (r['op'], r['param'], r['tier'], r['variant'], int(r['case']))
        got = gks.measurement(os.path.join(stats_dir, name_of(cell)), gks.measurement_label(r['op'], r['variant'], cell[4]))
        if got != (int(r['instructions']), int(r['cycles'])):
            out.append(f'case {r["case"]}: results.csv {r["instructions"]}/{r["cycles"]}, evidence {got}')
    return out


def finalize_record(run, run_id, cohort, manifest):
    """chip-matrix/<run>/record: tidy evidence with logical ELF paths, hashed in manifest.json; frozen from here on."""
    record = os.path.join(run, 'record')
    os.makedirs(os.path.join(record, 'cells'))
    raw_csv = os.path.join(run, 'kat', 'results.csv')
    texts = {'results.csv': tidy(read(raw_csv))}
    with open(raw_csv, newline='') as fh:
        if list(csv.reader(fh)) != list(csv.reader(texts['results.csv'].splitlines())):
            raise Stop(f'tidying {raw_csv} would change its fields')
    frozen = os.path.join(run, 'bin') + '/'
    for cell in cohort_cells(cohort):
        name = gks.stats_name(*cell)
        for raw, pub in EVIDENCE:
            text = read(os.path.join(run, 'kat', 'stats', name + raw)).replace(frozen, '').replace(REPO + '/', '')
            texts[f'cells/{cell_stem(*cell)}{pub}'] = tidy(text)
    for rel, text in texts.items():
        with open(os.path.join(record, rel), 'w') as fh:
            fh.write(text)
    manifest['evidence'] = {os.path.relpath(os.path.join(r, f), record): sha256(os.path.join(r, f))
                            for r, _, fs in os.walk(record) for f in fs}
    with open(os.path.join(record, 'manifest.json'), 'w') as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write('\n')
    return record


def validate_record(bundle, defn, dsha, raw=None):
    """A schema-2 record checked against its campaign definition and one manifest snapshot: raw, the manifest
    bytes the bundle must carry (default: its own manifest.json). Malformed manifests fail closed."""
    with open(os.path.join(bundle, 'manifest.json'), 'rb') as fh:
        own = fh.read()
    if raw is not None and own != raw:
        raise Refused(f'{bundle}: manifest.json is not the snapshot being checked')
    m = json.loads(own)
    c = m.get('cohort')
    problems = []
    if m.get('schema') != 2 or m.get('engine') != 'iss' or m.get('campaign') != defn['name'] or m.get('definition') != dsha:
        problems.append('manifest identity')
    if c not in defn['cohorts'] or m.get('protocol') != c['protocol']:
        problems.append('cohort is not the campaign\'s')
        raise Refused(f'{m.get("run")}: {", ".join(problems)}')
    cells = cohort_cells(c)
    comp = m.get('completion', {})
    if comp.get('accepted') is not True or comp.get('collector_exit') != 0 or comp.get('cells') != len(cells):
        problems.append('completion record')
    if m.get('profile') != expected_layout(c['profile']):
        problems.append('profile')
    if not RUN_ID.fullmatch(str(m.get('run'))):
        problems.append('run id')
    src, ex, arts = m.get('source'), m.get('execution'), m.get('artifacts')
    vec = os.path.relpath(gks.testvec_path(c['param']), REPO)
    extra = {os.path.relpath(p, REPO) for p in gks.aux_inputs(c['op'], c['param'], c['variant'])}
    if not isinstance(src, dict) or src.get('commit') != defn['tooling_commit'] \
            or src.get('overlay') != defn['overlays'][str(c['profile'])] or src.get('config') != defn['config']:
        problems.append('source is not the campaign\'s commit, overlay and configuration')
    elif not isinstance(src.get('inputs'), dict) or src.get('vectors') != {vec: src['inputs'].get(vec)} \
            or not (set(REQUIRED_FILES) | set(c['drivers']) | {vec} | extra) <= set(src['inputs']) \
            or not all(isinstance(h, str) and re.fullmatch(r'[0-9a-f]{64}', h) for h in src['inputs'].values()):
        problems.append('source inputs are not sha256 digests of the required files and the vector files')
    if not isinstance(ex, dict) or not isinstance(ex.get('workers'), int) or ex['workers'] < 1 \
            or not isinstance(ex.get('timeout'), (int, float)) or not math.isfinite(ex['timeout']) or ex['timeout'] <= 0:
        problems.append('execution record')
    rel = gks.elf_of(c['op'], c['param'], c['tier'], c['variant'], layout_of(defn))
    if not isinstance(arts, dict) or set(arts) != {label_of(rel)} or arts[label_of(rel)].get('elf') != rel \
            or not re.fullmatch(r'[0-9a-f]{64}', str(arts[label_of(rel)].get('sha256'))):
        problems.append('artifact is not the cohort\'s ELF')
    evidence = m.get('evidence', {})
    on_disk = {os.path.relpath(os.path.join(r, f), bundle) for r, _, fs in os.walk(bundle) for f in fs} - {'manifest.json'}
    if set(evidence) != evidence_names(cells) or on_disk != set(evidence):
        problems.append('evidence files are not the cohort\'s cells')
    elif any(sha256(os.path.join(bundle, f)) != h for f, h in evidence.items()):
        problems.append('files differ from the hashes in the manifest')
    else:
        for f in sorted(evidence):
            t = read(os.path.join(bundle, f), newline='')
            if t != tidy(t) or t[0].isspace():
                problems.append(f'{f} is empty or not tidy')
                break
    if not problems:
        rows = list(csv.DictReader(read(os.path.join(bundle, 'results.csv')).splitlines()))
        problems += accept(rows, cells, comp.get('collector_exit'))
        if not problems:
            problems += count_problems(os.path.join(bundle, 'cells'), rows, lambda cell: f'{cell_stem(*cell)}.stats.txt', c)
    if problems:
        raise Refused(f'{m.get("run")}: {"; ".join(problems)}')
    return m


def publish_record(record, checkout):
    """Install a finalised record under the checkout's lock and add it to its campaign's completion list.
    One snapshot of the record's manifest decides the run id, campaign and cohort, the manifest the published
    copy must carry and the hash entered in the list. Finishes an interrupted publication of the same record;
    refuses anything else already there."""
    with open(os.path.join(record, 'manifest.json'), 'rb') as fh:
        raw = fh.read()
    try:
        m = json.loads(raw)
        run_id, name = m.get('run'), m.get('campaign')
    except (ValueError, AttributeError) as e:
        raise Stop(f'{record}: not a campaign record ({e})')
    if not RUN_ID.fullmatch(str(run_id)) or not isinstance(name, str):
        raise Stop(f'{record}: not a campaign record')
    mhash = hashlib.sha256(raw).hexdigest()
    final = os.path.join(checkout, RESULTS, run_id)
    with locked(os.path.join(checkout, LOCK)):
        defn, dsha = load_definition(checkout, name)
        if dsha != m.get('definition'):
            raise Stop(f'campaign {name} changed since run {run_id}')
        done = completed_records(checkout, name, defn, dsha)     # every listed record checked before any change
        try:
            validate_record(record, defn, dsha, raw)
        except Refused as e:
            raise Stop(f'not published: {e}')
        key = cohort_key(m['cohort'])
        if key in done:
            if done[key] == {'run': run_id, 'manifest': mhash}:   # its bundle was just checked against this hash
                print(f'{run_id} is already published')
                return final
            raise Stop(f'{key} is already published in campaign {name} by {done[key]["run"]}')
        if os.path.exists(final):                    # an interrupted publication: finish it only if it is this record
            try:
                validate_record(final, defn, dsha, raw)
            except Refused as e:
                raise Stop(f'{final} exists and is not this record: {e}')
        else:
            staging = os.path.join(checkout, RESULTS, f'.staging-{run_id}')
            shutil.rmtree(staging, ignore_errors=True)
            shutil.copytree(record, staging)
            try:                                     # the copy, not the source, is what goes live
                validate_record(staging, defn, dsha, raw)
            except Refused as e:
                shutil.rmtree(staging, ignore_errors=True)
                raise Stop(f'not published: {e}')
            os.rename(staging, final)
        done[key] = {'run': run_id, 'manifest': mhash}
        _, done_path = campaign_files(checkout, name)
        write_atomic(done_path, json.dumps({'campaign': name, 'definition': dsha, 'cohorts': done},
                                           indent=1, sort_keys=True) + '\n')
    return final


def run_cohort(checkout, name, want, workers, timeout, dsha_expected=None):
    """One cohort: True if accepted and published, False if a case failed or timed out.
    Raises Stop on drift, broken campaign state, a failed build or an unfinished publication."""
    defn, dsha = load_definition(checkout, name)
    if dsha_expected is not None and dsha != dsha_expected:
        raise Stop(f'campaign {name} changed during the run')
    cohort = next((c for c in defn['cohorts'] if all(c[k] == want[k] for k in ('op', 'variant', 'tier', 'param'))), None)
    if cohort is None:
        raise Stop(f'{"/".join(want[k] for k in ("op", "variant", "tier", "param"))} is not a cohort of campaign {name}')
    key, profile = cohort_key(cohort), cohort['profile']
    problems = provenance(defn, profile)
    if problems:
        raise Stop('; '.join(problems))
    if key in completed_records(checkout, name, defn, dsha):
        raise Stop(f'{key} is already published in campaign {name}')
    stamp = datetime.datetime.now(datetime.timezone.utc)
    run_id = f'iss-{profile}-{stamp:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}'
    run = os.path.join(REPO, RUNS, run_id)
    os.makedirs(run)
    created = now()
    log = os.path.join(run, 'build.log')
    rel = gks.elf_of(cohort['op'], cohort['param'], cohort['tier'], cohort['variant'])
    label = label_of(rel)
    inputs = input_paths(cohort, [label], log)
    stray = untracked(inputs)
    if stray:
        raise Stop(f'untracked inputs: {stray}')
    before = hash_inputs(inputs)
    bep = os.path.join(run, 'build.bep.json')
    bazel('build', f'--build_event_json_file={bep}', label, log=log)
    exec_root = bazel('info', 'execution_root', log=log).strip()
    files = bazel('cquery', '--output=files', f'"{label}"', log=log).split()
    dst = os.path.join(run, 'bin', rel)
    os.makedirs(os.path.dirname(dst))
    shutil.copyfile(os.path.join(exec_root, pick_elves(files, [label])[label]), dst)   # a regular file
    artifacts = {label: {'elf': rel, 'sha256': sha256(dst), **elf_facts(dst)}}
    gather = [sys.executable, os.path.join(REPO, 'tools/gather_kat_stats.py'), '--out', os.path.join(run, 'kat'), '--fresh',
              '--ops', cohort['op'], '--params', cohort['param'], '--tiers', cohort['tier'], '--variants', cohort['variant'],
              '--cases', ','.join(map(str, cohort['cases'])), '--elf-root', os.path.join(run, 'bin'),
              '--workers', str(workers), '--timeout', str(timeout)]
    with open(os.path.join(run, 'collector.log'), 'w') as fh:
        collector_exit = subprocess.run(gather, cwd=REPO, stdout=fh, stderr=subprocess.STDOUT).returncode
    res = os.path.join(run, 'kat', 'results.csv')
    rows = list(csv.DictReader(read(res).splitlines())) if os.path.exists(res) else []
    # drift is checked before the verdict: a changed tree invalidates passes and failures alike
    after = input_paths(cohort, [label], log)
    problems = provenance(defn, profile) + [f'untracked inputs: {u}' for u in [untracked(after)] if u]
    if after != inputs:
        problems.append(f'the input set changed: added {sorted(set(after) - set(inputs))}, removed {sorted(set(inputs) - set(after))}')
    problems += [f'input changed: {p}' for p, h in hash_inputs(inputs).items() if before[p] != h]
    if sha256(dst) != artifacts[label]['sha256']:
        problems.append('the frozen ELF changed')
    if problems:
        raise Stop(f'run {run_id}: {"; ".join(problems)} (evidence in {RUNS}/{run_id})')
    if not collector_completed(run, rows, cohort):
        raise Stop(f'run {run_id}: the collector did not complete (exit {collector_exit}; see {RUNS}/{run_id}/collector.log)')
    failed = [f'case {r["case"]} {r["kat"]}' for r in rows if r['kat'] != 'PASS']
    if failed:
        print(f'{key}: not accepted, {", ".join(failed)} (evidence in {RUNS}/{run_id}; a retry is a new run)')
        return False
    bad = count_problems(os.path.join(run, 'kat', 'stats'), rows, lambda cell: gks.stats_name(*cell), cohort)
    if collector_exit != 0 or bad:
        raise Stop(f'run {run_id}: collector exit {collector_exit} with every case PASS; {bad}')
    manifest = {
        'schema': 2, 'run': run_id, 'engine': 'iss', 'campaign': name, 'definition': dsha, 'cohort': cohort,
        'protocol': cohort['protocol'], 'created': created, 'completed': now(),
        'source': {'commit': defn['tooling_commit'], 'overlay': defn['overlays'][str(profile)], 'config': defn['config'],
                   'inputs': before, 'vectors': {os.path.relpath(gks.testvec_path(cohort['param']), REPO):
                                                 before[os.path.relpath(gks.testvec_path(cohort['param']), REPO)]}},
        'execution': {'python': sys.version.split()[0], 'bazel': bazel('--version').strip().splitlines()[-1],
                      'bazel_options': build_options(bep), 'collector': [os.path.relpath(x, REPO) if x.startswith(REPO) else x
                                                                         for x in gather[1:]],
                      'workers': workers, 'timeout': timeout},
        'profile': actual_layout(),
        'artifacts': artifacts,
        'completion': {'collector_exit': collector_exit, 'cells': len(rows), 'accepted': True},
    }
    record = finalize_record(run, run_id, cohort, manifest)
    final = publish_record(record, checkout)
    print(f'accepted {run_id}: {key}, {len(rows)} cases PASS -> {final}')
    return True


def run_iss(a):
    """Exit 0: accepted and published, 1: a case failed or timed out, 2: stopped."""
    want = dict(zip(('op', 'variant', 'tier', 'param'), a.cohort.split('/')))
    if len(want) != 4 or a.cohort.count('/') != 3:
        fail('--cohort is op/variant/tier/param, e.g. keygen/full/bngfaes/Ip')
    checkout = canonical(a.publish_to)
    try:
        return 0 if run_cohort(checkout, a.campaign, want, a.workers, a.timeout) else 1
    except (Stop, Refused, OSError) as e:
        print(f'uov.py: stopped: {e}', file=sys.stderr)
        return 2


def run_campaign(a):
    """Exit 0: every cohort of the profile published, 1: some cohort failed, 2: stopped."""
    checkout = canonical(a.publish_to)
    try:
        defn, dsha = load_definition(checkout, a.campaign)
        done = completed_records(checkout, a.campaign, defn, dsha)
    except (Stop, Refused, OSError) as e:
        print(f'uov.py: stopped: {e}', file=sys.stderr)
        return 2
    mine = [c for c in defn['cohorts'] if c['profile'] == a.profile]
    if not mine:
        fail(f'campaign {a.campaign} has no {a.profile} KiB cohort')
    todo = sorted((c for c in mine if cohort_key(c) not in done),
                  key=lambda c: (TIER_ORDER[c['tier']], OP_ORDER[c['op']], cohort_key(c)))
    print(f'campaign {a.campaign}, {a.profile} KiB: {len(todo)} of {len(mine)} cohorts to run')
    failed = []
    for c in todo:
        try:
            if not run_cohort(checkout, a.campaign, c, a.workers, a.timeout, dsha_expected=dsha):
                failed.append(cohort_key(c))
        except (Stop, Refused, OSError) as e:
            print(f'stopped at {cohort_key(c)}: {e}', file=sys.stderr)
            return 2
    if failed:
        print(f'{len(failed)} cohorts not accepted: {", ".join(failed)}')
        return 1
    print(f'campaign {a.campaign}, {a.profile} KiB: every cohort published')
    return 0


def run_publish(a):
    checkout = canonical(a.publish_to)
    try:
        publish_record(os.path.join(os.path.realpath(a.run), 'record'), checkout)
    except (Stop, Refused, OSError, ValueError) as e:
        print(f'uov.py: stopped: {e}', file=sys.stderr)
        return 2
    return 0


# ---------------------------------------------------------------------------------------------
# RTL: finished tools/rtl_campaign.sh run directories, registered after launch, published a whole profile at a time.

RTL_RUN = re.compile(r'rtl-(32|128)k-(\d{8}T\d{6}Z)')
RTL_DONE = re.compile(r'collector_exit=0 postcheck_exit=0 archive_exit=0 finished=[0-9TZ]+')
RTL_MODE = {32: 'dmem32k', 128: 'dmem128k'}
RTL_GENERATION = 'chip-meters-g4'
RTL_OLD_GENERATIONS = ('contract2-g2', 'chip-meters-g3')   # their records load, their run archives are not re-imported
RTL_NOTE = 'registered after launch; the runs did not bind this definition'
RTL_TESTS = 'sw/device/tests/acc_uov'
RTL_BASELINE = f'{RTL_TESTS}/expected_insn_counts_32k.csv'
# the measuring tools of each generation's runs, by their names then
RTL_TOOLS_OF = {'contract2-g2': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py', 'tools/acc_bind.py'),
                'chip-meters-g3': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py', 'tools/check_firmware_kernels.py'),
                'chip-meters-g4': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py')}
RTL_TOOLS = RTL_TOOLS_OF[RTL_GENERATION]
SHA = re.compile(r'[0-9a-f]{64}')


# ---------------------------------------------------------------------------------------------
# Retry records: one sign kernel on a vector set with a known number of retries per case (e.g. retrygrid).
# Not part of any campaign, so they never replace a published KAT cell; the paper reads them on their own.

RETRY_KERNELS = {'ldirect': 32, 'sprec': 512}   # sign kernel -> the DMEM profile it is measured at
RETRY_TIER = 'bngfaes'
SIG_BYTES = {'Ip': 128, 'Ip3': 135, 'Is': 96}    # signature length of each parameter set (the specification)
CYCLES_MSG_LEN = 32                              # tab-cycles shows the KAT case with a message of this length
PAPER_KERNEL = {'stream_uniform': '\\kernel{uniform}$^\\dagger$', 'tuned': '\\kernel{tuned}$^\\dagger$'}   # cycles tables: the streamed kernels; \kernel = the paper's kernel-name style
PAPER_SET = {'Ip': 'uov-Ip-r2', 'Ip3': 'uov-Ip', 'Is': 'uov-Is'}    # paper tables: uov-Ip is the Round-3 set, as in the specification; Round 2 is marked


def kat_case_of_len(p, n, digest):
    """The KAT case of testvectors-<p>-pkc-skc whose message has n bytes (third line of a case: signature, message);
    refused unless the file is the one the records ran (digest: the sha256 they recorded for it)."""
    with open(gks.testvec_path(p), 'rb') as fh:
        data = fh.read()                                  # one read: the bytes hashed are the bytes parsed
    if hashlib.sha256(data).hexdigest() != digest:
        raise Refused(f'{gks.testvec_path(p)}: not the vector file the records ran')
    text = data.decode().split('\n')
    hits = [i // 3 for i in range(0, len(text) - 2, 3) if len(text[i + 2].strip()) // 2 - SIG_BYTES[p] == n]
    if len(hits) != 1:
        raise Refused(f'{gks.testvec_path(p)}: {len(hits)} cases with a {n}-byte message')
    return hits[0]


def retry_index_path(vectors):
    return f'{gks.HANDWRITTEN_DIR}/test_data/testvectors-{vectors}-index.csv'


def retry_index(vectors):
    """{param: [(key_case, msg_len, attempts), ...]} in case order, from test_data/testvectors-VECTORS-index.csv. Each
    row must describe its case of testvectors-<param>-pkc-skc.VECTORS: the key lines equal case key_case of key_file,
    the message has msg_len bytes."""
    out, lines = {}, {}
    td = os.path.dirname(retry_index_path(vectors))

    def three(name):
        if name not in lines:
            if not re.fullmatch(r'testvectors-[A-Za-z0-9.-]+', name):
                raise Stop(f'bad vector file name {name!r} in the index')
            text = read(os.path.join(td, name)).lower().split('\n')
            lines[name] = [text[i:i + 3] for i in range(0, len(text) - 2, 3)]
        return lines[name]
    for r in csv.DictReader(read(retry_index_path(vectors)).splitlines()):
        p, case, key = r['param'], int(r['case']), int(r['key_case'])
        cases = out.setdefault(p, [])
        if case != len(cases):
            raise Stop(f'{retry_index_path(vectors)}: {p} case {case} is out of order')
        vec = three(f'testvectors-{p}-pkc-skc.{vectors}')
        src = three(r['key_file'])
        if case >= len(vec) or key >= len(src) or vec[case][:2] != src[key][:2] \
                or len(vec[case][2]) // 2 - SIG_BYTES[p] != int(r['msg_len']):
            raise Stop(f'{retry_index_path(vectors)}: {p} case {case} does not describe its vector')
        cases.append((key, int(r['msg_len']), int(r['attempts'])))
    return out


def run_retry(a):
    """Exit 0: accepted and published, 1: a case failed or timed out, 2: stopped."""
    try:
        return 0 if retry_record(canonical(a.publish_to), a.kernel, a.vectors, a.params.split(','), a.workers,
                                 a.timeout) else 1
    except (Stop, Refused, OSError, ValueError) as e:
        print(f'uov.py: stopped: {e}', file=sys.stderr)
        return 2


def retry_record(checkout, kernel, vectors, params, workers, timeout):
    """Run one sign kernel (bngfaes) on a vector set in this tree and publish the record to the checkout.
    The tree must be a commit plus exactly the kernel's profile overlay; every case must pass, re-derive its count
    from its evidence and show the attempts of the index in the harness's counter; no input or frozen ELF may change."""
    if not re.fullmatch(r'[a-z0-9]+', vectors):
        raise Stop(f'bad vector set name {vectors!r}')
    gks.VECTORS = vectors
    try:
        return _retry_record(checkout, kernel, vectors, params, workers, timeout)
    finally:
        gks.VECTORS = None


def _retry_record(checkout, kernel, vectors, params, workers, timeout):
    profile, tier = RETRY_KERNELS[kernel], RETRY_TIER
    index = retry_index(vectors)
    for p in params:
        if p not in index:
            raise Stop(f'{p} has no cases in {retry_index_path(vectors)}')
        if gks.vector_cases(gks.testvec_path(p)) != len(index[p]):
            raise Stop(f'{gks.testvec_path(p)}: case count differs from the index')
    if len({len(index[p]) for p in params}) != 1:
        raise Stop('the parameter sets have different case counts; run them separately')
    head = git('rev-parse', 'HEAD').strip()
    overlay, config = profile_overlays(head, [profile])[str(profile)], tree_config(REPO)

    def drift():
        out = []
        if git('rev-parse', 'HEAD').strip() != head:
            out.append('HEAD moved')
        if git('diff', '--cached', '--name-only').strip():
            out.append('staged changes')
        if tree_overlay(REPO) != overlay:
            out.append(f'tracked changes are not exactly the {profile} KiB overlay '
                       f'(python3 tools/uov.py profile --profile {profile} on a clean tree)')
        if tree_config(REPO) != config:
            out.append('the local Bazel configuration changed')
        if actual_layout() != expected_layout(profile):
            out.append(f'the tree is not at the {profile} KiB profile')
        return out
    bad = drift()
    if bad:
        raise Stop('; '.join(bad))
    stamp = datetime.datetime.now(datetime.timezone.utc)
    run_id = f'retry-{profile}-{stamp:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}'
    run = os.path.join(REPO, RUNS, run_id)
    os.makedirs(run)
    created = now()
    log = os.path.join(run, 'build.log')
    rels = {p: gks.elf_of('sign', p, tier, kernel) for p in params}
    labels = {p: label_of(r) for p, r in rels.items()}
    index_rel = os.path.relpath(retry_index_path(vectors), REPO)

    key_files = {os.path.relpath(os.path.join(os.path.dirname(retry_index_path(vectors)), r['key_file']), REPO)
                 for r in csv.DictReader(read(retry_index_path(vectors)).splitlines())}

    def input_set():
        paths = {index_rel} | key_files
        for p in params:
            paths.update(input_paths({'op': 'sign', 'param': p, 'variant': kernel}, list(labels.values()), log))
        return sorted(paths)
    inputs = input_set()
    stray = untracked(inputs)
    if stray:
        raise Stop(f'untracked inputs: {stray}')
    before = hash_inputs(inputs)
    bep = os.path.join(run, 'build.bep.json')
    bazel('build', f'--build_event_json_file={bep}', *labels.values(), log=log)
    exec_root = bazel('info', 'execution_root', log=log).strip()
    files = bazel('cquery', '--output=files', 'set(' + ' '.join(f'"{lab}"' for lab in labels.values()) + ')',
                  log=log).split()
    picked = pick_elves(files, list(labels.values()))
    artifacts = {}
    for p, rel in rels.items():
        dst = os.path.join(run, 'bin', rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(exec_root, picked[labels[p]]), dst)   # a regular file
        artifacts[labels[p]] = {'param': p, 'elf': rel, 'sha256': sha256(dst), **elf_facts(dst)}
    n = len(index[params[0]])
    gather = [sys.executable, os.path.join(REPO, 'tools/gather_kat_stats.py'), '--out', os.path.join(run, 'kat'), '--fresh',
              '--ops', 'sign', '--params', ','.join(params), '--tiers', tier, '--variants', kernel, '--vectors', vectors,
              '--cases', f'0-{n - 1}', '--elf-root', os.path.join(run, 'bin'), '--workers', str(workers),
              '--timeout', str(timeout)]
    with open(os.path.join(run, 'collector.log'), 'w') as fh:
        collector_exit = subprocess.run(gather, cwd=REPO, stdout=fh, stderr=subprocess.STDOUT).returncode
    res = os.path.join(run, 'kat', 'results.csv')
    rows = list(csv.DictReader(read(res).splitlines())) if os.path.exists(res) else []
    # drift is checked before the verdict: a changed tree invalidates passes and failures alike
    after = input_set()
    bad = drift() + [f'untracked inputs: {u}' for u in [untracked(after)] if u]
    if after != inputs:
        bad.append(f'the input set changed: added {sorted(set(after) - set(inputs))}, removed {sorted(set(inputs) - set(after))}')
    bad += [f'input changed: {p}' for p, h in hash_inputs(inputs).items() if before[p] != h]
    bad += [f'the frozen ELF changed: {art["elf"]}' for art in artifacts.values()
            if sha256(os.path.join(run, 'bin', art['elf'])) != art['sha256']]
    if bad:
        raise Stop(f'run {run_id}: {"; ".join(bad)} (evidence in {RUNS}/{run_id})')
    cells = [('sign', p, tier, kernel, c) for p in params for c in range(n)]
    have = sorted((r['op'], r['param'], r['tier'], r['variant'], int(r['case'])) for r in rows)
    if have != sorted(cells) or not re.search(r'^DONE \d+/\d+ ', read(os.path.join(run, 'collector.log')), re.M):
        raise Stop(f'run {run_id}: the collector did not complete (exit {collector_exit}; see {RUNS}/{run_id}/collector.log)')
    failed = [f'{r["param"]} case {r["case"]} {r["kat"]}' for r in rows if r['kat'] != 'PASS']
    if failed:
        print(f'retry {kernel}: not accepted, {", ".join(failed)} (evidence in {RUNS}/{run_id}; a retry is a new run)')
        return False
    stats = os.path.join(run, 'kat', 'stats')
    bad = count_problems(stats, rows, lambda cell: gks.stats_name(*cell), None)
    for r in rows:
        attempts = index[r['param']][int(r['case'])][2]
        found = COUNTER.findall(read(os.path.join(stats, gks.stats_name('sign', r['param'], tier, kernel, int(r['case']))
                                                  + '.log')))
        if found != [str(attempts - 1)]:
            bad.append(f'{r["param"]} case {r["case"]}: attempt counter {found}, the index has {attempts} attempts')
    if collector_exit != 0 or bad:
        raise Stop(f'run {run_id}: collector exit {collector_exit} with every case PASS; {bad}')
    record = os.path.join(run, 'record')
    os.makedirs(os.path.join(record, 'cells'))
    table = [['kernel', 'profile', 'tier', 'param', 'case', 'key_case', 'msg_len', 'attempts', 'instructions', 'cycles']]
    for r in sorted(rows, key=lambda r: (r['param'], int(r['case']))):
        key_case, msg_len, attempts = index[r['param']][int(r['case'])]
        table.append([kernel, profile, tier, r['param'], r['case'], key_case, msg_len, attempts, r['instructions'], r['cycles']])
    buf = io.StringIO()
    csv.writer(buf, lineterminator='\n').writerows(table)
    texts = {'results.csv': buf.getvalue()}
    frozen = os.path.join(run, 'bin') + '/'
    for cell in cells:
        name = gks.stats_name(*cell)
        for raw, pub in EVIDENCE:
            text = read(os.path.join(stats, name + raw)).replace(frozen, '').replace(REPO + '/', '')
            texts[f'cells/{cell_stem(*cell)}{pub}'] = tidy(text)
    for rel, text in texts.items():
        with open(os.path.join(record, rel), 'w') as fh:
            fh.write(text)
    vec_files = sorted({os.path.relpath(gks.testvec_path(p), REPO) for p in params} | {index_rel})
    manifest = {
        'schema': 1, 'engine': 'retry', 'kind': 'retry', 'run': run_id, 'created': created, 'completed': now(),
        'kernel': kernel, 'profile': profile, 'tier': tier, 'params': params,
        'vectors': {f: before[f] for f in vec_files},
        'source': {'commit': head, 'overlay': overlay, 'config': config, 'inputs': before},
        'execution': {'python': sys.version.split()[0], 'bazel': bazel('--version').strip().splitlines()[-1],
                      'bazel_options': build_options(bep), 'collector': [os.path.relpath(x, REPO) if x.startswith(REPO) else x
                                                                         for x in gather[1:]],
                      'workers': workers, 'timeout': timeout},
        'layout': actual_layout(),
        'artifacts': artifacts,
        'results_sha256': hashlib.sha256(texts['results.csv'].encode()).hexdigest(),
        'completion': {'collector_exit': collector_exit, 'cells': len(rows), 'accepted': True},
    }
    manifest['evidence'] = {os.path.relpath(os.path.join(r, f), record): sha256(os.path.join(r, f))
                            for r, _, fs in os.walk(record) for f in fs}
    with open(os.path.join(record, 'manifest.json'), 'w') as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write('\n')
    final = os.path.join(checkout, RESULTS, run_id)
    with locked(os.path.join(checkout, LOCK)):
        if os.path.exists(final):
            raise Stop(f'{final} exists')
        staging = os.path.join(checkout, RESULTS, f'.staging-{run_id}')
        shutil.rmtree(staging, ignore_errors=True)
        shutil.copytree(record, staging)
        os.rename(staging, final)
    print(f'accepted {run_id}: sign/{kernel}/{tier}@{profile} on {vectors}, {len(rows)} cases PASS -> {final}')
    return True


def rtl_cells():
    """Every chip cell of the collector's catalog by its run-selection name: (profile, protocol, catalog cell)."""
    out = {}
    for profile, cells in ((32, gcm.CELLS), (128, gcm.ONESHOT_CELLS)):
        for c in cells:
            out[gcm.target(*c)[:-len('_sim_verilator')]] = (profile, gcm.expected_protocol(c[0], c[1], c[3]), c)
    return out


def rtl_key(cell, profile):
    return f'rtl:{cell}@{profile}'


def blob_sha256(rev, rel):
    """sha256 of a file as committed at rev; None if it is not there."""
    r = subprocess.run(['git', 'cat-file', 'blob', f'{rev}:{rel}'], cwd=REPO, capture_output=True)
    return None if r.returncode else hashlib.sha256(r.stdout).hexdigest()


def patched_overlay(rev, patch):
    """What a `git diff HEAD` patch changes when applied to rev: path -> [sha256 (None: deleted), git mode], added
    files included. Applied to a temporary index, never to a working tree."""
    with tempfile.TemporaryDirectory(prefix='uov-patch-') as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, 'index'))

        def run(*args):
            r = subprocess.run(['git', *args], cwd=REPO, env=env, capture_output=True)
            if r.returncode:
                raise Stop(f'git {args[0]} failed on {patch}: {r.stderr.decode(errors="replace").strip()[:300]}')
            return r.stdout
        run('read-tree', rev)
        if os.path.getsize(patch):
            run('apply', '--cached', patch)
        raw = run('diff-index', '--cached', '--raw', '--no-abbrev', '-z', rev).split(b'\0')
        out = {}
        for meta, name in zip(raw[0::2], raw[1::2]):
            _, mode, _, blob, status = meta.decode().lstrip(':').split()
            out[name.decode()] = [None, None] if status == 'D' else [hashlib.sha256(run('cat-file', 'blob', blob)).hexdigest(), mode]
        return out


def rtl_init(a):
    checkout = canonical(a.publish_to)
    path, done = campaign_files(checkout, a.name)
    if os.path.exists(path) or os.path.exists(done):
        fail(f'{path} exists; a definition is never rewritten')
    if git('status', '--porcelain', '--untracked-files=no').strip():
        fail('this tree has tracked changes; rtl-init records a clean tooling commit')
    r = subprocess.run(['git', 'rev-parse', '--verify', '--quiet', f'{a.measured_at}^{{commit}}'], cwd=REPO,
                       capture_output=True, text=True)
    if r.returncode:
        fail(f'--measured-at {a.measured_at} is not a commit of this repository')
    rev = r.stdout.strip()
    if not os.path.isfile(a.bazelrc_site):
        fail(f'--bazelrc-site {a.bazelrc_site} is not a file')
    baseline = blob_sha256(rev, RTL_BASELINE)
    if baseline is None:
        fail(f'{RTL_BASELINE} is not in {rev[:10]}')
    head = git('rev-parse', 'HEAD').strip()
    defn = {'schema': 1, 'engine': 'rtl', 'name': a.name, 'created': now(), 'note': RTL_NOTE, 'tooling_commit': head,
            'measuring_commit': rev, 'generation': RTL_GENERATION, 'config': {'.bazelrc-site': sha256(a.bazelrc_site)},
            'overlays': profile_overlays(head, sorted(RTL_MODE)), 'baseline': baseline,
            'cells': [{'profile': p, 'cell': name, 'protocol': proto} for name, (p, proto, _) in rtl_cells().items()]}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'x') as fh:
        json.dump(defn, fh, indent=1, sort_keys=True)
        fh.write('\n')
    print(f'wrote {path}: {len(defn["cells"])} cells measured at {rev[:10]}, tooling commit {head[:10]}; '
          f'commit it in {checkout}, then import the run directories')


def load_rtl_definition(checkout, name):
    """(definition, sha256 of its bytes) of an RTL registration, committed in the checkout as it stands."""
    path, _ = campaign_files(checkout, name)
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
        d = json.loads(raw)
    except (OSError, ValueError) as e:
        raise Stop(f'RTL definition {path}: {e}')
    keys = {'schema', 'engine', 'name', 'created', 'note', 'tooling_commit', 'measuring_commit', 'generation', 'config',
            'overlays', 'baseline', 'cells'}
    cells = [{'profile': p, 'cell': n, 'protocol': proto} for n, (p, proto, _) in rtl_cells().items()]
    if not isinstance(d, dict) or set(d) != keys or d['schema'] != 1 or d['engine'] != 'rtl' or d['name'] != name \
            or d['generation'] not in (RTL_GENERATION, *RTL_OLD_GENERATIONS) or d['cells'] != cells \
            or not all(re.fullmatch(r'[0-9a-f]{40}', str(d[k])) for k in ('tooling_commit', 'measuring_commit')) \
            or not SHA.fullmatch(str(d['baseline'])) or not isinstance(d['config'], dict) \
            or set(d['config']) != set(CONFIG_FILES) or not all(SHA.fullmatch(str(h)) for h in d['config'].values()) \
            or not isinstance(d['overlays'], dict) or set(d['overlays']) != {str(p) for p in RTL_MODE}:
        raise Stop(f'{path} is not an RTL definition with this collector\'s cells')
    if head_blob(checkout, os.path.relpath(path, checkout)) != raw:
        raise Stop(f'{path} is not committed in {checkout} as it stands')
    return d, hashlib.sha256(raw).hexdigest()


def rtl_csv(rows):
    """The published results.csv: the collector's own serialisation of its rows."""
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=gcm.ONESHOT_FIELDS, lineterminator='\n')
    w.writeheader()
    w.writerows(rows)
    return out.getvalue().encode()


def rtl_row_problems(cells, rows):
    """rows must be, cell by cell, the run roles of each cell's protocol in order, every verdict PASS."""
    cat = rtl_cells()
    want = []
    for name in cells:
        _, protocol, (op, family, param, tier) = cat[name]
        want += [(op, family or 'ldirect', param, tier, protocol, role, 'PASS') for role in gcm.PROTOCOL_RUNS[protocol]]
    have = [tuple(str(r.get(k)) for k in ('op', 'family', 'param', 'tier', 'protocol', 'run', 'verdict')) for r in rows]
    if have != want:
        return [f'rows are not the run roles of the cells, in order, all PASS ({len(have)} rows, {len(want)} expected)']
    meters = ('acc_insn', 'exec_wait', 'host_io_fold', 'op_total_v2', 'app_load')
    for r in rows:
        v = [str(r.get(k, '')) for k in meters]
        # exec_wait and host_io_fold are disjoint brackets inside op_total_v2
        ok = str(r.get('contract')) == '2' and all(re.fullmatch('[0-9]+', x) for x in v) and int(v[1]) + int(v[2]) <= int(v[3])
        if not ok:
            return [f'{r["op"]} {r["family"]} {r["param"]} {r["tier"]} {r["run"]}: not a meters v2 row with its counters']
    return []


def validate_rtl_bundle(bundle, defn, dsha, raw=None):
    """A published RTL record checked against its definition and one manifest snapshot: identity, source, its
    cells, the hash of results.csv and the rows that file must hold. Nothing is re-read from a run directory."""
    with open(os.path.join(bundle, 'manifest.json'), 'rb') as fh:
        own = fh.read()
    if raw is not None and own != raw:
        raise Refused(f'{bundle}: manifest.json is not the snapshot being checked')
    m = json.loads(own)
    keys = {'schema', 'engine', 'campaign', 'definition', 'run', 'profile', 'cells', 'source', 'tools', 'execution',
            'archive', 'completion', 'evidence'}
    name = RTL_RUN.fullmatch(str(m.get('run'))) if isinstance(m, dict) else None
    if not name or set(m) != keys or m['schema'] != 2 or m['engine'] != 'rtl' or m['campaign'] != defn['name'] \
            or m['definition'] != dsha or m['profile'] != int(name[1]):
        raise Refused(f'{bundle}: manifest identity')
    profile, cells = m['profile'], m['cells']
    mine = {c['cell'] for c in defn['cells'] if c['profile'] == profile}
    if not isinstance(cells, list) or not cells or len(set(map(str, cells))) != len(cells) or not set(map(str, cells)) <= mine:
        raise Refused(f'{m["run"]}: cells are not {profile} KiB cells of the definition')
    problems = []
    src, tools, ex, arch = m['source'], m['tools'], m['execution'], m['archive']
    if not isinstance(src, dict) or set(src) != {'commit', 'snapshot', 'overlay', 'config'} \
            or src['commit'] != defn['measuring_commit'] or src['overlay'] != defn['overlays'][str(profile)] \
            or src['config'] != defn['config'] or not SHA.fullmatch(str(src['snapshot'])):
        problems.append('source is not the definition\'s commit, overlay and configuration')
    if not isinstance(tools, dict) or set(tools) != {'measuring', 'publishing'} or tools['publishing'] != defn['tooling_commit'] \
            or not isinstance(tools['measuring'], dict) or set(tools['measuring']) != set(RTL_TOOLS_OF[defn['generation']]) \
            or not all(SHA.fullmatch(str(h)) for h in tools['measuring'].values()):
        problems.append('tools record')
    if not isinstance(ex, dict) or set(ex) != {'bazel', 'flags'} or not all(isinstance(v, str) and v for v in ex.values()):
        problems.append('execution record')
    if not isinstance(arch, dict) or set(arch) != {'done', 'inventory', 'files'} or not RTL_DONE.fullmatch(str(arch['done'])) \
            or not SHA.fullmatch(str(arch['inventory'])) or type(arch['files']) is not int or arch['files'] < 1:
        problems.append('archive record')
    evidence = m['evidence']
    on_disk = {os.path.relpath(os.path.join(r, f), bundle) for r, _, fs in os.walk(bundle) for f in fs}
    if not isinstance(evidence, dict) or set(evidence) != {'results.csv'} or on_disk != {'manifest.json', 'results.csv'}:
        problems.append('the record is not manifest.json and results.csv')
    elif sha256(os.path.join(bundle, 'results.csv')) != evidence['results.csv']:
        problems.append('results.csv differs from the hash in the manifest')
    else:
        with open(os.path.join(bundle, 'results.csv'), newline='') as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        if reader.fieldnames != list(gcm.ONESHOT_FIELDS):
            problems.append('results.csv columns')
        else:
            problems += rtl_row_problems(cells, rows)
        if m['completion'] != {'accepted': True, 'cells': len(cells), 'rows': len(rows),
                               'baseline': 'identical' if profile == 32 else None}:
            problems.append('completion record')
    if problems:
        raise Refused(f'{m["run"]}: {"; ".join(problems)}')
    return m


def rtl_completed(checkout, name, defn, dsha):
    """The RTL completion list, cell key -> {run, manifest}: every listed record checked, each listed with
    exactly its own cells, every profile present complete. Stop on any inconsistency."""
    _, path = campaign_files(checkout, name)
    if not os.path.exists(path):
        return {}
    try:
        done = json.loads(read(path))
        ok = (isinstance(done, dict) and set(done) == {'campaign', 'definition', 'cells'} and done['campaign'] == name
              and isinstance(done['cells'], dict))
    except ValueError:
        ok = False
    if not ok:
        raise Stop(f'{path} is not an RTL completion list')
    if done['definition'] != dsha:
        raise Stop(f'{path} belongs to another version of {name}')
    runs = {}
    for key, e in done['cells'].items():
        if not isinstance(e, dict) or set(e) != {'run', 'manifest'} or not RTL_RUN.fullmatch(str(e['run'])) \
                or not SHA.fullmatch(str(e['manifest'])) or runs.setdefault(e['run'], e['manifest']) != e['manifest']:
            raise Stop(f'completion list of {name}: bad entry {key}')
    for run, mhash in runs.items():
        bundle = os.path.join(checkout, RESULTS, run)
        try:
            with open(os.path.join(bundle, 'manifest.json'), 'rb') as fh:
                raw = fh.read()
        except OSError:
            raw = b''
        if hashlib.sha256(raw).hexdigest() != mhash:
            raise Stop(f'completion list of {name}: {run} is missing or altered')
        try:
            m = validate_rtl_bundle(bundle, defn, dsha, raw)
        except Refused as err:
            raise Stop(f'completion list of {name}: {err}')
        if m['run'] != run or {rtl_key(c, m['profile']) for c in m['cells']} != {k for k, e in done['cells'].items()
                                                                                 if e['run'] == run}:
            raise Stop(f'completion list of {name}: {run} is not listed with exactly its cells')
    partial = rtl_partial(defn, done['cells'])
    if partial:
        raise Stop(f'completion list of {name}: {partial}')
    return done['cells']


def rtl_partial(defn, keys):
    """'' if every profile that has a cell among keys has all of its cells, else what is missing."""
    out = []
    for p in sorted(RTL_MODE):
        want = {rtl_key(c['cell'], p) for c in defn['cells'] if c['profile'] == p}
        have = want & set(keys)
        if have and have != want:
            out.append(f'{p} KiB has {len(have)} of {len(want)} cells')
    return '; '.join(out)


def rtl_manifest(text):
    """manifest.txt of a run directory -> (its single-valued lines, its source hashes); a repeated line stops."""
    fields, sources = {}, {}
    for line in text.splitlines():
        kind, _, rest = line.partition(' ')
        if kind == 'source':
            parts = rest.rsplit(' ', 2)
            if len(parts) != 3 or parts[1] != 'sha256' or parts[0] in sources:
                raise Stop(f'manifest.txt: bad or repeated source line: {line[:120]}')
            sources[parts[0]] = parts[2]
        elif kind not in ('firmware', 'elf', 'runfile', 'fixture'):
            if kind in fields:
                raise Stop(f'manifest.txt: repeated {kind} line')
            fields[kind] = rest
    return fields, sources


def rtl_record(archive, defn, dsha):
    """One finished run directory -> (run id, cell keys, manifest.json bytes, results.csv bytes) of its record.
    Stop names why it is not importable. Everything decisive is read from a private copy whose bytes equal
    the run's inventory; recorded machine paths and command lines are never followed or executed."""
    archive = os.path.realpath(archive)
    run_id = os.path.basename(archive)
    name = RTL_RUN.fullmatch(run_id)
    if not name:
        raise Stop(f'{archive}: not a run directory name (rtl-<32|128>k-<stamp>)')
    profile, rev = int(name[1]), defn['measuring_commit']

    def stop(why):
        return Stop(f'{run_id}: {why}')
    def pinned():
        """(evidence.sha256, DONE) as they are now; b'' for one that cannot be read."""
        out = []
        for f in ('evidence.sha256', 'DONE'):
            try:
                with open(os.path.join(archive, f), 'rb') as fh:
                    out.append(fh.read())
            except OSError:
                out.append(b'')
        return out
    inv_bytes, done_bytes = pinned()                     # read before the verification; a change seen after it stops
    r = subprocess.run(['bash', os.path.join(REPO, 'tools/rtl_campaign.sh'), '--verify-only', archive],
                       capture_output=True, text=True)
    if r.returncode:
        raise stop(f'not a finished, intact run directory: {r.stderr.strip() or f"exit {r.returncode}"}')
    if pinned() != [inv_bytes, done_bytes]:
        raise stop('evidence.sha256 or DONE changed while the run directory was verified')
    done = done_bytes.decode()
    if not RTL_DONE.fullmatch(done.rstrip('\n')) or done.count('\n') != 1:
        raise stop('DONE is not one clean line')
    inventory = {}
    for line in inv_bytes.decode().splitlines():
        if not re.fullmatch(r'[0-9a-f]{64}  \./\S.*', line) or line[68:] in inventory:
            raise stop(f'bad or repeated inventory line: {line[:120]}')
        inventory[line[68:]] = line[:64]
    with tempfile.TemporaryDirectory(prefix='uov-rtl-') as snap:
        def take(*rels):
            for rel in rels:
                src = os.path.join(archive, rel)
                if rel not in inventory or os.path.realpath(src) != src or not os.path.isfile(src):
                    raise stop(f'{rel} is not a regular file of the inventory')
                with open(src, 'rb') as fh:
                    data = fh.read()
                if hashlib.sha256(data).hexdigest() != inventory[rel]:
                    raise stop(f'{rel} differs from the inventory')
                os.makedirs(os.path.dirname(os.path.join(snap, rel)), exist_ok=True)
                with open(os.path.join(snap, rel), 'wb') as fh:
                    fh.write(data)
        take('manifest.txt', 'tracked-changes.patch', 'untracked-files.txt', 'rtl_campaign.sh', 'results/run.json',
             'results/bep.json', *(['results/expected_insn_counts_32k.csv'] if profile == 32 else []))
        fields, sources = rtl_manifest(read(os.path.join(snap, 'manifest.txt')))
        need = ('stamp', 'generation', 'profile', 'head', 'snapshot', 'bazel', 'flags', 'cells')
        if any(k not in fields for k in need):
            raise stop(f'manifest.txt lacks {[k for k in need if k not in fields]}')
        if (fields['stamp'], fields['profile'], fields['generation']) != (name[2], name[1], defn['generation']):
            raise stop('manifest.txt stamp, profile or generation is not this run\'s')
        if fields['head'] != rev:
            raise stop(f'measured at {fields["head"][:10]}, the definition says {rev[:10]}')
        if os.path.getsize(os.path.join(snap, 'untracked-files.txt')):
            raise stop('the measuring tree had untracked files')
        if patched_overlay(rev, os.path.join(snap, 'tracked-changes.patch')) != defn['overlays'][str(profile)]:
            raise stop(f'the tree\'s tracked changes are not exactly the {profile} KiB overlay')
        tests = subprocess.run(['git', 'ls-tree', '--name-only', rev, RTL_TESTS + '/'], cwd=REPO, check=True,
                               capture_output=True, text=True).stdout.split('\n')
        want = {'.bazelrc', '.bazelversion', 'MODULE.bazel.lock', *RTL_TOOLS, *CONFIG_FILES,
                *([RTL_BASELINE] if profile == 32 else []),
                *(t for t in tests if re.fullmatch(r'.*/([^/]*_test\.c|gen_[^/]*_testvec\.py|BUILD|uov_test\.bzl)', t))}
        if set(sources) != want:
            raise stop(f'recorded sources: missing {sorted(want - set(sources))}, unexpected {sorted(set(sources) - want)}')
        drift = [p for p, h in sources.items()
                 if h != (defn['config'][p] if p in CONFIG_FILES else blob_sha256(rev, p))]
        if drift:
            raise stop(f'recorded sources differ from {rev[:10]} or the definition\'s configuration: {sorted(drift)}')
        if sha256(os.path.join(snap, 'rtl_campaign.sh')) != sources['tools/rtl_campaign.sh']:
            raise stop('the frozen runner is not the recorded one')
        bazel = fields['bazel']
        if not bazel:
            # runners before the fix probed `bazel --version` after --output_base and recorded nothing; the run's own
            # build event log, an inventoried file, names the Bazel that executed it
            seen = set()
            for line in read(os.path.join(snap, 'results/bep.json')).splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                v = e.get('started', {}).get('buildToolVersion') if isinstance(e, dict) else None
                if v:
                    seen.add(v)
            if len(seen) != 1:
                raise stop(f'manifest.txt records no Bazel version and the build event log names {sorted(seen) or "none"}')
            bazel = f"bazel {seen.pop()} (from the run's build event log; its manifest recorded no version)"
        with open(os.path.join(snap, 'results/run.json')) as fh:
            cells = json.load(fh).get('cells')
        mine = {c['cell'] for c in defn['cells'] if c['profile'] == profile}
        if not isinstance(cells, list) or not cells or cells != fields['cells'].split() or not set(cells) <= mine \
                or len(set(cells)) != len(cells):
            raise stop(f'run.json and manifest.txt do not name the same {profile} KiB cells of the definition')
        take(*(f'results/logs/{c}_sim_verilator/{f}' for c in cells for f in ('test.log', 'test.xml')))
        try:
            run, _, rows, gate = gcm.replay(os.path.join(snap, 'results'), RTL_MODE[profile])
        except SystemExit as e:
            raise stop(f'not re-readable: {e}')
    problems = rtl_row_problems(cells, rows)
    if run.get('bazel_exit') != 0:
        problems.append(f'bazel exit {run.get("bazel_exit")}')
    if profile == 32 and (run.get('baseline') != defn['baseline'] or gate is None or any(gate.values())):
        problems.append('the baseline gate is not the definition\'s ledger with every cell identical')
    data = rtl_csv(rows)
    try:
        with open(os.path.join(archive, 'results', f'results_{profile}k.csv'), 'rb') as fh:
            if fh.read() != data:
                problems.append('the run\'s own csv is not what its logs re-read to')
    except OSError as e:
        problems.append(f'the run\'s own csv: {e}')
    if re.search(r'(?:^|[\s=,:])/(?!/)\S', f'{bazel} {fields["flags"]}'):
        problems.append('the recorded Bazel flags name a path of the measuring machine')
    if problems:
        raise stop('; '.join(problems))
    manifest = {'schema': 2, 'engine': 'rtl', 'campaign': defn['name'], 'definition': dsha, 'run': run_id,
                'profile': profile, 'cells': cells,
                'source': {'commit': rev, 'snapshot': fields['snapshot'], 'overlay': defn['overlays'][str(profile)],
                           'config': {f: sources[f] for f in CONFIG_FILES}},
                'tools': {'measuring': {t: sources[t] for t in RTL_TOOLS}, 'publishing': defn['tooling_commit']},
                'execution': {'bazel': bazel, 'flags': fields['flags']},
                'archive': {'done': done.rstrip('\n'), 'inventory': hashlib.sha256(inv_bytes).hexdigest(),
                            'files': len(inventory)},
                'completion': {'accepted': True, 'cells': len(cells), 'rows': len(rows),
                               'baseline': 'identical' if profile == 32 else None},
                'evidence': {'results.csv': hashlib.sha256(data).hexdigest()}}
    text = json.dumps(manifest, indent=1, sort_keys=True) + '\n'
    return run_id, {rtl_key(c, profile) for c in cells}, text.encode(), data


def rtl_publish(checkout, name, dsha, records):
    """Install the records and list their cells in one step, under the checkout's lock: the definition and every
    listed record are checked again, a cell may come from one run only, and each profile is published whole
    or not at all. A record already installed with the same bytes is accepted, so a retry finishes an
    interrupted import; nothing that is listed is ever replaced."""
    results = os.path.join(checkout, RESULTS)
    if len({run_id for run_id, *_ in records}) != len(records):
        raise Stop('a run directory is given twice')
    with locked(os.path.join(checkout, LOCK)):
        defn, now_sha = load_rtl_definition(checkout, name)
        if now_sha != dsha:
            raise Stop(f'{name} changed since the run directories were read')
        done = rtl_completed(checkout, name, defn, dsha)
        new = dict(done)
        for run_id, keys, manifest, data in records:
            entry = {'run': run_id, 'manifest': hashlib.sha256(manifest).hexdigest()}
            mine = {k for k, e in new.items() if e['run'] == run_id}
            if mine and (mine != keys or any(new[k] != entry for k in mine)):
                raise Stop(f'{run_id} is already listed as another record')
            taken = sorted(k for k in keys - mine if k in new)
            if taken:
                raise Stop(f'{run_id}: {len(taken)} cells are already published from another record, e.g. {taken[0]} '
                           f'from {new[taken[0]]["run"]}')
            new.update(dict.fromkeys(keys, entry))
        partial = rtl_partial(defn, new)
        if partial:
            raise Stop(f'nothing published: {partial}; a profile is published only with all its cells')
        staged = []
        try:
            for run_id, keys, manifest, data in records:
                final = os.path.join(results, run_id)
                staging = os.path.join(results, f'.staging-{run_id}')
                shutil.rmtree(staging, ignore_errors=True)
                staged.append(staging)
                os.makedirs(staging)
                for fname, content in (('manifest.json', manifest), ('results.csv', data)):
                    with open(os.path.join(staging, fname), 'wb') as fh:
                        fh.write(content)
                for d in (staging, *([final] if os.path.exists(final) else [])):
                    try:                             # the manifest's csv hash was taken from the re-read rows
                        validate_rtl_bundle(d, defn, dsha, manifest)
                    except (Refused, OSError, ValueError) as e:
                        raise Stop(f'not published: {e}')
            for (run_id, *_), staging in zip(records, staged):
                final = os.path.join(results, run_id)
                if os.path.exists(final):                   # the same record, checked above
                    shutil.rmtree(staging)
                else:
                    os.rename(staging, final)
        finally:
            for staging in staged:
                shutil.rmtree(staging, ignore_errors=True)
        if new != done:
            _, done_path = campaign_files(checkout, name)
            write_atomic(done_path, json.dumps({'campaign': name, 'definition': dsha, 'cells': new},
                                               indent=1, sort_keys=True) + '\n')
    return new


def run_rtl_import(a):
    checkout = canonical(a.publish_to)
    try:
        defn, dsha = load_rtl_definition(checkout, a.campaign)
        if git('rev-parse', 'HEAD').strip() != defn['tooling_commit'] \
                or git('status', '--porcelain', '--untracked-files=no').strip():
            raise Stop(f'import from a clean tree at the definition\'s tooling commit {defn["tooling_commit"][:10]}')
        records = [rtl_record(d, defn, dsha) for d in a.archive]
        listed = rtl_publish(checkout, a.campaign, dsha, records)
    except (Stop, Refused, OSError, ValueError) as e:
        print(f'uov.py: stopped: {e}', file=sys.stderr)
        return 2
    print(f'{a.campaign}: {len(listed)} of {len(defn["cells"])} cells published; this call: '
          + ', '.join(f'{run_id} ({len(keys)})' for run_id, keys, *_ in records))
    return 0


# ---------------------------------------------------------------------------------------------
# README tables: written from the published records, never typed. A tracked Markdown file marks a table with
#   <!-- table:NAME -->
#   <!-- /table:NAME -->
# on lines of their own, and `tables` rewrites what lies between. NAME is one of
#   iss:OP/VARIANT@PROFILE[:PARAM,...]   ISS cycles of one kernel family: a row per tier, a column per parameter set
#   iss-speedup:...                      the same grid as speed-up over the sw tier
#   mem:OP/VARIANT@PROFILE[:PARAM,...]   memory of the ELFs those runs measured
#   rtl:OP/FAMILY@PROFILE[:PARAM,...]    chip-RTL meters of each test's accepting run
#   rtl-cycles:...                       exec+wait alone: a row per tier, a column per parameter set
#   rtl-speedup:..., rtl-speedup-op:...  times faster than the sw tier on the chip: exec+wait, or the whole operation
#   rtl-runs:...                         exec+wait of every timed run of each test (restarts, resident-key runs)
#   rtl-iss:...                          each test's ACC instruction count against the ISS cases of the same kernel
#   iss:all@PROFILE, rtl:all@PROFILE     every kernel family, or every chip test with meters, of a DMEM profile
#   iss-speedup:all, rtl-speedup:all, rtl-speedup-op:all
#                                        every family with an sw tier, of every profile (or of one: @PROFILE)
#   iss-ratio:OP/A@PROFILE/B@PROFILE     ISS cycles of family A divided by those of family B, per parameter set and tier
#   iss-retries:all                      every published KAT case in which signing needed a retry, with its cycles
#   iss-retries-speedup:all              the same cases as speed-up over the sw tier only (no cycles)
# with the names of tools/gather_kat_stats.py (ISS) and tools/gather_chip_matrix.py (RTL; sign's family is ldirect).
# A cell comes from the newest campaign that published it; a table is written only if all of its cells are published.
# Every grid leads with its DMEM profile. A KAT case in which signing needed a retry is shown only by iss-retries.
# A speed-up or ratio row uses the records of one campaign: re-measuring part of a row refuses it until the rest is in.

MARK = re.compile(r'^<!-- table:(\S+) -->\n(?:.*\n)*?<!-- /table:\1 -->\n', re.M)
TABLE = re.compile(r'(iss|iss-speedup|iss-ratio|iss-retries|iss-retries-speedup|mem|rtl|rtl-cycles|rtl-speedup|rtl-speedup-op|rtl-runs|rtl-iss)'
                   r':(?:all|(keygen|sign|verify)/(\w+))(?:@(\d+)(?:/(\w+)@(\d+))?)?(?::(\w+(?:,\w+)*))?')
# what one published ISS number covers, by measurement protocol
MEASURES = {'keygen-single-execution-kat': 'one key generation (a single EXECUTE)',
            'stream-keygen-kat': 'one key generation (INIT and every window, summed)',
            'stream-verify-accept': 'one accepting verification (INIT, the updates and FINAL, summed)',
            'oneshot-verify-resident-accept': 'one accepting verification with the key already installed',
            'sign-kat': 'one signature (a single EXECUTE)'}
# chip test families whose ISS variant of the same name runs the same ELF (sign's chip app is its own harness: no twin)
RTL_TWIN = {'stream', 'stream_uniform', 'min', 'sp', 'full'}
RTL_METERS = (('acc_insn', 'ACC instructions'), ('exec_wait', 'exec+wait'), ('host_io_fold', 'host I/O + fold'),
              ('op_total_v2', 'whole operation'), ('app_load', 'app load'))
# the shipping kernel's name in the tables (ISS variant and chip family stream); markers and records keep theirs
SHOWN = {'stream': 'tuned'}
SPEEDUP_TIERS = ('bngfonly', 'bnaesonly', 'bngfaes')         # sw is the baseline
SPEEDUP_TITLE = 'Times faster than sw (sw cycles / tier cycles), {}\n\n'
SPEEDUP_METERS = {
    'exec_wait': ('chip, exec+wait', 'exec+wait: Ibex cycles over EXECUTE and the wait for the ACC to finish, summed over the phases. '),
    'op_total_v2': ('chip, whole operation', 'The whole operation: from the first input write to the last result read, the host\'s '
                    'transfers included (for the stream keygens, tuned and stream_uniform, also the host\'s fold; in the verify '
                    'full tests this run also installs the key). ')}
COUNTER = re.compile(r'^\s*Counter \(GPR x8\): (.*)$', re.M)   # the sign harness's attempt counter, in its driver output
RETRY_NOTE = ('a case in which signing needed a retry is left out; it is in the retry table of '
              '`sw/acc/crypto/handwritten/uov/results/README.md`')


def span(values):
    lo, hi = min(values), max(values)
    return f'{lo:,}' if lo == hi else f'{lo:,}-{hi:,}'


def cases_text(cases):
    """[0,1,2,5] -> '0-2,5'"""
    out, start = [], None
    for i, c in enumerate(cases):
        if start is None:
            start = c
        if i + 1 == len(cases) or cases[i + 1] != c + 1:
            out.append(f'{start}' if start == c else f'{start}-{c}')
            start = None
    return ','.join(out)


def published(checkout):
    """{'iss': {cohort key: (campaign, run)}, 'rtl': {cell key: (campaign, run)}} over every campaign of the
    checkout that has a completion list. Every listed record is validated first (Stop on
    any inconsistency); where two campaigns hold the same cell, the one defined later wins."""
    d = os.path.join(checkout, CAMPAIGNS)
    camps = []
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not f.endswith('.completed.json'):
            continue
        name = f[:-len('.completed.json')]
        path, _ = campaign_files(checkout, name)
        try:
            rtl = json.loads(read(path)).get('engine') == 'rtl'
        except (OSError, ValueError, AttributeError) as e:
            raise Stop(f'campaign definition {path}: {e}')
        defn, dsha = (load_rtl_definition if rtl else load_definition)(checkout, name)
        done = (rtl_completed if rtl else completed_records)(checkout, name, defn, dsha)
        try:
            when = datetime.datetime.fromisoformat(defn['created']).timestamp()
        except (TypeError, ValueError):
            raise Stop(f'{path}: created is not a date')
        camps.append((when, name, 'rtl' if rtl else 'iss', done))
    out = {'iss': {}, 'rtl': {}}
    for _, name, engine, done in sorted(camps, key=lambda c: c[:2]):       # oldest first: a later one overwrites
        out[engine].update({key: (name, e['run']) for key, e in done.items()})
    return out


def record_of(pub, engine, key, results_dir):
    """(campaign, manifest, rows of results.csv) of the record that published key; Refused if none did."""
    if key not in pub[engine]:
        raise Refused(f'nothing published for {key}')
    name, run = pub[engine][key]
    bundle = os.path.join(results_dir, run)
    return (name, json.loads(read(os.path.join(bundle, 'manifest.json'))),
            list(csv.DictReader(read(os.path.join(bundle, 'results.csv')).splitlines())))


def measured_days(m):
    """ISS: the day the record completed; RTL: the days the run started and finished (Europe/Berlin)."""
    if m['engine'] == 'iss':
        return [m['completed'][:10]]
    stamps = [RTL_RUN.fullmatch(m['run'])[2], re.search(r'finished=(\d{8}T\d{6}Z)', m['archive']['done'])[1]]
    return [datetime.datetime.strptime(s, '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
            .astimezone(ZoneInfo('Europe/Berlin')).date().isoformat() for s in stamps]


def source_note(recs):
    """The closing line of a table: when and at which commit its records (campaign, manifest) were measured."""
    days = sorted(d for _, m in recs for d in measured_days(m))
    when = days[0] if days[0] == days[-1] else f'{days[0]} to {days[-1]}'
    commits = ', '.join(f'`{c}`' for c in sorted({m['source']['commit'][:10] for _, m in recs}))
    return f'Measured {when} at {commits} ({", ".join(sorted({name for name, _ in recs}))}).\n'


def iss_cells(pub, results_dir, op, variant, profile, only=None):
    """(params, tiers, {(tier, param): (campaign, manifest, rows)}) of one catalog family; every row carries its retries."""
    cat = gks.CAMPAIGN.get((profile, op, variant))
    if cat is None or (only and not set(only) <= set(cat[0])):
        raise Refused(f'no ISS family {op}/{variant}@{profile}' + (f' with {",".join(only)}' if only else ''))
    params = [p for p in cat[0] if not only or p in only]
    cells = {(t, p): record_of(pub, 'iss', cohort_key({'op': op, 'variant': variant, 'tier': t, 'param': p,
                                                        'profile': profile}), results_dir)
             for t in cat[1] for p in params}
    for (t, p), (_, m, rows) in cells.items():
        for r in rows:
            r['retries'] = retries(results_dir, m, op, p, t, variant, int(r['case']))
    return params, cat[1], cells


def retries(results_dir, m, op, p, t, v, case):
    """Retries of one published case: the sign harness's attempt counter x8 (0: the first attempt signed); 0 for
    keygen and verify, which have none."""
    if op != 'sign':
        return 0
    try:
        found = COUNTER.findall(read(os.path.join(results_dir, m['run'], 'cells', cell_stem(op, p, t, v, case) + '.driver.txt')))
    except OSError as e:
        raise Refused(f'{m["run"]}: {e}')
    if len(found) != 1 or not re.fullmatch('[0-9]+', found[0]):
        raise Refused(f'{m["run"]}: case {case} has no single attempt counter in its driver output')
    return int(found[0])


def one_source(group, one_campaign):
    """Refused unless the records of group [(campaign, manifest, rows)] ran on the same vectors and, for a ratio, come
    from one campaign."""
    runs = ', '.join(sorted({m['run'] for _, m, _ in group}))
    if len({json.dumps(m['source']['vectors'], sort_keys=True) for _, m, _ in group}) != 1:
        raise Refused(f'{runs}: not the same vectors')
    if one_campaign and len({name for name, _, _ in group}) != 1:
        raise Refused(f'{runs}: a ratio over the records of more than one campaign')
    return runs


def kept_cases(group, one_campaign=False):
    """The KAT cases a range or a ratio over group [(campaign, manifest, rows)] uses: all of its records ran the same
    cases on the same vectors, and a case in which any of them retried leaves the whole group."""
    runs = one_source(group, one_campaign)
    if len({frozenset(r['case'] for r in rows) for _, _, rows in group}) != 1:
        raise Refused(f'{runs}: not the same KAT cases')
    keep = {int(r['case']) for r in group[0][2]} - {int(r['case']) for _, _, rows in group for r in rows if r['retries']}
    if not keep:
        raise Refused(f'{runs}: every case needed a retry')
    return keep


def shown_rows(cells, tiers, params):
    """{(tier, param): the rows a cycle table shows}: every case but one in which a tier of that parameter set retried."""
    keep = {p: kept_cases([cells[t, p] for t in tiers]) for p in params}
    return {(t, p): [r for r in cells[t, p][2] if int(r['case']) in keep[p]] for t in tiers for p in params}


def total(rec, keep):
    return sum(int(r['cycles']) for r in rec[2] if int(r['case']) in keep)


def profile_note(profile):
    return f'{profile} KiB DMEM profile' + ('' if profile in RTL_MODE else ' (ISS only: no chip test runs at this profile)')


def cycles_note(what, recs, shown):
    """The caption of an ISS cycle table over the records recs, whose cells show the rows in shown."""
    ran = max(len(rows) for _, _, rows in recs)
    fewer = sorted({len(rows) for rows in shown} - {ran})
    ranged = any(len({r['cycles'] for r in rows}) > 1 for rows in shown)
    counted = f'{ran} KAT cases' + (f' ({span(fewer)} where {RETRY_NOTE})' if fewer else '')
    return (f'\n\nISS cycles of {what}; '
            + (f'a range is the lowest and the highest of the {counted}' if ranged else f'the same in all {counted}')
            + '.\nEvery case passed. ' + source_note([(name, m) for name, m, _ in recs]))


def iss_table(pub, results_dir, op, variant, profile, only):
    params, tiers, cells = iss_cells(pub, results_dir, op, variant, profile, only)
    shown = shown_rows(cells, tiers, params)
    lines = ['| DMEM | tier | ' + ' | '.join(params) + ' |', '|---|---|' + '---:|' * len(params)]
    for t in tiers:
        lines.append(f'| {profile} KiB | {t} | ' + ' | '.join(span([int(r['cycles']) for r in shown[t, p]]) for p in params) + ' |')
    return '\n'.join(lines) + cycles_note(f'{MEASURES[gks.PROTOCOL[op, variant]]}, {profile_note(profile)}',
                                          list(cells.values()), list(shown.values()))


def times(a, b):
    """a / b as a speed-up: three significant digits, e.g. 60.1x, 3.32x, 154x."""
    return f'{float(f"{a / b:.3g}"):g}x'


def speedups(cells, tiers, p, base='sw'):
    """{tier: times faster than base} of parameter set p, over the cases in which no tier retried."""
    keep = kept_cases([cells[t, p] for t in tiers], one_campaign=True)
    return {t: times(total(cells[base, p], keep), total(cells[t, p], keep)) for t in tiers if t != base}


def sums_note(recs, how=''):
    """The first caption line of a ratio of ISS sums over the records recs [(campaign, manifest, rows)]."""
    retried = any(r['retries'] for _, _, rows in recs for r in rows)
    return f'\n\nThe cycles of the KAT cases added up per row{how}' + (f'; {RETRY_NOTE}' if retried else '') + '.'


def speedup_note(what, recs):
    return sums_note(recs, ', sw divided by the tier') + ' -: no run of that tier.\n' + what + source_note([(n, m) for n, m, _ in recs])


def iss_speedup(pub, results_dir, op, variant, profile, only):
    if 'sw' not in gks.CAMPAIGN.get((profile, op, variant), ((), ('sw',)))[1]:
        raise Refused(f'{op}/{variant}@{profile} has no sw tier to compare with')
    params, tiers, cells = iss_cells(pub, results_dir, op, variant, profile, only)
    by = {p: speedups(cells, tiers, p) for p in params}
    lines = ['| DMEM | tier | ' + ' | '.join(params) + ' |', '|---|---|' + '---:|' * len(params)]
    for t in SPEEDUP_TIERS:
        if t in tiers:
            lines.append(f'| {profile} KiB | {t} | ' + ' | '.join(by[p][t] for p in params) + ' |')
    return SPEEDUP_TITLE.format('ISS') + '\n'.join(lines) + speedup_note(f'ISS, {profile_note(profile)}. ', list(cells.values()))


def iss_speedup_all(pub, results_dir, profile):
    """Times faster than sw of every family with an sw tier, of one profile or of all."""
    families = sorted((f for f, (_, tiers) in gks.CAMPAIGN.items() if 'sw' in tiers and profile in (None, f[0])),
                      key=lambda f: (f[0], OP_ORDER[f[1]], SHOWN.get(f[2], f[2])))
    if not families:
        raise Refused('no family with an sw tier' + (f' at {profile} KiB' if profile is not None else ''))
    lines = ['| DMEM | op | kernel | param | ' + ' | '.join(SPEEDUP_TIERS) + ' |', '|---|---|---|---|' + '---:|' * len(SPEEDUP_TIERS)]
    recs = []
    for pr, op, v in families:
        params, tiers, cells = iss_cells(pub, results_dir, op, v, pr)
        recs += cells.values()
        for p in params:
            by = speedups(cells, tiers, p)
            lines.append(f'| {pr} KiB | {op} | {SHOWN.get(v, v)} | {p} | ' + ' | '.join(by.get(t, '-') for t in SPEEDUP_TIERS) + ' |')
    return SPEEDUP_TITLE.format('ISS') + '\n'.join(lines) + speedup_note('ISS. ', recs)


def iss_ratio(pub, results_dir, op, a, pa, b, pb, only):
    """ISS cycles of family a at profile pa divided by those of family b at profile pb, per parameter set and tier."""
    if gks.PROTOCOL.get((op, a)) != gks.PROTOCOL.get((op, b)):
        raise Refused(f'{op}/{a} and {op}/{b}: protocols differ ({gks.PROTOCOL.get((op, a))}, {gks.PROTOCOL.get((op, b))})')
    params_a, tiers_a, ca = iss_cells(pub, results_dir, op, a, pa, only)
    params_b, tiers_b, cb = iss_cells(pub, results_dir, op, b, pb, only)
    params = [p for p in params_a if p in params_b]
    tiers = [t for t in SPEEDUP_TIERS + ('sw',) if t in tiers_a and t in tiers_b]
    if not params or not tiers:
        raise Refused(f'{op}/{a}@{pa} and {op}/{b}@{pb} share no parameter set and tier')
    name_a, name_b = SHOWN.get(a, a), SHOWN.get(b, b)
    dmem = f'{pa} KiB' if pa == pb else f'{name_a} {pa} KiB, {name_b} {pb} KiB'
    lines = ['| DMEM | op | param | ' + ' | '.join(tiers) + ' |', '|---|---|---|' + '---:|' * len(tiers)]
    used = [rec for t in tiers for p in params for rec in (ca[t, p], cb[t, p])]
    for p in params:
        keep = kept_cases([rec for t in tiers for rec in (ca[t, p], cb[t, p])], one_campaign=True)
        lines.append(f'| {dmem} | {op} | {p} | ' + ' | '.join(f'{total(ca[t, p], keep) / total(cb[t, p], keep):.2f}x' for t in tiers) + ' |')
    return (f'{name_a} / {name_b} (ISS cycles of {name_a} divided by those of {name_b}; above 1.00x, {name_b} is faster)\n\n'
            + '\n'.join(lines) + sums_note(used) + ' Two decimals: 1.00x is within half a percent, not necessarily equal.\nISS. '
            + source_note([(n, m) for n, m, _ in used]))


def iss_retries(pub, results_dir, ratios=False):
    """Every published KAT case in which signing needed a retry: every tier of its family and parameter set with its
    cycles, or (ratios) one row per case with each tier's speed-up over sw in that case."""
    lines = (['| DMEM | op | kernel | param | KAT case | retries | ' + ' | '.join(SPEEDUP_TIERS) + ' |',
              '|---|---|---|---|---:|---:|' + '---:|' * len(SPEEDUP_TIERS)] if ratios else
             ['| DMEM | op | kernel | param | tier | KAT case | retries | ISS cycles | times faster than sw, same case |',
              '|---|---|---|---|---|---:|---:|---:|---:|'])
    recs = []
    for pr, op, v in sorted(gks.CAMPAIGN, key=lambda f: (f[0], OP_ORDER[f[1]], SHOWN.get(f[2], f[2]))):
        params, tiers, cells = iss_cells(pub, results_dir, op, v, pr)
        for p in params:
            for c in sorted({int(r['case']) for t in tiers for r in cells[t, p][2] if r['retries']}):
                one_source([cells[t, p] for t in tiers], one_campaign=True)       # its sw column divides within the row
                row = {t: next(r for r in cells[t, p][2] if int(r['case']) == c) for t in tiers}
                if ratios:
                    if 'sw' in row:                                 # a family without an sw run has no speed-up
                        recs += [cells[t, p][:2] for t in tiers]
                        n = {r['retries'] for r in row.values()}
                        lines.append(f'| {pr} KiB | {op} | {SHOWN.get(v, v)} | {p} | {c} | {n.pop() if len(n) == 1 else "-"} | ' + ' | '.join(
                            times(int(row['sw']['cycles']), int(row[t]['cycles'])) if t in row else '-' for t in SPEEDUP_TIERS) + ' |')
                    continue
                for t in [t for t in SPEEDUP_TIERS + ('sw',) if t in row]:
                    recs.append(cells[t, p][:2])
                    sw = times(int(row['sw']['cycles']), int(row[t]['cycles'])) if 'sw' in row and t != 'sw' else '-'
                    lines.append(f'| {pr} KiB | {op} | {SHOWN.get(v, v)} | {p} | {t} | {c} | {row[t]["retries"]} '
                                 f'| {int(row[t]["cycles"]):,} | {sw} |')
    if not recs:
        return 'No published KAT case needed a retry' + (' in a family with an sw run' if ratios else '') + '.\n'
    if ratios:
        return (SPEEDUP_TITLE.format('ISS, the KAT cases in which signing needed a retry') + '\n'.join(lines)
                + '\n\nsw divided by the tier in that one case; its cycles are in the retry table of '
                  '`sw/acc/crypto/handwritten/uov/results/README.md`. retries: - where the tiers\' counts differ. '
                  'In a tier column, -: no run of that tier.\nISS. ' + source_note(recs))
    return ('KAT cases in which signing needed a retry\n\n' + '\n'.join(lines)
            + '\n\nretries: the attempts after the first, from the sign loop\'s counter (x8) in the driver output. The tables '
              'without retries leave these cases out.\nISS. ' + source_note(recs))


def iss_all(pub, results_dir, profile):
    """Every ISS family of a profile, one row per family and tier."""
    families = [(op, v) for (p, op, v) in gks.CAMPAIGN if p == profile]
    if not families:
        raise Refused(f'no ISS family at {profile} KiB')
    params = [p for p in gks.PARAMS3 if any(p in gks.CAMPAIGN[profile, op, v][0] for op, v in families)]
    lines = ['| DMEM | op | kernel | tier | ' + ' | '.join(params) + ' |', '|---|---|---|---|' + '---:|' * len(params)]
    recs, shown = [], []
    for op, v in sorted(families, key=lambda f: (OP_ORDER[f[0]], SHOWN.get(f[1], f[1]))):
        mine, tiers, cells = iss_cells(pub, results_dir, op, v, profile)
        rows = shown_rows(cells, tiers, mine)
        recs += cells.values()
        shown += rows.values()
        for t in tiers:
            lines.append(f'| {profile} KiB | {op} | {SHOWN.get(v, v)} | {t} | ' + ' | '.join(
                span([int(r['cycles']) for r in rows[t, p]]) if p in mine else '-' for p in params) + ' |')
    return '\n'.join(lines) + cycles_note(f'one operation per kernel family, {profile_note(profile)}', recs, shown)


def mem_table(pub, results_dir, op, variant, profile, only):
    params, tiers, cells = iss_cells(pub, results_dir, op, variant, profile, only)
    facts = {}
    for key, (_, m, _) in cells.items():
        (art,) = m['artifacts'].values()
        code = [size for addr, size, _ in art['segments'] if addr != m['profile']['dmem_address']]
        if len(code) != 1:
            raise Refused(f'{m["run"]}: {len(code)} load segments outside the DMEM')
        facts[key] = (code[0], art['dmem_bss_end'], art.get('stack_reserved'))
    stack = any(f[2] is not None for f in facts.values())
    lines = ['| DMEM | tier | ' + ' | '.join(params) + ' |', '|---|---|' + '---:|' * len(params)]
    for t in tiers:
        lines.append(f'| {profile} KiB | {t} | ' + ' | '.join(' / '.join('-' if v is None else f'{v:,}' for v in facts[t, p][:3 if stack else 2])
                                                              for p in params) + ' |')
    return '\n'.join(lines) + (f'\n\nBytes of the ELFs the ISS ran at the {profile_note(profile)}: code / `_dmem_bss_end` (the end of the linked data and bss)'
                               + (' / the stack block\nreserved inside it (`stack_end - stack`; a reservation, not a measured peak).\n'
                                  if stack else '.\n') + source_note([(name, m) for name, m, _ in cells.values()]))


def rtl_rows(pub, results_dir, op, family, profile, only, every_run=False):
    """[(campaign, manifest, the accepting run's row)] of the chip tests of a profile: all (op None) or one family's.
    With every_run the third item is the list of the test's rows, one per timed run."""
    rows, names = [], {p.lower(): p for p in gks.PARAMS3}
    for name, (p, _, c) in rtl_cells().items():
        if p != profile or (op and (c[0], c[1] or 'ldirect') != (op, family)) or (only and names[c[2]] not in only):
            continue
        camp, m, csv_rows = record_of(pub, 'rtl', rtl_key(name, profile), results_dir)
        runs = [dict(r) for r in csv_rows if (r['op'], r['family'], r['param'], r['tier']) == (c[0], c[1] or 'ldirect', c[2], c[3])]
        mine = [r for r in runs if r['run'] in ('accept', 'coverage')]
        if len(mine) != 1:
            raise Refused(f'{m["run"]}: {len(mine)} accepting rows for {name}')
        for r in runs:
            r['param'] = names[c[2]]                       # shown as Ip, Is, Ip3, like the ISS tables
        rows.append((camp, m, runs if every_run else mine[0]))
    if not rows:
        raise Refused(f'no chip test {op or "at all"}/{family or ""}@{profile}' + (f' with {",".join(only)}' if only else ''))
    def place(r):
        first = r[2][0] if every_run else r[2]
        return (OP_ORDER[first['op']], SHOWN.get(first['family'], first['family']), gks.PARAMS3.index(first['param']),
                gcm.R2_TIERS.index(first['tier']))
    return sorted(rows, key=place)


def rtl_note(profile, rows, runs='the accepting run of each test'):
    return f'Chip RTL under Verilator, {profile} KiB DMEM profile, {runs}. ' + source_note([(camp, m) for camp, m, _ in rows])


def lead_titles(lead):
    return ['kernel' if k == 'family' else k for k in lead]


def lead_cells(lead, r):
    return [SHOWN.get(r[k], r[k]) if k == 'family' else r[k] for k in lead]


def rtl_table(pub, results_dir, op, family, profile, only):
    rows = rtl_rows(pub, results_dir, op, family, profile, only)
    lead = ('param', 'tier') if op else ('op', 'family', 'param', 'tier')
    meters = RTL_METERS + (() if op else (('whole_test_cycles', 'whole test'),))
    lines = ['| ' + ' | '.join(['DMEM', *lead_titles(lead)] + [title for _, title in meters]) + ' |',
             '|' + '---|' * (1 + len(lead)) + '---:|' * len(meters)]
    for _, _, r in rows:
        lines.append('| ' + ' | '.join([f'{profile} KiB', *lead_cells(lead, r)] + [f'{int(r[f]):,}' if r[f] else '-' for f, _ in meters]) + ' |')
    return '\n'.join(lines) + '\n\nInstructions the ACC retired, then Ibex cycles.\n' + rtl_note(profile, rows)


def rtl_cycles(pub, results_dir, op, family, profile, only):
    rows = rtl_rows(pub, results_dir, op, family, profile, only)
    if not op:
        raise Refused('rtl-cycles names one test family')
    by = {(r['tier'], r['param']): r['exec_wait'] for _, _, r in rows}
    params = [p for p in gks.PARAMS3 if any(k[1] == p for k in by)]
    lines = ['| DMEM | tier | ' + ' | '.join(params) + ' |', '|---|---|' + '---:|' * len(params)]
    for t in gcm.R2_TIERS:
        if any(k[0] == t for k in by):
            lines.append(f'| {profile} KiB | {t} | ' + ' | '.join(f'{int(by[t, p]):,}' if by.get((t, p)) else '-' for p in params) + ' |')
    return '\n'.join(lines) + '\n\nexec+wait in Ibex cycles. ' + rtl_note(profile, rows)


def rtl_runs(pub, results_dir, op, family, profile, only):
    rows = rtl_rows(pub, results_dir, op, family, profile, only, every_run=True)
    roles = [role for roles in gcm.PROTOCOL_RUNS.values() for role in roles]
    roles = sorted({r['run'] for _, _, runs in rows for r in runs if r['exec_wait']}, key=roles.index)
    if not op or not roles:
        raise Refused('rtl-runs names one test family with timed runs')
    lines = ['| DMEM | param | tier | ' + ' | '.join(roles) + ' |', '|---|---|---|' + '---:|' * len(roles)]
    for _, _, runs in rows:
        by = {r['run']: r['exec_wait'] for r in runs}
        lines.append(f'| {profile} KiB | {runs[0]["param"]} | {runs[0]["tier"]} | '
                     + ' | '.join(f'{int(by[x]):,}' if by.get(x) else '-' for x in roles) + ' |')
    return '\n'.join(lines) + ('\n\nexec+wait in Ibex cycles of every timed run of each test; - where a test does not make that run.\n'
                               + rtl_note(profile, rows, 'one loaded image per test'))


def rtl_iss(pub, results_dir, op, family, profile, only):
    """The chip's instruction count of each test against the ISS runs of the same kernel family."""
    rows = rtl_rows(pub, results_dir, op, family, profile, only)
    lead = ('param', 'tier') if op else ('op', 'family', 'param', 'tier')
    lines = ['| ' + ' | '.join(['DMEM', *lead_titles(lead)]) + ' | ACC instructions | ISS cases with that count | exec+wait above the ISS cycles |',
             '|' + '---|' * (1 + len(lead)) + '---:|---|---:|']
    recs = [(camp, m) for camp, m, _ in rows]
    for _, _, r in rows:
        variant = r['family'] if r['family'] in RTL_TWIN else None
        cat = gks.CAMPAIGN.get((profile, r['op'], variant), ((), ()))
        if r['param'] not in cat[0] or r['tier'] not in cat[1]:
            continue                                         # no ISS run of this test's ELF
        camp, m, iss = record_of(pub, 'iss', cohort_key({'op': r['op'], 'variant': variant, 'tier': r['tier'],
                                                         'param': r['param'], 'profile': profile}), results_dir)
        recs.append((camp, m))
        same = sorted(int(x['case']) for x in iss if x['instructions'] == r['acc_insn'])
        above = int(r['exec_wait']) - int(next(x['cycles'] for x in iss if int(x['case']) == same[0])) if same else None
        lines.append('| ' + ' | '.join([f'{profile} KiB', *lead_cells(lead, r)] + [f'{int(r["acc_insn"]):,}', cases_text(same) or 'none',
                                                                                  '-' if above is None else f'{above:,}']) + ' |')
    if len(lines) == 2:
        raise Refused(f'no chip test of {op or "any"}/{family or ""}@{profile} runs the ELF of an ISS run')
    return '\n'.join(lines) + ('\n\nInstructions the ACC retired in each chip test, the cases whose ISS run of the same ELF retires exactly as many,\n'
                               'and how far the chip\'s exec+wait lies above the ISS cycles of the first such case (none: no case has that count).\n'
                               + f'Chip RTL under Verilator and the ISS, {profile} KiB DMEM profile. ' + source_note(recs))


def rtl_speedup(pub, results_dir, op, family, profile, only, meter):
    """sw divided by each tier on the chip in one meter, a row per test family and parameter set, of a profile or of all."""
    by, recs = {}, []
    for pr in [profile] if profile is not None else sorted(RTL_MODE):
        rows = rtl_rows(pub, results_dir, op, family, pr, only)
        recs += [(camp, m) for camp, m, _ in rows]
        for _, _, r in rows:
            by.setdefault((pr, r['op'], r['family'], r['param']), {})[r['tier']] = r
    if not by:
        raise Refused(f'no chip test of {op or "any"}/{family or ""} with the {meter} meter')
    lines = ['| DMEM | op | kernel | param | ' + ' | '.join(SPEEDUP_TIERS) + ' |', '|---|---|---|---|' + '---:|' * len(SPEEDUP_TIERS)]
    for (pr, o, f, p), cell in by.items():
        if 'sw' not in cell:
            raise Refused(f'{o}/{f}/{p}@{pr} has no sw test to compare with')
        lines.append(f'| {pr} KiB | {o} | {SHOWN.get(f, f)} | {p} | ' + ' | '.join(
            times(int(cell['sw'][meter]), int(cell[t][meter])) if t in cell else '-' for t in SPEEDUP_TIERS) + ' |')
    title, what = SPEEDUP_METERS[meter]
    return (SPEEDUP_TITLE.format(title) + '\n'.join(lines) + f'\n\n{what}-: no test of that tier.\n'
            + 'Chip RTL under Verilator, the accepting run of each test. ' + source_note(recs))


def table(name, pub, results_dir):
    """The text between one marker pair."""
    m = TABLE.fullmatch(name)
    if not m:
        raise Refused(f'unknown table {name}')
    kind, op, family, profile, other, profile2, only = m.groups()
    only = only.split(',') if only else None
    profile = None if profile is None else int(profile)
    if (other is not None) != (kind == 'iss-ratio') or (kind == 'iss-ratio' and not op):
        raise Refused(f'{name}: iss-ratio, and only iss-ratio, names two families: iss-ratio:OP/A@PROFILE/B@PROFILE')
    if kind == 'iss-ratio':
        return iss_ratio(pub, results_dir, op, family, profile, other, int(profile2), only)
    if kind in ('iss-retries', 'iss-retries-speedup'):
        if op or profile is not None or only:
            raise Refused(f'{name}: the retry tables are iss-retries:all and iss-retries-speedup:all')
        return iss_retries(pub, results_dir, ratios=kind == 'iss-retries-speedup')
    if profile is None and (op or kind not in ('iss-speedup', 'rtl-speedup', 'rtl-speedup-op')):
        raise Refused(f'{name}: names no DMEM profile (@PROFILE); only the :all speed-ups may span every profile')
    if kind in ('rtl-speedup', 'rtl-speedup-op'):
        return rtl_speedup(pub, results_dir, op, family, profile, only, 'exec_wait' if kind == 'rtl-speedup' else 'op_total_v2')
    if kind.startswith('rtl'):
        return {'rtl': rtl_table, 'rtl-cycles': rtl_cycles, 'rtl-runs': rtl_runs,
                'rtl-iss': rtl_iss}[kind](pub, results_dir, op, family, profile, only)
    if op is None:
        if only or kind not in ('iss', 'iss-speedup'):
            raise Refused(f'{name}: only iss:all, iss-speedup:all and the rtl kinds list a whole profile')
        return (iss_all if kind == 'iss' else iss_speedup_all)(pub, results_dir, profile)
    return {'iss': iss_table, 'iss-speedup': iss_speedup, 'mem': mem_table}[kind](pub, results_dir, op, family, profile, only)


def render(text, make):
    """(text with every marked table replaced by make(name), [(name, why)] for the tables make refused, which stay
    as they are); ValueError if a marker has no pair."""
    left = []

    def one(m):
        try:
            return f'<!-- table:{m[1]} -->\n{make(m[1])}<!-- /table:{m[1]} -->\n'
        except Refused as e:
            left.append((m[1], str(e)))
            return m[0]
    out, n = MARK.subn(one, text)
    if len(re.findall(r'^<!-- /?table:', text, re.M)) != 2 * n:
        raise ValueError('a table marker without its pair (each on a line of its own, the closing one after it)')
    return out, left


def marked_files(checkout):
    """Tracked Markdown files that hold a table marker."""
    r = subprocess.run(['git', 'grep', '-l', '-E', '^<!-- /?table:', '--', '*.md'], cwd=checkout, capture_output=True, text=True)
    if r.returncode > 1:
        raise Stop(f'git grep failed: {r.stderr.strip()}')
    return r.stdout.split('\n')[:-1]


def run_tables(a):
    """Rewrite (with --check: only compare) every marked table of this tree that the published records can fill.
    A table whose cells are not all published, or whose name is unknown, stays as it is and is reported.
    Exit 0: every table up to date or rewritten; 1: --check found a file that would change; 2: a table was
    left as it is, or the records or the markers are broken (then nothing is written)."""
    results_dir = os.path.join(REPO, RESULTS)
    with locked(os.path.join(REPO, LOCK)):
        try:
            pub = published(REPO)
            new, left = {}, []
            for rel in marked_files(REPO):
                try:
                    new[rel], bad = render(read(os.path.join(REPO, rel)), lambda name: table(name, pub, results_dir))
                except ValueError as e:
                    raise Refused(f'{rel}: {e}')
                left += [f'{rel}: {name}: {why}' for name, why in bad]
        except (Stop, Refused) as e:
            fail(f'READMEs unchanged: {e}')
        stale = [rel for rel, text in new.items() if read(os.path.join(REPO, rel)) != text]
        for rel in stale:
            if not a.check:
                write_atomic(os.path.join(REPO, rel), new[rel])
            print(f'{"would rewrite" if a.check else "rewrote"} {rel}')
        for line in left:
            print(f'left as it is: {line}')
        print(f'{len(new)} files with tables, {len(new) - len(stale)} up to date, {len(left)} tables left as they are')
        return 2 if left else 1 if a.check and stale else 0


def current(hjson_text):
    """The profile the hjson is in, or None."""
    skips, items = RE_SKIP.findall(hjson_text), RE_ITEMS.findall(hjson_text)
    for kib, (s, n, _) in PROFILES.items():
        if s in skips and n in items:
            return kib
    return None


def set_hjson(text, kib):
    """The DMEM window by value: one skipto and one items line, whatever comment the items line carries."""
    old = PROFILES[current(text)]
    s, n, note = PROFILES[kib]
    text, a = re.subn(rf'\{{ skipto: "{old[0]}" \}}', f'{{ skipto: "{s}" }}', text)
    text, b = re.subn(rf'items: "{old[1]}", // [^\n]*', f'items: "{n}", // {note}', text)
    assert a == 1 and b == 1 and current(text) == kib, (a, b)
    return text


def set_memutil(text, kib):
    base = PROFILES[kib][0]
    text, n1 = re.subn(r'"u_dmem"\), \d+ / 32,', f'"u_dmem"), {kib * 1024} / 32,', text)
    text, n2 = re.subn(r'RegisterMemoryArea\("dmem", 0x[0-9a-f]+,', f'RegisterMemoryArea("dmem", {base},', text)
    assert n1 == 1 and n2 == 1, (n1, n2)
    return text


def regen(*cmd):
    # cmdgen shells out to `util/regtool.py`: the interpreter's bin dir must lead PATH
    env = dict(os.environ, PATH=os.path.dirname(sys.executable) + os.pathsep + os.environ.get('PATH', ''))
    subprocess.run(cmd, cwd=REPO, check=True, stdout=subprocess.DEVNULL, env=env)


def run_profile(a):
    """Switch this clone's ACC DMEM profile: edit acc.hjson and the memutil constants, then regenerate what derives
    from them with the repo's own generators. Idempotent; never commit the result."""
    kib = a.profile
    hp, mp = os.path.join(REPO, HJSON), os.path.join(REPO, MEMUTIL)
    hj, mu = open(hp).read(), open(mp).read()
    now = current(hj)
    if now is None:
        fail(f'{HJSON} is in no known profile; fix it by hand first')
    # both edits validated before either file is written; the generators always run, so a failed
    # earlier run is repaired by running again (an interrupted topgen first wants its
    # ip_autogen/.~*.staging dir removed, and says so)
    hj2, mu2 = set_hjson(hj, kib), set_memutil(mu, kib)
    open(hp, 'w').write(hj2)
    open(mp, 'w').write(mu2)
    py = sys.executable
    regen(py, 'util/regtool.py', '-r', '-t', 'hw/ip/acc/rtl', HJSON)
    regen(py, 'util/regtool.py', '--sec-cm-testplan', HJSON)
    regen(py, 'util/cmdgen.py', '-u', 'hw/ip/acc/doc/registers.md')
    regen(py, 'util/topgen.py', '-t', 'hw/top_egret/data/top_egret.hjson',
        '-s', 'hw/top_egret/data/top_egret_seed.testing.hjson')
    changed = git('diff', '--name-only').split() if in_git() else []
    for f in changed:
        path = os.path.join(REPO, f)
        print(hashlib.sha256(open(path, 'rb').read()).hexdigest()[:16] if os.path.exists(path) else 'deleted'.ljust(16), f)
    differ = f'{len(changed)} files differ from HEAD' if in_git() else 'no git checkout: changed files not listed'
    print(f'profile {kib} KiB ({PROFILES[kib][0]} / {PROFILES[kib][1]}); {differ}')
    if kib == 512:
        print('512 KiB is ISS only: chip RTL runs at 32 and 128 KiB only')
    return 0


# ---------------------------------------------------------------------------------------------
# Paper tables: every published number as a \DefineVar line, plus LaTeX tabulars, written into the paper's tables
# directory. Names: iss:OP:KERNEL:PROFILE:PARAM:TIER:lo|hi|sum (cycles), spd:OP:KERNEL:PROFILE:PARAM:TIER (times
# faster than sw), both:OP:KERNEL:PROFILE:PARAM:TIER (times faster with both extensions than TIER),
# rtl:OP:KERNEL:PROFILE:PARAM:TIER:METER, rtlspd:METER:OP:KERNEL:PROFILE:PARAM:TIER,
# above:OP:KERNEL:PROFILE:PARAM:TIER (exec+wait above the ISS cycles), ratio:OP:A:PA:B:PB:PARAM:TIER,
# retry:OP:KERNEL:PROFILE:PARAM:TIER:CASE:cyc|n|spd, mem:OP:KERNEL:PROFILE:PARAM:TIER:code|bss|stack,
# claim:* (the numbers the paper's comparisons quote, paper_claims).

PAPER_RATIOS = (('sign', 'sprec', 512, 'ldirect', 32), ('keygen', 'stream_uniform', 32, 'stream', 32),
                ('verify', 'stream_uniform', 32, 'stream', 32),
                # the memory ladder: the streamed operation against the one-EXECUTE schedules (operation totals)
                ('keygen', 'stream', 32, 'min', 128), ('keygen', 'stream', 32, 'sp', 128), ('keygen', 'stream', 32, 'full', 512),
                ('verify', 'stream', 32, 'full', 128))


def paper_vars(pub, results_dir):
    """{name: value} of every published ISS and chip number, in the order the tables use them."""
    out = {}

    def var(name, value):
        if name in out:
            raise Refused(f'paper variable {name} defined twice')
        out[name] = value

    families = sorted(gks.CAMPAIGN, key=lambda f: (f[0], OP_ORDER[f[1]], SHOWN.get(f[2], f[2])))
    for pr, op, v in families:
        params, tiers, cells = iss_cells(pub, results_dir, op, v, pr)
        shown = shown_rows(cells, tiers, params)
        k = SHOWN.get(v, v)
        for p in params:
            keep = kept_cases([cells[t, p] for t in tiers])
            var(f'cases:{op}:{k}:{pr}:{p}', len(keep))
            vec = os.path.relpath(gks.testvec_path(p), REPO)
            c32 = kat_case_of_len(p, CYCLES_MSG_LEN, cells[tiers[0], p][1]['source']['vectors'].get(vec))
            for t in tiers:
                cyc = [int(r['cycles']) for r in shown[t, p]]
                var(f'iss:{op}:{k}:{pr}:{p}:{t}:lo', min(cyc))
                var(f'iss:{op}:{k}:{pr}:{p}:{t}:hi', max(cyc))
                var(f'iss:{op}:{k}:{pr}:{p}:{t}:sum', total(cells[t, p], keep))
                hit = [r for r in cells[t, p][2] if int(r['case']) == c32]
                if len(hit) != 1 or hit[0]['retries']:
                    raise Refused(f'{op} {k} {pr} KiB {p} {t}: the {CYCLES_MSG_LEN}-byte case {c32} is missing or retried')
                var(f'iss:{op}:{k}:{pr}:{p}:{t}:m{CYCLES_MSG_LEN}', int(hit[0]['cycles']))
            if 'sw' in tiers:
                for t, s in speedups(cells, tiers, p).items():
                    var(f'spd:{op}:{k}:{pr}:{p}:{t}', s[:-1])
            for t in ('bngfonly', 'bnaesonly'):
                if t in tiers and 'bngfaes' in tiers:
                    var(f'both:{op}:{k}:{pr}:{p}:{t}', speedups(cells, tiers, p, t)['bngfaes'][:-1])
            for c in sorted({int(r['case']) for t in tiers for r in cells[t, p][2] if r['retries']}):
                row = {t: next(r for r in cells[t, p][2] if int(r['case']) == c) for t in tiers}
                for t in tiers:
                    var(f'retry:{op}:{k}:{pr}:{p}:{t}:{c}:cyc', int(row[t]['cycles']))
                    var(f'retry:{op}:{k}:{pr}:{p}:{t}:{c}:n', row[t]['retries'])
                    if 'sw' in row and t != 'sw':
                        var(f'retry:{op}:{k}:{pr}:{p}:{t}:{c}:spd', times(int(row['sw']['cycles']), int(row[t]['cycles']))[:-1])
        for (t, p), (_, m, _) in cells.items():
            (art,) = m['artifacts'].values()
            code = [size for addr, size, _ in art['segments'] if addr != m['profile']['dmem_address']]
            var(f'mem:{op}:{k}:{pr}:{p}:{t}:code', code[0] if len(code) == 1 else '')
            var(f'mem:{op}:{k}:{pr}:{p}:{t}:bss', art['dmem_bss_end'])
            var(f'mem:{op}:{k}:{pr}:{p}:{t}:stack', art.get('stack_reserved') or '')
    for op, a, pa, b, pb in PAPER_RATIOS:
        if (pa, op, a) not in gks.CAMPAIGN or (pb, op, b) not in gks.CAMPAIGN:
            continue
        params_a, tiers_a, ca = iss_cells(pub, results_dir, op, a, pa)
        params_b, tiers_b, cb = iss_cells(pub, results_dir, op, b, pb)
        for p in [p for p in params_a if p in params_b]:
            tiers = [t for t in SPEEDUP_TIERS + ('sw',) if t in tiers_a and t in tiers_b]
            keep = kept_cases([rec for t in tiers for rec in (ca[t, p], cb[t, p])], one_campaign=True)
            for t in tiers:
                var(f'ratio:{op}:{SHOWN.get(a, a)}:{pa}:{SHOWN.get(b, b)}:{pb}:{p}:{t}',
                    f'{total(ca[t, p], keep) / total(cb[t, p], keep):.2f}')
    for pr in sorted(RTL_MODE):
        if not any(p == pr for p, _, _ in rtl_cells().values()):
            continue
        rows = rtl_rows(pub, results_dir, None, None, pr, None)
        by = {}
        for _, _, r in rows:
            k = SHOWN.get(r['family'], r['family'])
            for f, _ in RTL_METERS + (('whole_test_cycles', ''),):
                if r.get(f):
                    var(f'rtl:{r["op"]}:{k}:{pr}:{r["param"]}:{r["tier"]}:{f}', int(r[f]))
            by.setdefault((r['op'], k, r['param']), {})[r['tier']] = r
            variant = r['family'] if r['family'] in RTL_TWIN else None
            cat = gks.CAMPAIGN.get((pr, r['op'], variant), ((), ()))
            if r['param'] in cat[0] and r['tier'] in cat[1]:
                _, m, iss = record_of(pub, 'iss', cohort_key({'op': r['op'], 'variant': variant, 'tier': r['tier'],
                                                             'param': r['param'], 'profile': pr}), results_dir)
                same = sorted(int(x['case']) for x in iss if x['instructions'] == r['acc_insn'])
                var(f'twin:{r["op"]}:{k}:{pr}:{r["param"]}:{r["tier"]}', len(same))
                if same:
                    var(f'above:{r["op"]}:{k}:{pr}:{r["param"]}:{r["tier"]}',
                        int(r['exec_wait']) - int(next(x['cycles'] for x in iss if int(x['case']) == same[0])))
        for (op, k, p), cell in by.items():
            if 'sw' in cell:
                for t in SPEEDUP_TIERS:
                    if t in cell:
                        for f in ('exec_wait', 'op_total_v2'):
                            var(f'rtlspd:{f}:{op}:{k}:{pr}:{p}:{t}', times(int(cell['sw'][f]), int(cell[t][f]))[:-1])
    return out


def var_span(vals, name):
    """The cycles of name (iss:OP:KERNEL:PROFILE:PARAM:TIER) as \\Var references: one number, lowest--highest, or --."""
    if f'{name}:lo' not in vals:
        return '--'
    lo, hi = vals[f'{name}:lo'], vals[f'{name}:hi']
    return f'\\num{{\\Var{{{name}:lo}}}}' if lo == hi else f'\\num{{\\Var{{{name}:lo}}}}--\\num{{\\Var{{{name}:hi}}}}'


def tex_num(lo, hi):
    return f'\\num{{{lo}}}' if lo == hi else f'\\num{{{lo}}}--\\num{{{hi}}}'


def paper_tables(vals):
    """{file name: LaTeX tabular} drawn from the paper variables: ISS cycles per profile, the speed-ups on the ISS
    and on the chip (two meters), the retry cases."""
    tabs = {}
    fams = sorted({(int(n.split(':')[3]), n.split(':')[1], n.split(':')[2]) for n in vals if n.startswith('iss:')},
                  key=lambda f: (f[0], OP_ORDER[f[1]], f[2]))
    params = gks.PARAMS3
    for pr in sorted({f[0] for f in fams}):
        lines = [r'\begin{tabular}{lllrrr}', r'\toprule', 'Operation & Kernel & Tier & ' + ' & '.join(params) + r' \\', r'\midrule']
        for p0, op, k in [f for f in fams if f[0] == pr]:
            for t in ('sw',) + SPEEDUP_TIERS:
                cells = [tex_num(vals[f'iss:{op}:{k}:{pr}:{p}:{t}:lo'], vals[f'iss:{op}:{k}:{pr}:{p}:{t}:hi'])
                         if f'iss:{op}:{k}:{pr}:{p}:{t}:lo' in vals else '--' for p in params]
                lines.append(f'{op} & {k.replace("_", chr(92) + "_")} & \\texttt{{{t}}} & ' + ' & '.join(cells) + r' \\')
            lines.append(r'\addlinespace')
        lines[-1:] = [r'\bottomrule', r'\end{tabular}']
        tabs[f'tab-iss-{pr}.tex'] = '\n'.join(lines) + '\n'
    for name, prefix in (('tab-speedup.tex', 'spd'), ('tab-rtl-speedup.tex', 'rtlspd:exec_wait'),
                         ('tab-rtl-speedup-op.tex', 'rtlspd:op_total_v2')):
        lines = [r'\begin{tabular}{llllrrr}', r'\toprule',
                 'DMEM & Operation & Kernel & Param & ' + ' & '.join(f'\\texttt{{{t}}}' for t in SPEEDUP_TIERS) + r' \\', r'\midrule']
        for pr, op, k in fams:
            for p in params:
                keys = [f'{prefix}:{op}:{k}:{pr}:{p}:{t}' for t in SPEEDUP_TIERS]
                if any(x in vals for x in keys):
                    lines.append(f'{pr}\\,KiB & {op} & {k.replace("_", chr(92) + "_")} & {p} & '
                                 + ' & '.join(f'\\Var{{{x}}}$\\times$' if x in vals else '--' for x in keys) + r' \\')
        tabs[name] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    lines = [r'\begin{tabular}{llllrrrr}', r'\toprule', r' & & & & \multicolumn{4}{c}{cycles (millions)} \\', r'\cmidrule(lr){5-8}',
             'DMEM & Operation & Kernel & Set & ' + ' & '.join(f'\\texttt{{{t}}}' for t in ('sw',) + SPEEDUP_TIERS) + r' \\', r'\midrule']
    head = lines
    for name, meter in (('tab-cycles.tex', f'm{CYCLES_MSG_LEN}'), ('tab-rtl-cycles.tex', 'exec_wait')):
        # every kernel's cycles in millions to 3 figures: the ISS at the 32-byte case, and the chip RTL (exec+wait)
        eng = 'rtl' if meter == 'exec_wait' else 'iss'
        lines = list(head)
        for pr, op, k in fams:
            for p in params:
                one = [f'{eng}:{op}:{k}:{pr}:{p}:{t}:{meter}' for t in ('sw',) + SPEEDUP_TIERS]
                if any(x in vals for x in one):
                    label = PAPER_KERNEL.get(k, '\\kernel{' + k.replace('_', '\\_') + '}')
                    lines.append(f'{pr}\\,KiB & {op} & {label} & {PAPER_SET[p]} & '
                                 + ' & '.join(f'\\num[round-mode=figures,round-precision=3]{{\\fpeval{{\\Var{{{x}}}/1000000}}}}'
                                              if x in vals else '--' for x in one) + r' \\')
        tabs[name] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    # linked DMEM extent (_dmem_bss_end) per family and tier; 0 marks a fixed-address map (no linked data)
    lines = [r'\begin{tabular}{lllrrr}', r'\toprule', 'Operation & Kernel & Tier & ' + ' & '.join(params) + r' \\', r'\midrule']
    for pr, op, k in fams:
        for t in ('sw',) + SPEEDUP_TIERS:
            cells = [f'\\num{{{vals[f"mem:{op}:{k}:{pr}:{p}:{t}:bss"]}}}' if f'mem:{op}:{k}:{pr}:{p}:{t}:bss' in vals else '--' for p in params]
            lines.append(f'{op} & {k.replace("_", chr(92) + "_")} ({pr}\\,KiB) & \\texttt{{{t}}} & ' + ' & '.join(cells) + r' \\')
        lines.append(r'\addlinespace')
    lines[-1:] = [r'\bottomrule', r'\end{tabular}']
    tabs['tab-mem.tex'] = '\n'.join(lines) + '\n'
    retry = sorted({tuple(n.split(':')[1:7]) for n in vals if n.startswith('retry:')},
                   key=lambda r: (int(r[2]), OP_ORDER[r[0]], r[1], r[3], TIER_ORDER[r[4]], int(r[5])))
    lines = [r'\begin{tabular}{lllllrrr}', r'\toprule', r'DMEM & Operation & Kernel & Param & Tier & Case & Retries & ISS cycles \\', r'\midrule']
    for op, k, pr, p, t, c in retry:
        lines.append(f'{pr}\\,KiB & {op} & {k} & {p} & \\texttt{{{t}}} & {c} & \\Var{{retry:{op}:{k}:{pr}:{p}:{t}:{c}:n}} '
                     f'& \\num{{\\Var{{retry:{op}:{k}:{pr}:{p}:{t}:{c}:cyc}}}} \\\\')
    tabs['tab-retry.tex'] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    return tabs


# ---------------------------------------------------------------------------------------------
# Observe records: what the ISS observers measured (trace equality of the sign kernels; DMEM bytes touched per
# kernel), results/observe-<kind>-<stamp>/{manifest.json, results.csv}. The paper renderer reads the newest record of
# each kind. The observers left the repo; tools/README.md says how to restore them.

def artifact_image(facts):
    """The sha256 of an ELF's entry point and loaded segments (elf_facts, or an ISS record's artifact): what the ISS
    loads, the same for a rebuild that changes only the debug and file names."""
    return hashlib.sha256(json.dumps([facts['entry'], facts['segments']]).encode()).hexdigest()


def observe_records(results_dir):
    """{kind: (manifest, rows)}: the newest observe record of each kind, its results.csv checked against the manifest."""
    out = {}
    for name in sorted(os.listdir(results_dir)) if os.path.isdir(results_dir) else []:
        if not name.startswith('observe-'):
            continue
        m = json.loads(read(os.path.join(results_dir, name, 'manifest.json')))
        text = read(os.path.join(results_dir, name, 'results.csv'))
        if hashlib.sha256(text.encode()).hexdigest() != m['results_sha256']:
            raise Stop(f'{name}: results.csv does not match its manifest')
        if m['kind'] not in out or m['created'] > out[m['kind']][0]['created']:
            out[m['kind']] = (m, list(csv.DictReader(text.splitlines())))
    return out


def observed_binaries_match(pub, results_dir, rec, pairs):
    """Refused unless every ((op, variant, profile, param, tier), image) of an observe record's rows is the image of an
    ELF the published ISS record of that cell froze: the paper never puts an observation of other binaries next to its
    cycles. Every row counts, not one per cell."""
    for (op, v, pr, p, t), image in sorted(pairs):
        _, m, _ = record_of(pub, 'iss', cohort_key({'op': op, 'variant': v, 'tier': t, 'param': p, 'profile': int(pr)}), results_dir)
        if image not in {artifact_image(art) for art in m['artifacts'].values()}:
            raise Refused(f'{rec}: {op}/{v}@{pr} {p} {t} observed another ELF than {m["run"]} measured')


def observe_vars(results_dir, pub=None):
    """{name: value} from the newest observe records: ct:PARAM:TIER:runs|classes|whole|bodies (whole: the most distinct
    whole traces in any (length, attempts) group; bodies: the most distinct failed or final attempt bodies at any length),
    ct:PARAM:TIER:LEN:ATTEMPTS:runs|whole|cycles, and span:OP:KERNEL:PROFILE:PARAM:TIER:touched|lo|hi|phases."""
    out = {}
    recs = observe_records(results_dir)
    if pub is not None and 'trace' in recs:
        observed_binaries_match(pub, results_dir, recs['trace'][0]['run'],
                                {(('sign', 'ldirect', 32, r['param'], r['tier']), r.get('elf_image')) for r in recs['trace'][1]})
    if pub is not None and 'span' in recs:
        observed_binaries_match(pub, results_dir, recs['span'][0]['run'],
                                {((r['op'], r['variant'], r['profile'], r['param'], r['tier']), r.get('elf_image')) for r in recs['span'][1]})
    if 'trace' in recs:
        rows = recs['trace'][1]
        for p in gks.PARAMS3:
            for t in gcm.R2_TIERS:
                mine = [r for r in rows if (r['param'], r['tier']) == (p, t)]
                if not mine:
                    continue
                groups, bodies = {}, {}
                for r in mine:
                    groups.setdefault((int(r['msg_len']), int(r['attempts'])), []).append(r)
                    *failed, final = r['bodies'].split(';')
                    bodies.setdefault((int(r['msg_len']), 'failed'), set()).update(failed)
                    bodies.setdefault((int(r['msg_len']), 'final'), set()).add(final)
                out[f'ct:{p}:{t}:runs'] = len(mine)
                out[f'ct:{p}:{t}:classes'] = len({int(r['msg_len']) for r in mine})
                out[f'ct:{p}:{t}:whole'] = max(len({r['whole'] for r in g}) for g in groups.values())
                out[f'ct:{p}:{t}:bodies'] = max(len(b) for b in bodies.values())
                for (L, k), g in sorted(groups.items()):
                    out[f'ct:{p}:{t}:{L}:{k}:runs'] = len(g)
                    out[f'ct:{p}:{t}:{L}:{k}:whole'] = len({r['whole'] for r in g})
                    cyc = sorted({int(r['cycles']) for r in g})
                    out[f'ct:{p}:{t}:{L}:{k}:cycles'] = cyc[0] if len(cyc) == 1 else f'{cyc[0]}..{cyc[-1]}'
    if 'span' in recs:
        for r in recs['span'][1]:
            k = SHOWN.get(r['variant'], r['variant'])
            for f in ('touched_bytes', 'lo', 'hi', 'phases'):
                out[f'span:{r["op"]}:{k}:{r["profile"]}:{r["param"]}:{r["tier"]}:{f.replace("touched_bytes", "touched")}'] = r[f]
    return out


def observe_tables(vals):
    """{file name: tabular} from the observe variables: tab-ct.tex (trace experiment) and tab-span.tex (bytes touched)."""
    tabs = {}
    ct = sorted({tuple(n.split(':')[1:3]) for n in vals if n.startswith('ct:') and n.endswith(':runs') and n.count(':') == 3},
                key=lambda x: (gks.PARAMS3.index(x[0]), TIER_ORDER[x[1]]))
    if ct:
        lines = [r'\begin{tabular}{llrrrr}', r'\toprule', r'Set & Backend & Runs & Length classes & Distinct whole traces & Distinct attempt bodies \\', r'\midrule']
        for p, t in ct:
            lines.append(f'{PAPER_SET[p]} & \\texttt{{{t}}} & \\Var{{ct:{p}:{t}:runs}} & \\Var{{ct:{p}:{t}:classes}} & \\Var{{ct:{p}:{t}:whole}} & \\Var{{ct:{p}:{t}:bodies}} \\\\')
        tabs['tab-ct.tex'] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    span = sorted({tuple(n.split(':')[1:4]) for n in vals if n.startswith('span:')}, key=lambda f: (int(f[2]), OP_ORDER[f[0]], f[1]))
    if span:
        params = gks.PARAMS3
        lines = [r'\begin{tabular}{lllrrr}', r'\toprule', 'Operation & Kernel & Tier & ' + ' & '.join(params) + r' \\', r'\midrule']
        for op, k, pr in span:
            for t in ('sw',) + SPEEDUP_TIERS:
                cells = [f'\\num{{\\Var{{span:{op}:{k}:{pr}:{p}:{t}:touched}}}}' if f'span:{op}:{k}:{pr}:{p}:{t}:touched' in vals else '--' for p in params]
                lines.append(f'{op} & {k.replace("_", chr(92) + "_")} ({pr}\\,KiB) & \\texttt{{{t}}} & ' + ' & '.join(cells) + r' \\')
            lines.append(r'\addlinespace')
        lines[-1:] = [r'\bottomrule', r'\end{tabular}']
        tabs['tab-span.tex'] = '\n'.join(lines) + '\n'
    return tabs


# ---------------------------------------------------------------------------------------------
# Memory usage of the 32 KiB kernels: the DMEM granules the ACC touched (tools/dmem_usage.py), split by the ELF's
# DMEM symbols into fixed state, streaming buffers and the message. Inside sign's stack block the labels only reserve.

MEMUSE = 'sw/acc/crypto/handwritten/uov/mem-usage'
MEMUSE_FAMILIES = (('keygen', 'stream'), ('sign', 'ldirect'), ('verify', 'stream'),
                   ('keygen', 'stream_uniform'), ('verify', 'stream_uniform'))
# buffers whose size the kernel chose (P3 windows, keystream and B-row buffers); the message; the rest is fixed
MEM_STREAM = {'slice', 'p1buf', 'group_buf', 'gbuf01', 'gbuf23', 'p2buf', 'msgwin'}
MEM_MSG = {'msg'}
# symbols that only mark where a region ends
MEM_MARKS = {'slice_end', 'swstack_end', 'stack_end', 'winend', 'swframe_end', 'kg_stack_top', 'backend_stack_end',
             'backend_swstack_end', 'sfk_stack_end', 'vfk_stack_end'}
DMEM_BUS, DMEM_ALL = 31744, 32768


def elf_dmem(path):
    """(.text bytes, _dmem_bss_end, {name: (address, 'linked'|'abs')}) of an ELF's DMEM symbols."""
    from elftools.elf.elffile import ELFFile
    with open(path, 'rb') as fh:
        e = ELFFile(fh)
        text = e.get_section_by_name('.text')['sh_size']
        syms, end = {}, None
        for s in e.get_section_by_name('.symtab').iter_symbols():
            sh = s['st_shndx']
            if s.name == '_dmem_bss_end':
                end = s['st_value']
            if not s.name or s.name.startswith(('_', '$')) or s['st_info']['type'] in ('STT_FILE', 'STT_SECTION'):
                continue
            sec = e.get_section(sh).name if isinstance(sh, int) else sh
            if sec in ('.data', '.bss') or (sh == 'SHN_ABS' and s['st_value'] >= DMEM_BUS):
                if syms.get(s.name, (s['st_value'],))[0] != s['st_value']:
                    raise Refused(f'{path}: {s.name} at two addresses')
                syms[s.name] = (s['st_value'], 'abs' if sh == 'SHN_ABS' else 'linked')
    return text, end, syms


def mem_regions(syms, end):
    """[(name, class, lo, hi)] of one ELF's DMEM, hi exclusive."""
    if 'stack' in syms and 'stack_end' in syms:
        lo, hi = syms['stack'][0], syms['stack_end'][0]
        syms = {n: v for n, v in syms.items() if not lo < v[0] < hi}
    bounds = sorted({a for a, _ in syms.values()} | {end, DMEM_BUS, DMEM_ALL})
    starts = sorted((a, n) for n, (a, _) in syms.items() if n not in MEM_MARKS)
    if len({a for a, _ in starts}) != len(starts):
        raise Refused(f'two regions start at one address: {starts}')
    out = []
    for a, n in starts:
        hi = next(b for b in bounds if b > a)
        out.append((n, 'stream' if n in MEM_STREAM else 'msg' if n in MEM_MSG else 'fixed', a, hi))
    return out


def borrowed_regions(regions):
    """The fixed map of a bngfaes verify arm, which links no data: its sibling bngfonly arm names the same host map
    (the sources say so); the window runs to the bus end, and the scratch above it is one fixed region."""
    keep = []
    for n, c, lo, hi in regions:
        keep.append((n, c, lo, DMEM_BUS if n == 'msgwin' else hi))
        if n == 'msgwin':
            return keep + [('scratch', 'fixed', DMEM_BUS, DMEM_ALL)]
    raise Refused('the bngfonly map has no msgwin')


def granules(ranges):
    """{32-byte granule: first touched byte in it} of [lo, hi] byte ranges."""
    out = {}
    for lo, hi in ranges:
        for g in range(lo >> 5, (hi >> 5) + 1):
            out[g] = min(out.get(g, 1 << 30), max(lo, g << 5))
    return out


def mem_usage_cell(elf, obs, regions=None):
    """(row, region rows) of one cell from its ELF and its observation."""
    text, end, syms = elf_dmem(elf)
    regions = regions or mem_regions(syms, end)
    touched = granules(obs['read'] + obs['written'])
    per = {n: 0 for n, *_ in regions}
    nbytes = {n: 0 for n, *_ in regions}
    for g, first in touched.items():
        hit = [n for n, _, lo, hi in regions if lo <= first < hi]
        if len(hit) != 1:
            raise Refused(f'{elf}: touched byte {first} lies in {len(hit)} regions')
        per[hit[0]] += 32
    merged = []
    for lo, hi in sorted(obs['read'] + obs['written']):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    for lo, hi in merged:
        for n, _, rlo, rhi in regions:
            nbytes[n] += max(0, min(hi + 1, rhi) - max(lo, rlo))
    cls = {n: c for n, c, *_ in regions}
    split = {c: sum(v for n, v in per.items() if cls[n] == c) for c in ('fixed', 'stream', 'msg')}
    row = {'imem': text, 'dmem': split['fixed'] + split['stream'], 'dmem_fixed': split['fixed'],
           'dmem_stream': split['stream'], 'msg': sum(hi - lo for n, c, lo, hi in regions if c == 'msg'),
           'msg_touched': split['msg'], 'touched': 32 * len(touched), 'linked_end': end,
           'scratch_touched': sum(32 for g in touched if g << 5 >= DMEM_BUS),
           'stream_reserved': sum(hi - lo for n, c, lo, hi in regions if c == 'stream'),
           'elf_image': artifact_image(elf_facts(elf))}
    return row, [{'region': n, 'class': c, 'lo': lo, 'reserved': hi - lo, 'touched': per[n], 'touched_bytes': nbytes[n]}
                 for n, c, lo, hi in regions]


def run_mem_usage(a):
    """Write the MEMUSE record from the built ELFs and their observations. Exit 0: written; 2: refused."""
    rows, regs, cells = [], [], {}
    try:
        for op, v in MEMUSE_FAMILIES:
            params, tiers = gks.CAMPAIGN[32, op, v]
            for p in params:
                for t in tiers:
                    rel = gks.elf_of(op, p, t, v)
                    elf = os.path.join(a.elf_root, rel)
                    obs_path = os.path.join(a.observed, f'{op}_{v}_{p}_{t}.json')
                    if not os.path.exists(obs_path):
                        raise Refused(f'{op} {v} {p} {t}: no observation')
                    obs = json.loads(read(obs_path))
                    if obs.get('verdict') != 'PASS' or obs.get('exit') != 0:
                        raise Refused(f'{op} {v} {p} {t}: the observed run did not pass ({obs.get("verdict")})')
                    if obs['elf_sha256'] != sha256(elf):
                        raise Refused(f'{op} {v} {p} {t}: observed another ELF than {rel}')
                    regions = None
                    if op == 'verify' and v == 'stream' and t == 'bngfaes':
                        sib = os.path.join(a.elf_root, gks.elf_of(op, p, 'bngfonly', v))
                        _, send, ssyms = elf_dmem(sib)
                        regions = borrowed_regions(mem_regions(ssyms, send))
                    row, reg = mem_usage_cell(elf, obs, regions)
                    key = {'op': op, 'variant': v, 'param': p, 'tier': t}
                    rows.append({**key, 'case': obs['case'], 'phases': obs['phases'], **row})
                    regs += [{**key, **r} for r in reg]
                    cells[f'{op}/{v}/{p}/{t}'] = {'elf': rel, 'elf_sha256': obs['elf_sha256'], 'driver': obs['driver'],
                                                  'args': [x if not x.startswith('/') else os.path.basename(x) for x in obs['args']]}
    except (Refused, OSError, KeyError) as e:
        fail(f'nothing written: {e}')
    out = os.path.join(REPO, MEMUSE)
    os.makedirs(out, exist_ok=True)
    texts = {}
    for name, data in (('usage.csv', rows), ('regions.csv', regs)):
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(data[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(data)
        texts[name] = buf.getvalue()
    head = git('rev-parse', 'HEAD').strip() if in_git() else None
    manifest = {'kind': 'mem-usage', 'schema': 1, 'created': now(), 'commit': head,
                'dirty': bool(git('status', '--porcelain', '--untracked-files=no').strip()) if in_git() else None,
                'profile': 32, 'layout': actual_layout(), 'cells': cells,
                **{f'{n[:-4]}_sha256': hashlib.sha256(t.encode()).hexdigest() for n, t in texts.items()}}
    for name, text in texts.items():
        write_atomic(os.path.join(out, name), text)
    write_atomic(os.path.join(out, 'manifest.json'), json.dumps(manifest, indent=1) + '\n')
    print(f'{len(rows)} cells written to {MEMUSE}')
    return 0


def mem_usage_record():
    """(manifest, rows, regions) of the MEMUSE record, its files checked against the manifest; None if absent."""
    d = os.path.join(REPO, MEMUSE)
    if not os.path.exists(os.path.join(d, 'manifest.json')):
        return None
    m = json.loads(read(os.path.join(d, 'manifest.json')))
    out = [m]
    for name in ('usage', 'regions'):
        text = read(os.path.join(d, f'{name}.csv'))
        if hashlib.sha256(text.encode()).hexdigest() != m[f'{name}_sha256']:
            raise Refused(f'{MEMUSE}/{name}.csv does not match its manifest')
        out.append(list(csv.DictReader(text.splitlines())))
    return tuple(out)


def mem_usage_vars(pub, results_dir):
    """mem:OP:KERNEL:32:PARAM:TIER:imem|dmem|dmem_fixed|dmem_stream|msg from the MEMUSE record, refused unless every
    row observed the ELF that the published ISS record of its cell measured."""
    rec = mem_usage_record()
    if rec is None:
        return {}
    _, rows, _ = rec
    observed_binaries_match(pub, results_dir, MEMUSE, {((r['op'], r['variant'], 32, r['param'], r['tier']), r['elf_image'])
                                                       for r in rows})
    out = {}
    for r in rows:
        k = SHOWN.get(r['variant'], r['variant'])
        for f in ('imem', 'dmem', 'dmem_fixed', 'dmem_stream', 'msg'):
            out[f'mem:{r["op"]}:{k}:32:{r["param"]}:{r["tier"]}:{f}'] = int(r[f])
        out[f'calls:{r["op"]}:{k}:32:{r["param"]}:{r["tier"]}'] = int(r['phases'])
    return out


# paper Table 9: the bngfaes implementation of each operation per DMEM size (None: none exists at that size)
DMEM_SIZES = (('keygen', ('tuned', 32), ('sp', 128), ('full', 512)),
              ('sign', ('ldirect', 32), None, ('sprec', 512)),
              ('verify', ('tuned', 32), ('full', 128), None))


def dmem_size_table(vals):
    """tab-dmem-sizes.tex: kilocycles of the 32-byte case with both extensions, per operation, set and DMEM size."""
    lines = [r'\begin{tabular}{llrrr}', r'\toprule', r'Operation & Set & 32\,KiB & 128\,KiB & 512\,KiB \\', r'\midrule']
    for op, *sizes in DMEM_SIZES:
        for p in ('Ip', 'Is', 'Ip3'):
            cells = []
            for s in sizes:
                x = s and f'iss:{op}:{s[0]}:{s[1]}:{p}:bngfaes:m{CYCLES_MSG_LEN}'
                if s and x not in vals:
                    return {}
                cells.append(f'\\num[round-mode=places,round-precision=0]{{\\fpeval{{\\Var{{{x}}}/1000}}}}' if s else '--')
            lines.append(f'{op} & {PAPER_SET[p]} & ' + ' & '.join(cells) + r' \\')
        lines.append(r'\addlinespace')
    lines[-1:] = [r'\bottomrule', r'\end{tabular}']
    return {'tab-dmem-sizes.tex': '\n'.join(lines) + '\n'}


def mem_usage_table(vals):
    """tab-mem-usage.tex: IMEM and DMEM (excluding the message) of the 32 KiB kernels, one row per operation and
    parameter set, a DMEM/IMEM pair per tier, as the paper's memory table."""
    lines = [r'\begin{tabular}{ll' + 'r' * 8 + '}', r'\toprule',
             r' & & ' + ' & '.join(f'\\multicolumn{{2}}{{c}}{{\\texttt{{{t}}}}}' for t in ('sw',) + SPEEDUP_TIERS) + r' \\',
             ''.join(f'\\cmidrule(lr){{{3 + 2 * i}-{4 + 2 * i}}}' for i in range(4)),
             r'Operation & Set & ' + ' & '.join(['DMEM & IMEM'] * 4) + r' \\', r'\midrule']
    rows = 0
    for op, k in (('keygen', 'tuned'), ('sign', 'ldirect'), ('verify', 'tuned')):
        for p in ('Ip', 'Is', 'Ip3'):
            keys = [f'mem:{op}:{k}:32:{p}:{t}' for t in ('sw',) + SPEEDUP_TIERS]
            if not all(f'{x}:dmem' in vals for x in keys):
                continue
            rows += 1
            lines.append(f'{op} & {PAPER_SET[p]} & ' + ' & '.join(f'\\num{{\\Var{{{x}:dmem}}}} & \\num{{\\Var{{{x}:imem}}}}'
                                                               for x in keys) + r' \\')
        lines.append(r'\addlinespace')
    if not rows:
        return {}
    lines[-1:] = [r'\bottomrule', r'\end{tabular}']
    return {'tab-mem-usage.tex': '\n'.join(lines) + '\n'}


# field size q and number of equations m of each parameter set (the specification): the retry model's inputs
OV = {P.short: P for P in (ov_params.OV_IP, ov_params.OV_IP3, ov_params.OV_IS)}
RETRY_MODEL = {p: (P.gf, P.o) for p, P in OV.items()}
RETRY_MODEL_LEN = 32   # message length the model figures use


def retry_records(results_dir):
    """{kernel: (manifest, rows)}: the retry record of each sign kernel, at most one each (a new run replaces the old
    record in the same commit); every evidence file and results.csv checked against its manifest."""
    out = {}
    for name in sorted(os.listdir(results_dir)) if os.path.isdir(results_dir) else []:
        if not name.startswith('retry-'):
            continue
        d = os.path.join(results_dir, name)
        m = json.loads(read(os.path.join(d, 'manifest.json')))
        files = {os.path.relpath(os.path.join(r, f), d) for r, _, fs in os.walk(d) for f in fs} - {'manifest.json'}
        if files != set(m['evidence']) or any(sha256(os.path.join(d, f)) != h for f, h in m['evidence'].items()):
            raise Refused(f'{name}: its files do not match its manifest')
        text = read(os.path.join(d, 'results.csv'))
        if hashlib.sha256(text.encode()).hexdigest() != m['results_sha256']:
            raise Refused(f'{name}: results.csv does not match its manifest')
        if m['kernel'] in out:
            raise Refused(f'two retry records of {m["kernel"]}: {out[m["kernel"]][0]["run"]} and {name}')
        rows = list(csv.DictReader(text.splitlines()))
        if (m['tier'], m['profile']) != (RETRY_TIER, RETRY_KERNELS.get(m['kernel'])) \
                or {r['param'] for r in rows} - {art['param'] for art in m['artifacts'].values()}:
            raise Refused(f'{name}: not a {RETRY_TIER} record of its kernel\'s profile, or a set without its ELF')
        out[m['kernel']] = (m, rows)
    if len({json.dumps(m['vectors'], sort_keys=True) for m, _ in out.values()}) > 1:
        raise Refused('the retry records ran different vector files')
    return out


def retry_vars(results_dir, pub=None):
    """{name: value} from the retry records (one per kernel): retrygrid:KERNEL:PARAM:LEN:RETRIES:cyc (one count over all keys),
    retrygrid:KERNEL:PARAM:LEN:step (what each measured retry adds; refused unless every one adds the same),
    retrygrid:PARAM:keys, and, where both kernels are there, the model figures at RETRY_MODEL_LEN bytes:
    retrygrid:PARAM:pfail (percent), avg:KERNEL and over:KERNEL (percent above no retry), ratio (sprec / ldirect),
    breakeven (the fewest retries in one signature at which sprec is cheaper) and tail (the chance of that many)."""
    recs = retry_records(results_dir)
    out, cyc, steps = {}, {}, {}
    for kernel, (m, rows) in sorted(recs.items()):
        if pub is not None:
            observed_binaries_match(pub, results_dir, m['run'],
                                    {(('sign', kernel, m['profile'], art['param'], m['tier']), artifact_image(art))
                                     for art in m['artifacts'].values()})
        groups, keys, seen = {}, {}, {}
        for r in rows:
            g = (r['param'], int(r['msg_len']), int(r['attempts']) - 1)
            groups.setdefault(g, set()).add(int(r['cycles']))
            seen.setdefault(g, set()).add(r['key_case'])
            keys.setdefault(r['param'], set()).add(r['key_case'])
        for (p, length, n), v in sorted(groups.items()):
            if len(v) != 1:
                raise Refused(f'{m["run"]}: {p} {length} B with {n} retries: the keys give {sorted(v)}')
            if seen[p, length, n] != keys[p]:
                raise Refused(f'{m["run"]}: {p} {length} B with {n} retries: not every key ran')
            cyc[kernel, p, length, n] = v.pop()
            out[f'retrygrid:{kernel}:{p}:{length}:{n}:cyc'] = cyc[kernel, p, length, n]
        for p, length in sorted({(p, length) for p, length, _ in groups}):
            ns = sorted(n for q, l2, n in groups if (q, l2) == (p, length))
            adds = {cyc[kernel, p, length, n] - cyc[kernel, p, length, n - 1] for n in ns[1:] if n - 1 in ns}
            if len(adds) != 1 or ns != list(range(len(ns))) or len(ns) < 3:
                raise Refused(f'{m["run"]}: {p} {length} B: retries {ns} add {sorted(adds)} cycles, not one cost each')
            steps[kernel, p, length] = adds.pop()
            out[f'retrygrid:{kernel}:{p}:{length}:step'] = steps[kernel, p, length]
        for p, k in sorted(keys.items()):
            if out.setdefault(f'retrygrid:{p}:keys', len(k)) != len(k):
                raise Refused(f'{p}: the retry records use different numbers of keys')
    for p, (q, m) in RETRY_MODEL.items():
        need = [('ldirect', p, RETRY_MODEL_LEN), ('sprec', p, RETRY_MODEL_LEN)]
        if not all(k in steps and k + (0,) in cyc for k in need):
            continue
        pf = 1 - math.prod(1 - q ** -i for i in range(1, m + 1))
        e = pf / (1 - pf)                                   # expected retries per signature
        (lb, lr), (sb, sr) = [(cyc[k + (0,)], steps[k]) for k in need]
        if lr <= sr or sb <= lb:
            raise Refused(f'{p}: no break-even (ldirect {lb} + {lr} per retry, sprec {sb} + {sr} per retry)')
        n = (sb - lb) // (lr - sr) + 1
        out[f'retrygrid:{p}:pfail'] = f'{100 * pf:.3f}'
        out[f'retrygrid:{p}:avg:ldirect'] = round(lb + e * lr)
        out[f'retrygrid:{p}:avg:sprec'] = round(sb + e * sr)
        out[f'retrygrid:{p}:over:ldirect'] = f'{100 * e * lr / lb:.2f}'
        out[f'retrygrid:{p}:over:sprec'] = f'{100 * e * sr / sb:.2f}'
        out[f'retrygrid:{p}:ratio'] = f'{(sb + e * sr) / (lb + e * lr):.2f}'
        out[f'retrygrid:{p}:breakeven'] = n
        out[f'retrygrid:{p}:tail'] = f'{pf ** n:.1e}'
    return out


def retry_tables(vals):
    """{file name: tabular}: tab-retrygrid.tex (measured cycles at 0, 1 and 2 retries and what each retry adds) and
    tab-retrymodel.tex (the model figures), from the retrygrid variables."""
    tabs = {}
    rows = sorted({tuple(n.split(':')[1:4]) for n in vals if n.startswith('retrygrid:') and n.endswith(':step')},
                  key=lambda x: (gks.PARAMS3.index(x[1]), int(x[2]), x[0]))
    if rows:
        lines = [r'\begin{tabular}{lrlrrrr}', r'\toprule', r' & & & \multicolumn{4}{c}{cycles} \\', r'\cmidrule(lr){4-7}',
                 r'Set & Message & Kernel & 0 retries & 1 retry & 2 retries & Each retry \\', r'\midrule']
        last = None
        for kernel, p, length in rows:
            if last is not None and (p, length) != last:
                lines.append(r'\addlinespace')
            last = (p, length)
            cells = [f'\\num{{\\Var{{retrygrid:{kernel}:{p}:{length}:{n}:cyc}}}}'
                     if f'retrygrid:{kernel}:{p}:{length}:{n}:cyc' in vals else '--' for n in (0, 1, 2)]
            lines.append(f'{PAPER_SET[p]} & {length}\\,B & \\kernel{{{kernel}}} & ' + ' & '.join(cells)
                         + f' & \\num{{\\Var{{retrygrid:{kernel}:{p}:{length}:step}}}} \\\\')
        tabs['tab-retrygrid.tex'] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    model = [p for p in gks.PARAMS3 if f'retrygrid:{p}:breakeven' in vals]
    if model:
        lines = [r'\begin{tabular}{lrrrrrr}', r'\toprule',
                 r'Set & Attempt fails & \kernel{ldirect} average (cycles) & \kernel{sprec} average (cycles) & \kernel{sprec} / \kernel{ldirect}'
                 r' & \kernel{sprec} cheaper from & Chance \\', r'\midrule']
        for p in model:
            lines.append(f'{PAPER_SET[p]} & \\Var{{retrygrid:{p}:pfail}}\\,\\% & \\num{{\\Var{{retrygrid:{p}:avg:ldirect}}}} & '
                         f'\\num{{\\Var{{retrygrid:{p}:avg:sprec}}}} & \\Var{{retrygrid:{p}:ratio}}$\\times$ & '
                         f'\\Var{{retrygrid:{p}:breakeven}} retries & \\num{{\\Var{{retrygrid:{p}:tail}}}} \\\\')
        tabs['tab-retrymodel.tex'] = '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'
    return tabs


def uniform_tuned_table(vals):
    """{'tab-uniform-tuned.tex': tabular}: ISS cycles of stream_uniform and tuned at 32 KiB (lowest-highest KAT case)
    and the ratio uniform / tuned, from the published variables."""
    rows = [(op, p, t) for op in ('keygen', 'verify') for p in gks.PARAMS3 for t in ('sw',) + SPEEDUP_TIERS
            if f'ratio:{op}:stream_uniform:32:tuned:32:{p}:{t}' in vals]
    if not rows:
        return {}

    lines = [r'\begin{tabular}{lllrrr}', r'\toprule',
             r'Operation & Set & Backend & \texttt{stream\_uniform} & \texttt{tuned} & Uniform / tuned \\', r'\midrule']
    last = None
    for op, p, t in rows:
        if last is not None and (op, p) != last:
            lines.append(r'\addlinespace')
        last = (op, p)
        lines.append(f'{op} & {PAPER_SET[p]} & \\texttt{{{t}}} & {var_span(vals, f"iss:{op}:stream_uniform:32:{p}:{t}")} & {var_span(vals, f"iss:{op}:tuned:32:{p}:{t}")} & '
                     f'\\Var{{ratio:{op}:stream_uniform:32:tuned:32:{p}:{t}}}$\\times$ \\\\')
    return {'tab-uniform-tuned.tex': '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'}


CONTRIB = (('keygen', 'stream_uniform'), ('sign', 'ldirect'), ('verify', 'stream_uniform'))   # one outer kernel, four backends


def contrib_table(vals):
    """{'tab-contrib.tex': tabular}: per uniform kernel at 32 KiB, each backend over sw and bngfaes over each
    single-extension backend, from the published variables."""
    def names(op, k, p):
        return [f'spd:{op}:{k}:32:{p}:{t}' for t in SPEEDUP_TIERS] + [f'both:{op}:{k}:32:{p}:{t}' for t in ('bnaesonly', 'bngfonly')]
    rows = [(op, k, p) for op, k in CONTRIB for p in gks.PARAMS3]
    if not any(n in vals for r in rows for n in names(*r)):
        return {}
    lines = [r'\begin{tabular}{llrrrrr}', r'\toprule',
             r' & & \multicolumn{3}{c}{over \texttt{sw}} & \multicolumn{2}{c}{\texttt{bngfaes} over} \\',
             r'\cmidrule(lr){3-5}\cmidrule(lr){6-7}',
             r'Operation & Set & \texttt{bngfonly} & \texttt{bnaesonly} & \texttt{bngfaes} & \texttt{bnaesonly} & \texttt{bngfonly} \\',
             r'\midrule']
    for i, (op, k, p) in enumerate(rows):
        if i and op != rows[i - 1][0]:
            lines.append(r'\addlinespace')
        lines.append(f'{op} & {PAPER_SET[p]} & ' + ' & '.join(f'\\Var{{{c}}}$\\times$' if c in vals else '--' for c in names(op, k, p))
                     + r' \\')
    return {'tab-contrib.tex': '\n'.join(lines + [r'\bottomrule', r'\end{tabular}']) + '\n'}


def paper_claims(vals):
    """{name: value}: the numbers the paper's comparisons quote, computed from the published variables: claim:
    uniform-max (the largest uniform / tuned ratio), claim:gain:tuned|uniform|what (the cell with the largest relative
    increase of the speed-up from the uniform to the tuned kernels), claim:sbuild:P|min|max (field multiplies of
    building S over those of forming L once), claim:sbuf:P:kib|over (the S buffer in KiB, and over the bytes ldirect
    touches), claim:sbuf:over:min|max, claim:ct:runs:min|max, claim:minsp:P:TIER (keygen min over sp cycles at 128 KiB),
    claim:minsp:aesonly|noaes|both:min|max (bnaesonly; sw and bngfonly; bngfaes), claim:minsp:P:save (percent less
    linked memory for min). Refused unless every comparison the text makes holds:
    tuned at least as fast as uniform (raw sums) with a speed-up at least as large (three digits); in each
    contribution row both instructions faster than either alone and than the product of the two (raw and displayed),
    bn.aes128 alone ahead of bn.gfmul alone in sign and verify and further ahead than in keygen; ldirect within
    32 KiB, sprec above 128 KiB; sprec slower without a retry at every message length and on average, an ldirect
    retry at least 90 % of a signature, one sprec retry cheaper than an ldirect signature; one key count for all
    sets; one trace per group without the table AES and differing traces with it; sp faster and min smaller in every
    tier, and min's extra passes cheaper with bn.aes128 alone than in any tier without hardware AES."""
    out = {}
    hw = {'bngfonly': r'\texttt{bn.gfmul} alone', 'bnaesonly': r'\texttt{bn.aes128} alone', 'bngfaes': 'both instructions'}

    def cyc(op, k, p, t):
        return int(vals[f'iss:{op}:{k}:32:{p}:{t}:sum'])
    ratios = [(float(v), v) for n, v in vals.items() if re.fullmatch(r'ratio:(keygen|verify):stream_uniform:32:tuned:32:\w+:\w+', n)]
    if ratios:
        if min(ratios)[0] < 1:
            raise Refused('claim: a tuned kernel is slower than its uniform one')
        out['claim:uniform-max'] = max(ratios)[1]
    gains = []
    for op in ('keygen', 'verify'):
        for p in gks.PARAMS3:
            for t in SPEEDUP_TIERS:
                if f'spd:{op}:tuned:32:{p}:{t}' in vals and f'spd:{op}:stream_uniform:32:{p}:{t}' in vals:
                    tu, un = vals[f'spd:{op}:tuned:32:{p}:{t}'], vals[f'spd:{op}:stream_uniform:32:{p}:{t}']
                    if float(tu) < float(un):
                        raise Refused(f'claim: {op} {p} {t}: the tuned speed-up {tu} is below the uniform {un}')
                    for u in (t, 'sw'):
                        if cyc(op, 'tuned', p, u) > cyc(op, 'stream_uniform', p, u):
                            raise Refused(f'claim: {op} {p} {u}: the tuned kernel is slower than the uniform one')
                    gain = (cyc(op, 'tuned', p, 'sw') / cyc(op, 'tuned', p, t)) / (
                        cyc(op, 'stream_uniform', p, 'sw') / cyc(op, 'stream_uniform', p, t))
                    gains.append((gain, op, p, t))
    if gains:
        _, op, p, t = max(gains)
        out['claim:gain:tuned'] = vals[f'spd:{op}:tuned:32:{p}:{t}']
        out['claim:gain:uniform'] = vals[f'spd:{op}:stream_uniform:32:{p}:{t}']
        out['claim:gain:what'] = f'{PAPER_SET[p]} {"key generation" if op == "keygen" else "verification"} with {hw[t]}'
    aes = {}
    for op, k in CONTRIB:
        for p in gks.PARAMS3:
            if not all(f'iss:{op}:{k}:32:{p}:{t}:sum' in vals for t in ('sw',) + SPEEDUP_TIERS):
                continue
            s = {t: cyc(op, k, p, 'sw') / cyc(op, k, p, t) for t in SPEEDUP_TIERS}
            shown = [float(vals[f'spd:{op}:{k}:32:{p}:{t}']) for t in SPEEDUP_TIERS]
            if s['bngfaes'] <= s['bngfonly'] * s['bnaesonly'] or shown[2] <= shown[0] * shown[1]:
                raise Refused(f'claim: {op} {p}: both instructions do not beat the product of the single speed-ups')
            if s['bngfaes'] <= max(s['bngfonly'], s['bnaesonly']):
                raise Refused(f'claim: {op} {p}: both instructions are not faster than either alone')
            if op != 'keygen' and s['bnaesonly'] <= s['bngfonly']:
                raise Refused(f'claim: {op} {p}: bn.aes128 alone does not gain more than bn.gfmul alone')
            aes[op, p] = s['bnaesonly']
    for (op, p), a in aes.items():
        if op == 'keygen' and any(a >= aes[o, p] for o in ('sign', 'verify') if (o, p) in aes):
            raise Refused(f'claim: keygen {p}: the AES swap does not leave more of the software time than sign/verify')
    if len({vals[f'retrygrid:{p}:keys'] for p in OV if f'retrygrid:{p}:keys' in vals}) > 1:
        raise Refused('claim: the parameter sets have different numbers of retry-grid keys')
    for name in [n for n in vals if re.fullmatch(r'retrygrid:ldirect:\w+:\d+:step', n)]:
        _, _, p, length, _ = name.split(':')
        ld0, ld, sp = vals[f'retrygrid:ldirect:{p}:{length}:0:cyc'], vals[name], vals.get(f'retrygrid:sprec:{p}:{length}:step')
        if ld < 0.9 * ld0:
            raise Refused(f'claim: {p} {length} B: an ldirect retry is less than 90 % of a signature')
        if sp is not None and (vals[f'retrygrid:sprec:{p}:{length}:0:cyc'] <= ld0 or sp >= ld0):
            raise Refused(f'claim: {p} {length} B: sprec is not slower without a retry, or its retry not cheaper '
                          'than an ldirect signature')
    minsp = {}
    for p in OV:
        for t in ('sw',) + SPEEDUP_TIERS:
            a, b = vals.get(f'iss:keygen:min:128:{p}:{t}:sum'), vals.get(f'iss:keygen:sp:128:{p}:{t}:sum')
            if a is not None and b is not None:
                if a <= b:
                    raise Refused(f'claim: keygen {p} {t}: sp is not faster than min')
                minsp[p, t] = a / b
                out[f'claim:minsp:{p}:{t}'] = times(a, b)[:-1]
        a, b = vals.get(f'mem:keygen:min:128:{p}:bngfaes:bss'), vals.get(f'mem:keygen:sp:128:{p}:bngfaes:bss')
        if a not in (None, '') and b not in (None, ''):
            if a >= b:
                raise Refused(f'claim: keygen {p}: min does not use less memory than sp')
            out[f'claim:minsp:{p}:save'] = round(100 * (b - a) / b)
    groups = {'aesonly': ('bnaesonly',), 'noaes': ('sw', 'bngfonly'), 'both': ('bngfaes',)}
    span = {g: [r for (p, t), r in minsp.items() if t in ts] for g, ts in groups.items()}
    for g, rs in span.items():
        if rs:
            out[f'claim:minsp:{g}:min'], out[f'claim:minsp:{g}:max'] = (times(f(rs), 1)[:-1] for f in (min, max))
    if span['aesonly'] and span['noaes'] and max(span['aesonly']) >= min(span['noaes']):
        raise Refused('claim: keygen min is not cheaper relative to sp with bn.aes128 alone than without hardware AES')
    runs = [vals[n] for n in vals if re.fullmatch(r'ct:\w+:\w+:runs', n)]
    if runs:
        out['claim:ct:runs:min'], out['claim:ct:runs:max'] = min(runs), max(runs)
    for p in OV:
        if f'retrygrid:{p}:ratio' in vals and float(vals[f'retrygrid:{p}:ratio']) <= 1:
            raise Refused(f'claim: sprec {p} is not slower than ldirect on average')
        for t in SPEEDUP_TIERS:
            if f'ct:{p}:{t}:whole' in vals and (vals[f'ct:{p}:{t}:whole'], vals[f'ct:{p}:{t}:bodies']) != (1, 1):
                raise Refused(f'claim: {p} {t}: signing traces differ although the tier has no table AES')
        if f'ct:{p}:sw:whole' in vals and vals[f'ct:{p}:sw:whole'] <= 1:
            raise Refused(f'claim: {p} sw: the table AES no longer gives traces that differ between runs')
    for p in OV:
        fits, large = vals.get(f'mem:sign:ldirect:32:{p}:bngfaes:bss'), vals.get(f'mem:sign:sprec:512:{p}:bngfaes:bss')
        if fits not in (None, '') and int(fits) > 32 * 1024:
            raise Refused(f'claim: ldirect {p} does not fit 32 KiB')
        if large not in (None, '') and int(large) <= 128 * 1024:
            raise Refused(f'claim: sprec {p} would fit 128 KiB')
    build, over = {}, {}
    for p, P in OV.items():
        build[p] = P.v * (P.v - 1) * P.o ** 2 / (P.v * (P.v - 1) * P.o + 2 * P.v * P.o ** 2)
        out[f'claim:sbuild:{p}'] = times(build[p], 1)[:-1]
        sbytes = P.v * P.o * P.pub_m_byte
        out[f'claim:sbuf:{p}:kib'] = round(sbytes / 1024)
        if f'span:sign:ldirect:32:{p}:bngfaes:touched' in vals:
            over[p] = sbytes / int(vals[f'span:sign:ldirect:32:{p}:bngfaes:touched'])
            out[f'claim:sbuf:{p}:over'] = times(over[p], 1)[:-1]
    out['claim:sbuild:min'], out['claim:sbuild:max'] = (times(f(build.values()), 1)[:-1] for f in (min, max))
    if over:
        out['claim:sbuf:over:min'], out['claim:sbuf:over:max'] = (times(f(over.values()), 1)[:-1] for f in (min, max))
    return out


def run_paper(a):
    """Write vars.tex (every published number as a DefineVar line) and the generated tabulars into --out, from the
    published records of this tree. Exit 0: written; 2: the records are broken or a cell is missing."""
    results_dir = os.path.join(REPO, RESULTS)
    try:
        pub = published(REPO)
        vals = paper_vars(pub, results_dir)
        tabs = paper_tables(vals)
        vals.update(observe_vars(results_dir, pub))
        tabs.update(observe_tables(vals))
        vals.update(retry_vars(results_dir, pub))
        tabs.update(retry_tables(vals))
        tabs.update(uniform_tuned_table(vals))
        tabs.update(contrib_table(vals))
        vals.update(mem_usage_vars(pub, results_dir))
        tabs.update(mem_usage_table(vals))
        tabs.update(dmem_size_table(vals))
        vals.update(paper_claims(vals))
    except (Stop, Refused) as e:
        fail(f'nothing written: {e}')
    head = subprocess.run(['git', 'rev-parse', '--short=10', 'HEAD'], cwd=REPO, capture_output=True, text=True).stdout.strip()
    stamp = f'% Generated by tools/uov.py paper from the published records (tree at {head}); do not edit by hand.\n'
    os.makedirs(a.out, exist_ok=True)
    write_atomic(os.path.join(a.out, 'vars.tex'),
                 stamp + ''.join(f'\\DefineVar{{{n}}}{{{v}}}\n' for n, v in vals.items()))
    for name, text in tabs.items():
        write_atomic(os.path.join(a.out, name), stamp + text)
    print(f'{len(vals)} variables and {len(tabs)} tabulars written to {a.out}')
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('campaign-init', help='write a campaign definition into the publication checkout')
    p.add_argument('--name', required=True, help='campaign name (letters, digits, . _ -)')
    p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout the records are published into')
    p.add_argument('--profiles', default='32,128,512', help='DMEM profiles whose cohorts the campaign holds (default all)')
    for cmd, helptext in (('iss', 'run one cohort of a campaign and publish its record'),
                          ('campaign-run', 'run the unpublished cohorts of one profile, slowest first')):
        p = sub.add_parser(cmd, help=helptext)
        p.add_argument('--campaign', required=True, help='the campaign name')
        if cmd == 'iss':
            p.add_argument('--cohort', required=True, metavar='OP/VARIANT/TIER/PARAM', help='e.g. keygen/full/bngfaes/Ip')
        else:
            p.add_argument('--profile', type=int, required=True, choices=sorted(PROFILES), help='DMEM profile of this tree')
        p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout holding the campaign definition')
        p.add_argument('--workers', type=int, default=8, help='cases run at once (default 8)')
        p.add_argument('--timeout', type=float, default=21600, metavar='SECONDS', help='per case (default 6 h)')
    p = sub.add_parser('publish', help='finish publishing a finalised run')
    p.add_argument('--run', required=True, metavar='DIR', help='chip-matrix/<run> of this tree')
    p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout holding the campaign definition')
    p = sub.add_parser('rtl-init', help='register chip-RTL measurements: write their definition into the publication checkout')
    p.add_argument('--name', required=True, help='name of the registration (letters, digits, . _ -)')
    p.add_argument('--measured-at', required=True, metavar='COMMIT', help='the commit the run directories were measured at')
    p.add_argument('--bazelrc-site', required=True, metavar='FILE', help='the local .bazelrc-site the measuring trees used')
    p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout the records are published into')
    p = sub.add_parser('rtl-import', help='publish finished tools/rtl_campaign.sh run directories, a whole profile at a time')
    p.add_argument('--campaign', required=True, help='the name given to rtl-init')
    p.add_argument('--archive', required=True, action='append', metavar='DIR',
                   help='a finished run directory; repeat it for every run of the profile')
    p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout holding the definition')
    p = sub.add_parser('retry', help='run one sign kernel on a vector set with known retries and publish its record')
    p.add_argument('--kernel', required=True, choices=sorted(RETRY_KERNELS),
                   help='ldirect (this tree at 32 KiB) or sprec (this tree at 512 KiB); tier bngfaes')
    p.add_argument('--vectors', default='retrygrid', help='vector set: test_data/testvectors-<P>-pkc-skc.NAME (default retrygrid)')
    p.add_argument('--params', default='Ip,Ip3,Is', help='parameter sets (default Ip,Ip3,Is)')
    p.add_argument('--publish-to', required=True, metavar='CHECKOUT', help='the checkout the record is published into')
    p.add_argument('--workers', type=int, default=12, help='cases run at once (default 12)')
    p.add_argument('--timeout', type=float, default=7200, metavar='SECONDS', help='per case (default 2 h)')
    p = sub.add_parser('tables', help='rewrite the marked README tables from the published records')
    p.add_argument('--check', action='store_true', help='write nothing; exit 1 if a file would change')
    p = sub.add_parser('paper', help='write the paper tables (vars.tex and tabulars) from the published records')
    p.add_argument('--out', required=True, metavar='DIR', help='the paper tables directory to write into')
    p = sub.add_parser('mem-usage', help='write the memory usage of the 32 KiB kernels')
    p.add_argument('--elf-root', required=True, metavar='DIR', help='tree of the built ELFs, laid out like bazel-bin')
    p.add_argument('--observed', required=True, metavar='DIR', help='the per-cell files of tools/dmem_usage.py run')
    p = sub.add_parser('profile', help='switch the DMEM profile of this clone (never commit the result)')
    p.add_argument('--profile', type=int, required=True, choices=sorted(PROFILES),
                   help='total DMEM in KiB: 32 (shipped), 128 (one-shot), 512 (ISS only)')
    a = ap.parse_args()
    timeout = getattr(a, 'timeout', 1)
    if getattr(a, 'workers', 1) < 1 or not (math.isfinite(timeout) and timeout > 0):
        ap.error('--workers must be positive and --timeout positive and finite')
    cmd = {'campaign-init': campaign_init, 'iss': run_iss, 'campaign-run': run_campaign, 'publish': run_publish,
           'rtl-init': rtl_init, 'rtl-import': run_rtl_import, 'tables': run_tables, 'profile': run_profile,
           'paper': run_paper, 'retry': run_retry, 'mem-usage': run_mem_usage}[a.cmd]
    try:
        return cmd(a)
    except Exception:                    # a crash stops; exit 1 is only a cohort that ran and was not accepted
        traceback.print_exc()
        return 2


if __name__ == '__main__':
    sys.exit(main())

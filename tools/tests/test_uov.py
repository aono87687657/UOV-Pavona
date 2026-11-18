"""uov.py rules that need no build or simulator: layout, ELF pick, acceptance, campaign definitions,
record finalisation, publication and provenance, the registration and import of chip-RTL run
directories, and the README tables written from the published records."""
import contextlib
import csv
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/
import uov

GRID = [('keygen', p, 'bngfaes', 'full', c) for p in ('Ip', 'Is') for c in range(12)]    # (op, param, tier, variant, case)


def rows(params=('Ip', 'Is'), cases=range(12), cycles=1000):
    return [dict(op='keygen', param=p, tier='bngfaes', variant='full', case=str(c), kat='PASS',
                 instructions='900', cycles=str(cycles)) for p in params for c in cases]


def write_csv(path, rs):
    with open(path, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rs[0]), lineterminator='\n')   # as published
        w.writeheader()
        w.writerows(rs)


for _k in [k for k in os.environ if k.startswith('GIT_')]:     # no inherited GIT_DIR/GIT_WORK_TREE/... redirects git
    del os.environ[_k]


def git(path, *cmd):
    return subprocess.run(['git', *cmd], cwd=path, check=True, capture_output=True, text=True).stdout


def git_init(path):
    """A git repository of the test's own, in its temp directory (the only place tests may commit)."""
    os.makedirs(os.path.join(path, '.nohooks'), exist_ok=True)
    git(path, 'init', '-q')
    for k, v in (('user.email', 't@t'), ('user.name', 't'), ('core.fileMode', 'true'), ('commit.gpgsign', 'false'),
                 ('core.hooksPath', os.path.join(path, '.nohooks'))):
        git(path, 'config', k, v)
    top, gitdir = git(path, 'rev-parse', '--show-toplevel', '--absolute-git-dir').split()
    assert os.path.realpath(top) == os.path.realpath(path) and gitdir.startswith(os.path.realpath(path)), (top, gitdir)


def commit_all(path, msg='x'):
    git(path, 'add', '-A')
    git(path, 'commit', '-qm', msg)
    return git(path, 'rev-parse', 'HEAD').strip()


def same_tree(a, b):
    def files(d):
        return {os.path.relpath(os.path.join(r, f), d): uov.sha256(os.path.join(r, f)) for r, _, fs in os.walk(d) for f in fs}
    return files(a) == files(b)


class Basics(unittest.TestCase):
    def test_layout_from_profile_table(self):
        self.assertEqual(uov.expected_layout(512), {'dmem_address': 0x80000, 'dmem_bus_bytes': 523264, 'dmem_bytes': 524288})
        self.assertEqual(uov.expected_layout(32), {'dmem_address': 0x18000, 'dmem_bus_bytes': 31744, 'dmem_bytes': 32768})

    def test_a_failed_bazel_call_stops(self):
        with mock.patch.object(uov.subprocess, 'run', return_value=mock.Mock(returncode=1, stdout='', stderr='')), \
                self.assertRaises(uov.Stop):
            uov.bazel('build', '//x')

    def test_cli_refuses_a_non_finite_timeout(self):
        for bad in ('inf', 'nan', '0'):
            argv = ['uov.py', 'iss', '--campaign', 'c', '--cohort', 'a/b/c/d', '--publish-to', '.', '--timeout', bad]
            with self.subTest(bad), mock.patch.object(sys, 'argv', argv), mock.patch.object(uov, 'run_iss') as run, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
                uov.main()
            self.assertEqual(e.exception.code, 2)
            run.assert_not_called()
        with mock.patch.object(sys, 'argv', argv[:-1] + ['5']), mock.patch.object(uov, 'run_iss', return_value=0) as run:
            self.assertEqual(uov.main(), 0)                                    # a finite timeout reaches the command
        run.assert_called_once()
        with mock.patch.object(sys, 'argv', argv[:-1] + ['5']), mock.patch.object(uov, 'run_iss', side_effect=KeyError('x')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(uov.main(), 2)                                    # a crash is a stop, not a failed cohort


class Inputs(unittest.TestCase):
    COHORT = {'op': 'verify', 'param': 'Ip3', 'variant': 'full'}

    def test_second_key_is_a_required_input(self):
        with mock.patch.object(uov, 'build_inputs', return_value=set()):
            self.assertIn('sw/acc/crypto/handwritten/test_data/testvectors-Ip3-pkc-skc.nistkat',
                          uov.input_paths(self.COHORT, [], None))
            with mock.patch.object(uov.gks, 'aux_inputs', return_value=[os.path.join(uov.REPO, 'missing.nistkat')]), \
                    self.assertRaisesRegex(uov.Stop, 'required inputs missing'):
                uov.input_paths(self.COHORT, [], None)


class ElfPick(unittest.TestCase):
    LAB = '//sw/x/ov-Ip-pkc+skc:ov-Ip-keygen_test'

    def test_one_elf_per_label(self):
        files = ['bazel-out/k/bin/sw/x/ov-Ip-pkc+skc/ov-Ip-keygen_test.elf', 'bazel-out/k/bin/sw/x/ov-Ip-pkc+skc/ov-Ip-keygen_test.rv32embed.o']
        self.assertEqual(uov.pick_elves(files, [self.LAB])[self.LAB], files[0])
        for bad in ([], [files[0], 'bazel-out/j/bin/sw/x/ov-Ip-pkc+skc/ov-Ip-keygen_test.elf']):
            with self.subTest(n=len(bad)), self.assertRaises(uov.Stop):
                uov.pick_elves(bad, [self.LAB])

    def test_published_names_are_not_gitignored(self):
        names = sorted(uov.evidence_names(GRID) | {'manifest.json'})
        paths = ([f'{uov.RESULTS}/iss-512-x/{n}' for n in names] + [f'{uov.RESULTS}/README.md']
                 + [f'{uov.CAMPAIGNS}/c.json', f'{uov.CAMPAIGNS}/c.completed.json'])
        r = subprocess.run(['git', 'check-ignore', '--no-index', *paths], cwd=uov.REPO, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (1, ''), f'published files the repo would ignore: {r.stderr}')

    def test_label_from_logical_path(self):
        self.assertEqual(uov.label_of('sw/x/ov-Ip-pkc+skc/ov-Ip-keygen_test.elf'), self.LAB)

    def test_build_options_blank_local_paths_only(self):
        ev = {'id': {'optionsParsed': {}}, 'optionsParsed': {'cmdLine': [
            '--override_repository=r=/var/cache/x', '--flag_alias=a=//sw/x:y', '--copt=-O2',
            '--build_event_json_file=/tmp/b.json']}}
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            fh.write(json.dumps({'id': {'started': {}}}) + '\n' + json.dumps(ev) + '\n')
        try:
            self.assertEqual(uov.build_options(fh.name), ['--override_repository=r=<local>', '--flag_alias=a=//sw/x:y',
                                                          '--copt=-O2', '--build_event_json_file=<local>'])
        finally:
            os.remove(fh.name)


class Acceptance(unittest.TestCase):
    def test_exact_grid_accepted(self):
        self.assertEqual(uov.accept(rows(), GRID, 0), [])

    def test_blocked(self):
        dup = rows() + rows(params=('Ip',), cases=(0,))
        missing = rows()[:-1]
        extra = rows() + [dict(rows()[0], case='12')]
        failed = [dict(r, kat='FAIL') if r['case'] == '3' else r for r in rows()]
        nocount = [dict(r, cycles='') if r['case'] == '5' else r for r in rows()]
        for name, rs, code in (('duplicate', dup, 0), ('missing', missing, 0), ('extra', extra, 0),
                               ('fail', failed, 0), ('counts', nocount, 0), ('exit', rows(), 1)):
            with self.subTest(name):
                self.assertNotEqual(uov.accept(rs, GRID, code), [])


def cohort(op='keygen', variant='full', tier='bngfaes', param='Ip', profile=512):
    return uov.canonical_cohort(dict(profile=profile, op=op, variant=variant, tier=tier, param=param))


COHORT = cohort()
COHORT_IS = cohort(param='Is')
RUN = 'iss-512-20261003T000000Z-{:08x}'.format


class CampaignFixture(unittest.TestCase):
    """A scratch publication checkout with a committed definition, and finalised records for it."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.checkout = os.path.join(self.tmp.name, 'pub')
        git_init(self.checkout)
        self.committed = {}              # what the scratch checkout's HEAD holds: rel path -> bytes
        p = mock.patch.object(uov, 'head_blob', lambda checkout, rel: self.committed.get(rel))
        p.start()
        self.addCleanup(p.stop)
        os.makedirs(os.path.join(self.checkout, uov.CAMPAIGNS))
        self.write_definition([COHORT, COHORT_IS])

    def tearDown(self):
        self.tmp.cleanup()

    def write_definition(self, cohorts, name='c1', commit=True, **kw):
        d = {'schema': 1, 'name': name, 'created': 'now', 'tooling_commit': 'a' * 40, 'config': {'.bazelrc-site': None},
             'overlays': {'512': {}}, 'cohorts': cohorts}
        d.update(kw)
        path, _ = uov.campaign_files(self.checkout, name)
        with open(path, 'w') as fh:
            json.dump(d, fh)
        if commit:
            self.commit(path)
        return uov.load_definition(self.checkout, name)

    def commit(self, path):
        with open(path, 'rb') as fh:
            self.committed[os.path.relpath(path, self.checkout)] = fh.read()

    def record(self, run_id, cohort=COHORT, cycles=7, csv_cycles=None, name='c1', spread=0, facts=None, aux=True,
               extra_inputs=(), retries=None, driver=None, layout='current', **manifest_kw):
        """A finalised schema-2 record as run_cohort leaves it in chip-matrix/<run>/record; case 3 takes
        spread more cycles; facts are further ELF facts of its artifact. A sign case's driver output holds its
        attempt counter (retries: case -> counter, else 0), or driver as it stands."""
        defn, dsha = uov.load_definition(self.checkout, name)
        rec = os.path.join(self.tmp.name, 'runs', run_id, 'record')
        os.makedirs(os.path.join(rec, 'cells'))
        cells = uov.cohort_cells(cohort)
        write_csv(os.path.join(rec, 'results.csv'),
                  [dict(op=op, param=p, tier=t, variant=v, case=str(c), kat='PASS', instructions='5',
                        cycles=str((csv_cycles or cycles) + spread * (c == 3))) for op, p, t, v, c in cells])
        for cell in cells:
            stem = os.path.join(rec, 'cells', uov.cell_stem(*cell))
            label = uov.gks.measurement_label(cell[0], cell[3], cell[4])    # verify/full: the 'case <c> accept' record
            with open(stem + '.stats.txt', 'w') as fh:
                fh.write((f'{label}:\n' if label else '') + 'Execution time\n--------------\n'
                         f'ACC executed 5 instructions in {cycles + spread * (cell[4] == 3)} cycles.\n')
            with open(stem + '.driver.txt', 'w') as fh:
                if cell[0] != 'sign':
                    fh.write('[PASS]\n')
                else:
                    fh.write(driver if driver is not None else f'[PASS]\n  Counter (GPR x8): {(retries or {}).get(cell[4], 0)}\n')
        vec = os.path.relpath(uov.gks.testvec_path(cohort['param']), uov.REPO)
        extra = [os.path.relpath(p, uov.REPO) for p in uov.gks.aux_inputs(cohort['op'], cohort['param'], cohort['variant'])]
        inputs = {f: 'e' * 64 for f in (*uov.REQUIRED_FILES, *cohort['drivers'], vec, *(extra if aux else []), *extra_inputs)}
        inputs[vec] = uov.sha256(uov.gks.testvec_path(cohort['param']))           # the real vector file
        rel = uov.gks.elf_of(cohort['op'], cohort['param'], cohort['tier'], cohort['variant'], layout)
        m = {'schema': 2, 'run': run_id, 'engine': 'iss', 'campaign': name, 'definition': dsha, 'cohort': cohort,
             'protocol': cohort['protocol'], 'profile': uov.expected_layout(cohort['profile']),
             'source': {'commit': defn['tooling_commit'], 'overlay': defn['overlays'][str(cohort['profile'])],
                        'config': defn['config'], 'inputs': inputs, 'vectors': {vec: inputs[vec]}},
             'execution': {'workers': 4, 'timeout': 3600.0},
             'artifacts': {uov.label_of(rel): {'elf': rel, 'sha256': 'f' * 64, **(facts or {})}},
             'completion': {'accepted': True, 'collector_exit': 0, 'cells': len(cells)}}
        m.update(manifest_kw)
        m['evidence'] = {os.path.relpath(os.path.join(r, f), rec): uov.sha256(os.path.join(r, f))
                         for r, _, fs in os.walk(rec) for f in fs}
        with open(os.path.join(rec, 'manifest.json'), 'w') as fh:
            json.dump(m, fh)
        return rec

    def done(self, name='c1'):
        _, dsha = uov.load_definition(self.checkout, name)
        return uov.load_completed(self.checkout, name, dsha)

class Campaign(CampaignFixture):
    """Definition, record and publication rules on a scratch publication checkout."""

    def test_publish_then_idempotent(self):
        rec = self.record(RUN(1))
        final = uov.publish_record(rec, self.checkout)
        self.assertTrue(same_tree(final, rec))
        self.assertEqual(self.done()[uov.cohort_key(COHORT)]['run'], RUN(1))
        self.assertEqual(uov.publish_record(rec, self.checkout), final)            # finished already: no change
        self.assertEqual(list(self.done()), [uov.cohort_key(COHORT)])

    def test_a_published_cohort_is_never_replaced(self):
        uov.publish_record(self.record(RUN(1)), self.checkout)
        with self.assertRaises(uov.Stop):
            uov.publish_record(self.record(RUN(2), cycles=8), self.checkout)
        self.assertEqual(self.done()[uov.cohort_key(COHORT)]['run'], RUN(1))
        self.assertFalse(os.path.exists(os.path.join(self.checkout, uov.RESULTS, RUN(2))))

    def test_an_interrupted_publication_is_finished(self):
        rec = self.record(RUN(1))
        shutil.copytree(rec, os.path.join(self.checkout, uov.RESULTS, RUN(1)))     # renamed, completion list not written
        uov.publish_record(rec, self.checkout)
        self.assertEqual(self.done()[uov.cohort_key(COHORT)]['run'], RUN(1))

    def test_a_different_bundle_at_the_destination_is_refused(self):
        rec = self.record(RUN(1))
        dest = os.path.join(self.checkout, uov.RESULTS, RUN(1))
        shutil.copytree(rec, dest)
        with open(os.path.join(dest, 'results.csv'), 'a') as fh:
            fh.write('x\n')
        with self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)
        self.assertEqual(self.done(), {})

    def test_contradictory_or_missing_provenance_is_refused(self):
        defn, _ = uov.load_definition(self.checkout, 'c1')
        rel = uov.gks.elf_of('keygen', 'Ip', 'bngfaes', 'full')
        bad = {'no source': dict(source=None), 'other commit': dict(source={'commit': 'b' * 40}),
               'no execution': dict(execution=None), 'infinite timeout': dict(execution={'workers': 4, 'timeout': float('inf')}),
               'no artifact': dict(artifacts={}),
               'other ELF': dict(artifacts={uov.label_of(rel): {'elf': 'x.elf', 'sha256': 'f' * 64}})}
        for i, (name, kw) in enumerate(bad.items()):
            with self.subTest(name), self.assertRaises(uov.Stop):
                uov.publish_record(self.record(RUN(100 + i), **kw), self.checkout)
        rec = self.record(RUN(120))                                           # vectors not among the hashed inputs
        m = json.loads(uov.read(os.path.join(rec, 'manifest.json')))
        m['source']['vectors'] = {'other': 'e' * 64}
        with open(os.path.join(rec, 'manifest.json'), 'w') as fh:
            json.dump(m, fh)
        with self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)
        self.assertEqual(self.done(), {})

    def test_an_unsafe_run_id_is_refused(self):
        rec = self.record(RUN(30))
        m = json.loads(uov.read(os.path.join(rec, 'manifest.json')))
        m['run'] = '../../x'
        with open(os.path.join(rec, 'manifest.json'), 'w') as fh:
            json.dump(m, fh)
        with self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)

    def test_a_copy_changed_while_staging_never_goes_live(self):
        rec = self.record(RUN(31))
        real = shutil.copytree

        def copy_then_edit(src, dst, *a, **kw):
            real(src, dst, *a, **kw)
            with open(os.path.join(dst, 'results.csv'), 'a') as fh:
                fh.write('x\n')
        with mock.patch.object(uov.shutil, 'copytree', copy_then_edit), self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)
        self.assertFalse(os.path.exists(os.path.join(self.checkout, uov.RESULTS, RUN(31))))
        self.assertEqual(self.done(), {})

    def test_completion_entries_are_checked_against_their_records(self):
        uov.publish_record(self.record(RUN(40)), self.checkout)
        defn, dsha = uov.load_definition(self.checkout, 'c1')
        self.assertEqual(list(uov.completed_records(self.checkout, 'c1', defn, dsha)), [uov.cohort_key(COHORT)])
        a = mock.Mock(publish_to=self.checkout, campaign='c1', profile=32, workers=1, timeout=10.0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            uov.run_campaign(a)                                                # no 32 KiB cohort in this campaign
        self.assertEqual(e.exception.code, 2)
        _, done_path = uov.campaign_files(self.checkout, 'c1')
        good = uov.read(done_path)
        with open(done_path, 'w') as fh:                                       # an entry for a cohort not in the definition
            fh.write(good.replace(uov.cohort_key(COHORT), uov.cohort_key(dict(COHORT, profile=32))))
        with self.assertRaises(uov.Stop):
            uov.completed_records(self.checkout, 'c1', defn, dsha)
        with open(done_path, 'w') as fh:
            fh.write(good)
        bundle = os.path.join(self.checkout, uov.RESULTS, RUN(40))
        with open(os.path.join(bundle, 'cells', os.listdir(os.path.join(bundle, 'cells'))[0]), 'a') as fh:
            fh.write('edited\n')                                              # evidence no longer matches its manifest
        with self.assertRaises(uov.Stop):
            uov.completed_records(self.checkout, 'c1', defn, dsha)
        shutil.rmtree(bundle)                                                 # the listed record is gone
        with self.assertRaises(uov.Stop):
            uov.completed_records(self.checkout, 'c1', defn, dsha)
        a.profile = 512
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(uov.run_campaign(a), 2)

    def test_publish_run_refuses_while_another_entry_is_broken(self):
        uov.publish_record(self.record(RUN(60)), self.checkout)
        _, done_path = uov.campaign_files(self.checkout, 'c1')
        good = uov.read(done_path)
        rec_is = self.record(RUN(61), cohort=COHORT_IS)
        breakages = {'bundle deleted': lambda: shutil.rmtree(os.path.join(self.checkout, uov.RESULTS, RUN(60))),
                     'unknown cohort': lambda: open(done_path, 'w').write(
                         good.replace(uov.cohort_key(COHORT), uov.cohort_key(dict(COHORT, profile=32))))}
        for name, brk in breakages.items():
            with self.subTest(name):
                saved = os.path.join(self.tmp.name, 'saved')
                shutil.copytree(os.path.join(self.checkout, uov.RESULTS, RUN(60)), saved)
                brk()
                with contextlib.redirect_stderr(io.StringIO()):
                    rc = uov.run_publish(mock.Mock(run=os.path.dirname(rec_is), publish_to=self.checkout))
                self.assertEqual(rc, 2)
                self.assertFalse(os.path.exists(os.path.join(self.checkout, uov.RESULTS, RUN(61))))
                with open(done_path, 'w') as fh:                               # restore for the next breakage
                    fh.write(good)
                if not os.path.exists(os.path.join(self.checkout, uov.RESULTS, RUN(60))):
                    shutil.copytree(saved, os.path.join(self.checkout, uov.RESULTS, RUN(60)))
                shutil.rmtree(saved)

    def test_a_manifest_swapped_while_waiting_for_the_lock_is_not_mixed_in(self):
        rec, other = self.record(RUN(62)), self.record(RUN(63))           # same evidence, only the run id differs
        real = uov.locked

        @contextlib.contextmanager
        def swap_then_lock(path):
            shutil.copyfile(os.path.join(other, 'manifest.json'), os.path.join(rec, 'manifest.json'))
            with real(path):
                yield
        with mock.patch.object(uov, 'locked', swap_then_lock), self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)
        self.assertEqual(self.done(), {})
        self.assertFalse(any(n.startswith('iss-') for n in os.listdir(os.path.join(self.checkout, uov.RESULTS))))

    def test_input_digests_must_be_sha256(self):
        for i, bad in enumerate((None, 'e' * 63, 'E' * 64, 'g' * 64, 7)):
            rec = self.record(RUN(70 + i))
            m = json.loads(uov.read(os.path.join(rec, 'manifest.json')))
            m['source']['inputs'] = {k: bad for k in m['source']['inputs']}
            m['source']['vectors'] = {k: bad for k in m['source']['vectors']}
            with open(os.path.join(rec, 'manifest.json'), 'w') as fh:
                json.dump(m, fh)
            with self.subTest(bad=bad), self.assertRaises(uov.Stop):
                uov.publish_record(rec, self.checkout)
        self.assertEqual(self.done(), {})

    def test_a_new_campaign_record_must_hash_the_second_key(self):
        ip3 = cohort(op='verify', variant='full', param='Ip3', profile=128)
        self.write_definition([ip3], name='c2', overlays={'128': {}})
        with self.assertRaisesRegex(uov.Stop, 'vector files'):
            uov.publish_record(self.record(RUN(80), cohort=ip3, name='c2', aux=False), self.checkout)
        self.assertEqual(self.done('c2'), {})
        uov.publish_record(self.record(RUN(81), cohort=ip3, name='c2'), self.checkout)
        self.assertEqual([e['run'] for e in self.done('c2').values()], [RUN(81)])

    def test_a_completion_entry_must_name_its_records_run(self):
        uov.publish_record(self.record(RUN(64)), self.checkout)
        res = os.path.join(self.checkout, uov.RESULTS)
        shutil.copytree(os.path.join(res, RUN(64)), os.path.join(res, RUN(65)))   # same manifest, other directory
        _, done_path = uov.campaign_files(self.checkout, 'c1')
        listed = uov.read(done_path)
        with open(done_path, 'w') as fh:
            fh.write(listed.replace(RUN(64), RUN(65)))
        defn, dsha = uov.load_definition(self.checkout, 'c1')
        with self.assertRaises(uov.Stop) as stop:
            uov.completed_records(self.checkout, 'c1', defn, dsha)
        self.assertIn(f'run {RUN(64)}', str(stop.exception))                    # refused for the run, nothing else

    def test_a_refused_provenance_stops_before_any_build(self):
        with mock.patch.object(uov, 'provenance', return_value=['HEAD is not the campaign tooling commit']), \
                mock.patch.object(uov, 'bazel') as bazel, mock.patch.object(uov, 'input_paths') as inputs, \
                self.assertRaises(uov.Stop):
            uov.run_cohort(self.checkout, 'c1', COHORT, 1, 10.0)
        bazel.assert_not_called()
        inputs.assert_not_called()

    def test_a_rewritten_manifest_is_not_the_published_record(self):
        uov.publish_record(self.record(RUN(41)), self.checkout)
        defn, dsha = uov.load_definition(self.checkout, 'c1')
        mpath = os.path.join(self.checkout, uov.RESULTS, RUN(41), 'manifest.json')
        m = json.loads(uov.read(mpath))
        m['execution']['workers'] = 5                                          # still a valid record on its own
        with open(mpath, 'w') as fh:
            json.dump(m, fh)
        uov.validate_record(os.path.dirname(mpath), defn, dsha)
        with self.assertRaises(uov.Stop):
            uov.completed_records(self.checkout, 'c1', defn, dsha)

    def test_a_definition_changed_during_a_campaign_stops_the_next_cohort(self):
        with mock.patch.object(uov, 'provenance', side_effect=AssertionError('ran past the definition check')), \
                self.assertRaises(uov.Stop):
            uov.run_cohort(self.checkout, 'c1', COHORT, 1, 10.0, dsha_expected='0' * 64)

    def test_exit_codes(self):
        a = mock.Mock(publish_to=self.checkout, campaign='c1', cohort='keygen/full/bngfaes/Ip', profile=512,
                      workers=1, timeout=10.0)
        for outcome, code in ((True, 0), (False, 1), (uov.Stop('drift'), 2), (OSError('disk full'), 2)):
            run = mock.Mock(side_effect=outcome) if isinstance(outcome, Exception) else mock.Mock(return_value=outcome)
            with self.subTest(outcome=outcome), mock.patch.object(uov, 'run_cohort', run), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(uov.run_iss(a), code)
                self.assertEqual(uov.run_campaign(a), code)
        a.cohort = 'keygen/full'
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            uov.run_iss(a)
        self.assertEqual(e.exception.code, 2)

    def test_a_changed_definition_is_refused(self):
        rec = self.record(RUN(1))
        self.write_definition([COHORT, COHORT_IS], tooling_commit='b' * 40)
        with self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)

    def test_tampered_or_inconsistent_records_are_refused(self):
        cases = {'counts': self.record(RUN(3), csv_cycles=9),
                 'foreign cohort': self.record(RUN(4), cohort=dict(COHORT, cases=[0]))}
        rec = self.record(RUN(5))
        with open(os.path.join(rec, 'cells', uov.cell_stem(*uov.cohort_cells(COHORT)[0]) + '.driver.txt'), 'w') as fh:
            fh.write('edited\n')
        cases['tampered'] = rec
        for name, r in cases.items():
            with self.subTest(name), self.assertRaises(uov.Stop):
                uov.publish_record(r, self.checkout)
        self.assertEqual(self.done(), {})

    def publishers(self, recs):
        # each publisher pauses between reading and writing the completion list, so without the lock
        # the two read the same list and one entry would be lost or a cohort published twice
        code = ('import os, sys, time; sys.path.insert(0, {tools!r}); import uov\n'
                'uov.head_blob = lambda checkout, rel: open(os.path.join(checkout, rel), "rb").read()\n'
                'read = uov.load_completed\n'
                'def slow(*a):\n    done = read(*a)\n    time.sleep(1)\n    return done\n'
                'uov.load_completed = slow\n'
                'try:\n    uov.publish_record(sys.argv[1], {pub!r})\nexcept uov.Stop:\n    sys.exit(3)\n')
        code = code.format(tools=os.path.dirname(os.path.abspath(uov.__file__)), pub=self.checkout)
        procs = [subprocess.Popen([sys.executable, '-c', code, r], stdout=subprocess.DEVNULL) for r in recs]
        return sorted(p.wait() for p in procs)

    def test_concurrent_publishers_keep_every_entry(self):
        self.assertEqual(self.publishers([self.record(RUN(6)), self.record(RUN(7), cohort=COHORT_IS)]), [0, 0])
        self.assertEqual(sorted(self.done()), sorted(uov.cohort_key(c) for c in (COHORT, COHORT_IS)))

    def test_two_runs_of_one_cohort_race_and_one_wins(self):
        self.assertEqual(self.publishers([self.record(RUN(8), cycles=7), self.record(RUN(9), cycles=8)]), [0, 3])
        self.assertIn(self.done()[uov.cohort_key(COHORT)]['run'], (RUN(8), RUN(9)))

    def test_definition_and_completion_checks(self):
        path, done = uov.campaign_files(self.checkout, 'c1')
        with open(done, 'w') as fh:
            json.dump({'campaign': 'c1', 'definition': 'f' * 64, 'cohorts': {}}, fh)
        with self.assertRaises(uov.Stop):
            self.done()
        for bad in ('{', '[]', json.dumps({'schema': 1, 'name': 'other'})):
            with open(path, 'w') as fh:
                fh.write(bad)
            with self.subTest(bad=bad), self.assertRaises(uov.Stop):
                uov.load_definition(self.checkout, 'c1')
        with self.assertRaises(uov.Stop):                                         # a cohort listed twice
            self.write_definition([COHORT, COHORT])
        for name, c in (('not in the catalog', cohort(tier='bngfonly')), ('other cases', dict(COHORT, cases=[0, 1])),
                        ('other driver', dict(COHORT, drivers=['d.py']))):
            with self.subTest(name), self.assertRaises(uov.Stop):
                self.write_definition([c])
        with self.assertRaises(uov.Stop):                                         # never committed
            self.write_definition([COHORT], name='c2', commit=False)
        self.write_definition([COHORT])
        with open(path, 'a') as fh:                                            # edited after it was committed
            fh.write(' ')
        with self.assertRaises(uov.Stop):
            uov.load_definition(self.checkout, 'c1')
        with self.assertRaises(SystemExit):
            uov.campaign_files(self.checkout, '../x')

    def test_canonical_refuses_this_tree_and_non_checkouts(self):
        self.assertEqual(uov.canonical(self.checkout), os.path.realpath(self.checkout))
        for bad in (uov.REPO, os.path.join(self.checkout, uov.CAMPAIGNS)):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                uov.canonical(bad)

    def test_campaign_init_writes_the_catalog_once(self):
        a = mock.Mock(publish_to=self.checkout, profiles='512')
        a.name = 'new'
        fake_git = {('status', '--porcelain', '--untracked-files=no'): '', ('rev-parse', 'HEAD'): 'c' * 40 + '\n',
                    ('show', 'c' * 40 + ':' + uov.HJSON): '{ skipto: "0x80000" }\nitems: "130816", // 512\n'}
        with mock.patch.object(uov, 'git', lambda *args: fake_git[args]):
            uov.campaign_init(a)
            self.commit(uov.campaign_files(self.checkout, 'new')[0])
            d, _ = uov.load_definition(self.checkout, 'new')
            self.assertEqual(sorted(uov.cohort_key(c) for c in d['cohorts']),
                             sorted(f'iss:{op}/{v}/bngfaes/{p}@512' for op, v in (('keygen', 'full'), ('sign', 'sprec'))
                                    for p in ('Ip', 'Is', 'Ip3')))
            self.assertEqual(d['tooling_commit'], 'c' * 40)
            self.assertEqual(d['overlays'], {'512': {}})
            self.assertTrue(all(c == uov.canonical_cohort(c) for c in d['cohorts']))
            with self.assertRaises(SystemExit):                                   # never rewritten
                uov.campaign_init(a)
        fake_git[('status', '--porcelain', '--untracked-files=no')] = ' M tools/uov.py\n'
        a.name = 'dirty'
        with mock.patch.object(uov, 'git', lambda *args: fake_git[args]), self.assertRaises(SystemExit):
            uov.campaign_init(a)


class FlatLayout(CampaignFixture):
    """The rounds measured before the folder reorg keep their folders; every later round names the current ones."""
    OLD = 'iss-2026-10f'

    def flat(self, **kw):
        return uov.canonical_cohort(dict(profile=32, **kw), 'flat')

    def old_round(self, name=OLD, commit=uov.FLAT_LAYOUT[OLD]):
        cohorts = [self.flat(op='keygen', variant='stream', tier='bngfaes', param='Ip'),
                   self.flat(op='verify', variant='stream', tier='bngfaes', param='Ip3')]
        self.write_definition(cohorts, name=name, tooling_commit=commit, overlays={'32': {}}, created='2026-10-19T20:12:37+02:00')
        return cohorts

    def test_a_round_measured_before_the_reorg_keeps_its_folders(self):
        kg, vf = self.old_round()
        self.assertIn('verify_stream_round3', vf['drivers'][0])
        for c in (kg, vf):
            uov.publish_record(self.record(RUN(1 + (c is vf)), cohort=c, name=self.OLD, layout='flat'), self.checkout)
        got = uov.published(self.checkout)['iss']
        self.assertEqual({k for k in got if k.endswith('@32')}, {uov.cohort_key(kg), uov.cohort_key(vf)})

    def test_a_later_round_must_name_the_current_folders(self):
        for name, commit in (('iss-2026-10g', uov.FLAT_LAYOUT[self.OLD]), (self.OLD, 'b' * 40)):
            with self.subTest(name=name, commit=commit), self.assertRaises(uov.Stop):
                self.old_round(name, commit)

    def test_the_label_and_the_path_are_one_pair_of_the_rounds_layout(self):
        kg, _ = self.old_round()
        rel = uov.gks.elf_of('keygen', 'Ip', 'bngfaes', 'stream', 'flat')
        for name, art in (('current path', {'elf': uov.gks.elf_of('keygen', 'Ip', 'bngfaes', 'stream')}),
                          ('other label', {'elf': rel, 'label': '//x:y'})):
            label = art.pop('label', uov.label_of(art['elf']))
            rec = self.record(RUN(3), cohort=kg, name=self.OLD, layout='flat',
                              artifacts={label: {'elf': art['elf'], 'sha256': 'f' * 64}})
            with self.subTest(name), self.assertRaises(uov.Stop):
                uov.publish_record(rec, self.checkout)
            shutil.rmtree(os.path.dirname(rec))
        self.assertEqual(self.done(self.OLD), {})

    def test_a_later_round_publishes_current_paths_and_refuses_old_ones(self):
        c = uov.canonical_cohort(dict(profile=32, op='keygen', variant='stream', tier='bngfaes', param='Ip'))
        self.write_definition([c], name='iss-2026-10g', overlays={'32': {}}, created='2026-10-20T09:00:00+02:00')
        uov.publish_record(self.record(RUN(5), cohort=c, name='iss-2026-10g'), self.checkout)
        self.assertEqual(list(self.done('iss-2026-10g')), [uov.cohort_key(c)])
        c2 = uov.canonical_cohort(dict(profile=32, op='keygen', variant='stream', tier='bngfaes', param='Is'))
        self.write_definition([c, c2], name='iss-2026-10h', overlays={'32': {}}, created='2026-10-20T10:00:00+02:00')
        with self.assertRaises(uov.Stop) as e:
            uov.publish_record(self.record(RUN(6), cohort=c2, name='iss-2026-10h', layout='flat'), self.checkout)
        self.assertIn("artifact is not the cohort's ELF", str(e.exception))

    def test_every_pinned_round_keeps_its_folders(self):
        for i, (name, commit) in enumerate(uov.FLAT_LAYOUT.items()):
            with self.subTest(name=name):
                kg, _ = self.old_round(name, commit)
                uov.publish_record(self.record(RUN(10 + i), cohort=kg, name=name, layout='flat'), self.checkout)
                self.assertEqual(list(self.done(name)), [uov.cohort_key(kg)])

    def test_the_old_ip3_driver_must_be_a_hashed_input(self):
        _, vf = self.old_round()
        rec = self.record(RUN(8), cohort=vf, name=self.OLD, layout='flat')
        path = os.path.join(rec, 'manifest.json')
        m = json.load(open(path))
        del m['source']['inputs'][vf['drivers'][0]]
        json.dump(m, open(path, 'w'))
        with self.assertRaises(uov.Stop) as e:
            uov.publish_record(rec, self.checkout)
        self.assertIn('source inputs are not sha256 digests', str(e.exception))

    def test_a_tampered_old_record_is_refused(self):
        kg, _ = self.old_round()
        rec = self.record(RUN(4), cohort=kg, name=self.OLD, layout='flat')
        with open(os.path.join(rec, 'cells', uov.cell_stem(*uov.cohort_cells(kg)[0]) + '.stats.txt'), 'a') as fh:
            fh.write('\n')
        with self.assertRaises(uov.Stop):
            uov.publish_record(rec, self.checkout)


class Tables(CampaignFixture):
    """README tables from the published records of a scratch checkout."""
    FACTS = {'segments': [[32768, 4116, 'a' * 64], [524288, 429696, 'b' * 64]], 'dmem_bss_end': 429696}
    NAME = 'iss:keygen/full@512'
    SPREC = [cohort(op='sign', variant='sprec', param=p) for p in ('Ip', 'Is')]

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(uov.gks.CAMPAIGN, {(512, 'keygen', 'full'): (('Ip', 'Is'), ('bngfaes',)),   # the fixture's cells
                                               (512, 'sign', 'sprec'): (('Ip', 'Is'), ('bngfaes',))})
        p.start()
        self.addCleanup(p.stop)
        self.write_definition([COHORT, COHORT_IS, *self.SPREC], created='2026-10-03T10:00:00+02:00')
        self.results = os.path.join(self.checkout, uov.RESULTS)

    def publish(self, n, cohort=COHORT, name='c1', facts=FACTS, **kw):
        uov.publish_record(self.record(RUN(n), cohort, name=name, facts=facts, completed=f'2026-10-0{n}T23:59:00+02:00', **kw),
                           self.checkout)

    def table(self, name=NAME):
        return uov.table(name, uov.published(self.checkout), self.results)

    def test_cycles_per_tier_and_parameter_set(self):
        self.publish(1)
        self.publish(2, COHORT_IS, cycles=9, spread=2)
        self.assertEqual(self.table(), (
            '| DMEM | tier | Ip | Is |\n|---|---|---:|---:|\n| 512 KiB | bngfaes | 7 | 9-11 |\n\n'
            'ISS cycles of one key generation (a single EXECUTE), 512 KiB DMEM profile (ISS only: no chip test runs at this profile); '
            'a range is the lowest and the highest of the 12 KAT cases.\n'
            'Every case passed. Measured 2026-10-01 to 2026-10-02 at `aaaaaaaaaa` (c1).\n'))
        only = self.table(self.NAME + ':Is')
        self.assertIn('| DMEM | tier | Is |\n|---|---|---:|\n| 512 KiB | bngfaes | 9-11 |\n', only)
        self.assertIn('Measured 2026-10-02 at', only)

    def test_paper_numbers_and_tabulars_from_the_records(self):
        p = mock.patch.object(uov, 'REPO', self.checkout)                           # records hash the files of this tree
        p.start()
        self.addCleanup(p.stop)
        self.publish(1)
        self.publish(2, COHORT_IS, cycles=9, spread=2)
        for n, c in enumerate(self.SPREC, 3):
            self.publish(n, c, cycles=n)
        out = os.path.join(self.checkout, 'tables')
        with mock.patch.dict(uov.gks.CAMPAIGN, {(512, 'keygen', 'full'): (('Ip', 'Is'), ('bngfaes',)),
                                                (512, 'sign', 'sprec'): (('Ip', 'Is'), ('bngfaes',))}, clear=True), \
                mock.patch.object(uov, 'rtl_cells', lambda: {}):
            self.assertEqual(uov.run_paper(SimpleNamespace(out=out)), 0)
        with open(os.path.join(out, 'vars.tex')) as fh:
            vars_tex = fh.read()
        with open(os.path.join(self.results, RUN(2), 'results.csv')) as fh:
            is_sum = sum(int(r['cycles']) for r in csv.DictReader(fh))
        for line in (r'\DefineVar{iss:keygen:full:512:Ip:bngfaes:lo}{7}', r'\DefineVar{iss:keygen:full:512:Is:bngfaes:lo}{9}',
                     r'\DefineVar{iss:keygen:full:512:Is:bngfaes:hi}{11}', rf'\DefineVar{{iss:keygen:full:512:Is:bngfaes:sum}}{{{is_sum}}}',
                     r'\DefineVar{cases:keygen:full:512:Ip}{12}', r'\DefineVar{mem:keygen:full:512:Ip:bngfaes:code}{4116}',
                     r'\DefineVar{mem:keygen:full:512:Ip:bngfaes:bss}{429696}', r'\DefineVar{iss:sign:sprec:512:Is:bngfaes:lo}{4}',
                     r'\DefineVar{iss:keygen:full:512:Is:bngfaes:m32}{9}', r'\DefineVar{iss:sign:sprec:512:Is:bngfaes:m32}{4}'):
            self.assertIn(line + '\n', vars_tex)
        self.assertNotIn('spd:', vars_tex)                                            # no sw tier at 512 KiB: no speed-up
        self.assertEqual(vars_tex.count('\\DefineVar{'), len(set(vars_tex.split('\n')) - {''}) - 1)   # every name once
        with open(os.path.join(out, 'tab-iss-512.tex')) as fh:
            self.assertIn('keygen & full & \\texttt{bngfaes} & \\num{7} & \\num{9}--\\num{11} & -- \\\\\n', fh.read())
        with open(os.path.join(out, 'tab-cycles.tex')) as fh:
            self.assertIn('512\\,KiB & keygen & \\kernel{full} & uov-Is & -- & -- & -- & '      # the 32-byte case (6), not 9-11
                          '\\num[round-mode=figures,round-precision=3]{\\fpeval{\\Var{iss:keygen:full:512:Is:bngfaes:m32}/1000000}} \\\\\n', fh.read())
        self.assertEqual(sorted(os.listdir(out)), ['tab-cycles.tex', 'tab-iss-512.tex', 'tab-mem.tex', 'tab-retry.tex', 'tab-rtl-cycles.tex',
                                                   'tab-rtl-speedup-op.tex', 'tab-rtl-speedup.tex', 'tab-speedup.tex', 'vars.tex'])

    def test_paper_rtl_cycles_table_beside_the_iss_one(self):
        vals = {'iss:sign:ldirect:32:Ip:bngfaes:lo': 269284, 'iss:sign:ldirect:32:Ip:bngfaes:hi': 271092,
                'iss:sign:ldirect:32:Ip:bngfaes:m32': 269356, 'rtl:sign:ldirect:32:Ip:bngfaes:exec_wait': 270337,
                'iss:sign:sprec:512:Ip:bngfaes:lo': 9, 'iss:sign:sprec:512:Ip:bngfaes:hi': 9, 'iss:sign:sprec:512:Ip:bngfaes:m32': 9,
                'iss:verify:tuned:32:Ip:bngfaes:lo': 5, 'iss:verify:tuned:32:Ip:bngfaes:hi': 5, 'iss:verify:tuned:32:Ip:bngfaes:m32': 5}
        tabs = uov.paper_tables(vals)
        self.assertIn('32\\,KiB & sign & \\kernel{ldirect} & uov-Ip-r2 & -- & -- & -- & \\num[round-mode=figures,round-precision=3]'
                      '{\\fpeval{\\Var{rtl:sign:ldirect:32:Ip:bngfaes:exec_wait}/1000000}} \\\\\n', tabs['tab-rtl-cycles.tex'])
        self.assertNotIn('sprec', tabs['tab-rtl-cycles.tex'])                      # no chip run at 512 KiB: no row
        self.assertIn('512\\,KiB & sign & \\kernel{sprec}', tabs['tab-cycles.tex'])
        self.assertIn('32\\,KiB & verify & \\kernel{tuned}$^\\dagger$ & uov-Ip-r2', tabs['tab-cycles.tex'])     # streamed: marked

    def test_32_byte_case_only_from_the_vector_file_the_records_ran(self):
        digest = uov.sha256(uov.gks.testvec_path('Ip'))
        self.assertEqual(uov.kat_case_of_len('Ip', 32, digest), 6)                # messages 0, 1, 2, 4, ..., 1024 B
        with self.assertRaisesRegex(uov.Refused, 'not the vector file the records ran'):
            uov.kat_case_of_len('Ip', 32, 'f' * 64)                                # a reordered file would move case 6

    def test_paper_refuses_a_retried_32_byte_case(self):
        p = mock.patch.object(uov, 'REPO', self.checkout)
        p.start()
        self.addCleanup(p.stop)
        self.publish(1)
        self.publish(2, COHORT_IS)
        for n, c in enumerate(self.SPREC, 3):
            self.publish(n, c, cycles=n, retries={6: 1})                           # the 32-byte case signed on a retry
        err = io.StringIO()
        with mock.patch.dict(uov.gks.CAMPAIGN, {(512, 'keygen', 'full'): (('Ip', 'Is'), ('bngfaes',)),
                                                (512, 'sign', 'sprec'): (('Ip', 'Is'), ('bngfaes',))}, clear=True), \
                mock.patch.object(uov, 'rtl_cells', lambda: {}), contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as e:
            uov.run_paper(SimpleNamespace(out=os.path.join(self.checkout, 'tables')))
        self.assertEqual(e.exception.code, 2)
        self.assertIn('the 32-byte case 6 is missing or retried', err.getvalue())

    def test_paper_numbers_come_from_the_later_campaign(self):
        p = mock.patch.object(uov, 'REPO', self.checkout)
        p.start()
        self.addCleanup(p.stop)
        for n, c in enumerate([COHORT, COHORT_IS, *self.SPREC], 1):                 # c1: the earlier generation
            self.publish(n, c, cycles=7)
        self.write_definition([COHORT], name='c2', created='2026-10-05T10:00:00+02:00')
        self.publish(5, name='c2', cycles=5)                                        # c2 measures one cell again
        out = os.path.join(self.checkout, 'tables')
        with mock.patch.dict(uov.gks.CAMPAIGN, {(512, 'keygen', 'full'): (('Ip', 'Is'), ('bngfaes',)),
                                                (512, 'sign', 'sprec'): (('Ip', 'Is'), ('bngfaes',))}, clear=True), \
                mock.patch.object(uov, 'rtl_cells', lambda: {}):
            self.assertEqual(uov.run_paper(SimpleNamespace(out=out)), 0)
        with open(os.path.join(out, 'vars.tex')) as fh:
            self.assertIn(r'\DefineVar{iss:keygen:full:512:Ip:bngfaes:lo}{5}' + '\n', fh.read())   # c2, not c1's 7

    def test_every_family_of_a_profile(self):
        for n, c in enumerate([COHORT, COHORT_IS, *self.SPREC], 1):
            self.publish(n, c, cycles=n)
        self.assertIn('| DMEM | op | kernel | tier | Ip | Is |\n|---|---|---|---|---:|---:|\n| 512 KiB | keygen | full | bngfaes | 1 | 2 |\n'
                      '| 512 KiB | sign | sprec | bngfaes | 3 | 4 |\n\nISS cycles of one operation per kernel family, 512 KiB DMEM profile (ISS only: no chip test runs at this profile); '
                      'the same in all 12 KAT cases.\nEvery case passed. Measured 2026-10-01 to 2026-10-04 at',
                      self.table('iss:all@512'))
        pub = uov.published(self.checkout)
        with mock.patch.dict(uov.gks.CAMPAIGN, {(512, 'sign', 'sprec'): (('Ip',), ('bngfaes',))}):   # a family without Is
            self.assertIn('| 512 KiB | sign | sprec | bngfaes | 3 | - |\n', uov.iss_all(pub, self.results, 512))

    def test_ip3_cells_with_the_full_catalog(self):
        # the shipped catalog lists Ip3 for keygen full and sprec: once their records exist the 512 KiB tables show them
        ip3 = [cohort(param='Ip3'), cohort(op='sign', variant='sprec', param='Ip3')]
        full = {(512, op, v): (uov.gks.PARAMS3, ('bngfaes',)) for op, v in (('keygen', 'full'), ('sign', 'sprec'))}
        with mock.patch.dict(uov.gks.CAMPAIGN, full):
            self.write_definition([COHORT, COHORT_IS, *self.SPREC, *ip3], created='2026-10-03T10:00:00+02:00')
            for n, c in enumerate([COHORT, COHORT_IS, *self.SPREC, *ip3], 1):
                self.publish(n, c, cycles=n)
            self.assertIn('| DMEM | op | kernel | tier | Ip | Is | Ip3 |\n|---|---|---|---|---:|---:|---:|\n'
                          '| 512 KiB | keygen | full | bngfaes | 1 | 2 | 5 |\n| 512 KiB | sign | sprec | bngfaes | 3 | 4 | 6 |\n',
                          self.table('iss:all@512'))

    def test_speed_up_over_sw_adds_up_the_cases(self):
        tiers = {'bngfaes': dict(cycles=2, spread=12), 'bngfonly': dict(cycles=50), 'sw': dict(cycles=100)}
        cohorts = {t: cohort(op='verify', variant='full', tier=t, profile=128) for t in tiers}
        self.write_definition(list(cohorts.values()), name='v', created='2026-10-04T10:00:00+02:00', overlays={'128': {}})
        for n, (t, kw) in enumerate(tiers.items(), 1):
            uov.publish_record(self.record(RUN(n).replace('iss-512', 'iss-128'), cohorts[t], name='v',
                                           completed='2026-10-04T12:00:00+02:00', **kw), self.checkout)
        with mock.patch.dict(uov.gks.CAMPAIGN, {(128, 'verify', 'full'): (('Ip',), tuple(tiers))}):   # three tiers only
            t = self.table('iss-speedup:verify/full@128:Ip')
        self.assertIn('Times faster than sw (sw cycles / tier cycles), ISS\n\n| DMEM | tier | Ip |\n|---|---|---:|\n'
                      '| 128 KiB | bngfonly | 2x |\n| 128 KiB | bngfaes | 33.3x |\n\nThe cycles of the KAT cases added up per row, '
                      'sw divided by the tier. -: no run of that tier.\nISS, 128 KiB DMEM profile. Measured', t)     # no retry, no note
        with self.assertRaises(uov.Refused) as e:
            self.table('iss-speedup:keygen/full@512')
        self.assertIn('no sw tier', str(e.exception))
        pub = uov.published(self.checkout)
        with mock.patch.dict(uov.gks.CAMPAIGN, {(128, 'verify', 'full'): (('Ip',), tuple(tiers)),
                                                (512, 'keygen', 'full'): (('Ip',), ('bngfaes',))}, clear=True):
            every = '| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |\n|---|---|---|---|---:|---:|---:|\n'
            for name in ('iss-speedup:all', 'iss-speedup:all@128'):                 # 512 KiB has no sw tier
                self.assertIn(every + '| 128 KiB | verify | full | Ip | 2x | - | 33.3x |\n\n', uov.table(name, pub, self.results))
            with self.assertRaises(uov.Refused) as e:
                uov.table('iss-speedup:all@512', pub, self.results)
            self.assertIn('no family with an sw tier', str(e.exception))
        self.assertEqual([uov.times(a, b) for a, b in ((601, 10), (332, 100), (15437, 100), (1, 1), (5, 4))],
                         ['60.1x', '3.32x', '154x', '1x', '1.25x'])

    def test_chip_speed_up_one_table_per_meter(self):
        run = 'rtl-32k-20261001T000000Z'
        os.makedirs(os.path.join(self.results, run))
        fields = uov.gcm.ONESHOT_FIELDS
        cells = {'bngfaes': (10, 20), 'bngfonly': (400, 410), 'bnaesonly': (250, 260), 'sw': (1000, 1010)}
        write_csv(os.path.join(self.results, run, 'results.csv'),
                  [dict(dict.fromkeys(fields, ''), op='sign', family='ldirect', param='ip', tier=t, run='accept',
                        exec_wait=str(e), op_total_v2=str(o)) for t, (e, o) in cells.items()])
        with open(os.path.join(self.results, run, 'manifest.json'), 'w') as fh:
            json.dump({'engine': 'rtl', 'run': run, 'source': {'commit': 'b' * 40}, 'archive': {'done': DONE.rstrip()}}, fh)
        pub = {'iss': {}, 'rtl': {uov.rtl_key(f'acc_uov_sign_ip_{t}_test', 32): ('r1', run) for t in cells}}
        head = '| DMEM | op | kernel | param | bngfonly | bnaesonly | bngfaes |\n|---|---|---|---|---:|---:|---:|\n'
        self.assertIn('Times faster than sw (sw cycles / tier cycles), chip, exec+wait\n\n' + head
                      + '| 32 KiB | sign | ldirect | Ip | 2.5x | 4x | 100x |\n\n', uov.table('rtl-speedup:sign/ldirect@32:Ip', pub, self.results))
        self.assertIn('Times faster than sw (sw cycles / tier cycles), chip, whole operation\n\n' + head
                      + '| 32 KiB | sign | ldirect | Ip | 2.46x | 3.88x | 50.5x |\n\n', uov.table('rtl-speedup-op:sign/ldirect@32:Ip', pub, self.results))
        del pub['rtl'][uov.rtl_key('acc_uov_sign_ip_sw_test', 32)]
        with self.assertRaises(uov.Refused):
            uov.table('rtl-speedup:sign/ldirect@32:Ip', pub, self.results)

    def test_chip_instruction_counts_are_set_against_the_iss_cases(self):
        tiers = ('bngfaes', 'bngfonly', 'bnaesonly', 'sw')
        cohorts = {t: cohort(variant='sp', tier=t, profile=128) for t in tiers}
        self.write_definition(list(cohorts.values()), name='k', created='2026-10-04T10:00:00+02:00', overlays={'128': {}})
        for n, t in enumerate(tiers, 1):                                            # 5 instructions in every case, 10n cycles
            uov.publish_record(self.record(RUN(n).replace('iss-512', 'iss-128'), cohorts[t], name='k', cycles=10 * n,
                                           completed='2026-10-04T12:00:00+02:00'), self.checkout)
        run = 'rtl-128k-20261001T000000Z'
        os.makedirs(os.path.join(self.results, run))
        write_csv(os.path.join(self.results, run, 'results.csv'),
                  [dict(dict.fromkeys(uov.gcm.ONESHOT_FIELDS, ''), op='keygen', family='sp', param='ip', tier=t, run='accept',
                        acc_insn='6' if t == 'sw' else '5', exec_wait=str(10 * n + 100 + n)) for n, t in enumerate(tiers, 1)])
        with open(os.path.join(self.results, run, 'manifest.json'), 'w') as fh:
            json.dump({'engine': 'rtl', 'run': run, 'source': {'commit': 'b' * 40}, 'archive': {'done': DONE.rstrip()}}, fh)
        pub = uov.published(self.checkout)
        pub['rtl'] = {uov.rtl_key(f'acc_uov_keygen_sp_ip_{t}_test', 128): ('r1', run) for t in tiers}
        t = uov.table('rtl-iss:keygen/sp@128:Ip', pub, self.results)
        self.assertIn('| DMEM | param | tier | ACC instructions | ISS cases with that count | exec+wait above the ISS cycles |\n'
                      '|---|---|---|---:|---|---:|\n| 128 KiB | Ip | bngfaes | 5 | 0-11 | 101 |\n| 128 KiB | Ip | bngfonly | 5 | 0-11 | 102 |\n'
                      '| 128 KiB | Ip | bnaesonly | 5 | 0-11 | 103 |\n| 128 KiB | Ip | sw | 6 | none | - |\n\n', t)
        self.assertIn('(k, r1)', t)
        self.assertEqual(uov.cases_text([0, 1, 2, 5]), '0-2,5')
        pub['rtl'] = {uov.rtl_key(f'acc_uov_sign_ip_{t}_test', 32): ('r1', run) for t in tiers}   # sign runs its own harness ELF
        with open(os.path.join(self.results, run, 'results.csv'), 'a') as fh:
            fh.write(''.join(f'sign,ldirect,ip,{t},,,accept,5,9,,,,,,\n' for t in tiers))
        with self.assertRaises(uov.Refused) as e:
            uov.table('rtl-iss:sign/ldirect@32:Ip', pub, self.results)
        self.assertIn('runs the ELF of an ISS run', str(e.exception))

    def test_memory_of_the_measured_elves(self):
        self.publish(1, facts={**self.FACTS, 'stack_reserved': 386080})
        self.publish(2, COHORT_IS)
        t = self.table('mem:keygen/full@512')
        self.assertIn('| DMEM | tier | Ip | Is |\n|---|---|---:|---:|\n| 512 KiB | bngfaes | 4,116 / 429,696 / 386,080 | 4,116 / 429,696 / - |\n\n', t)
        self.assertIn('not a measured peak', t)
        only = self.table('mem:keygen/full@512:Is')
        self.assertIn('| DMEM | tier | Is |\n|---|---|---:|\n| 512 KiB | bngfaes | 4,116 / 429,696 |\n\n', only)
        self.assertNotIn('stack', only)

    def test_a_case_with_a_retry_is_only_in_the_retry_table(self):
        ldirect = {t: cohort(op='sign', variant='ldirect', tier=t, param='Is', profile=32) for t in ('bngfaes', 'sw')}
        sprec = cohort(op='sign', variant='sprec', param='Is')
        self.write_definition([*ldirect.values(), sprec], name='s', created='2026-10-04T10:00:00+02:00', overlays={'32': {}, '512': {}})
        for n, (c, cycles) in enumerate(((ldirect['bngfaes'], 2), (ldirect['sw'], 100), (sprec, 8)), 1):    # case 3: a retry
            run = RUN(n).replace('iss-512', 'iss-32') if c['profile'] == 32 else RUN(n)
            uov.publish_record(self.record(run, c, name='s', cycles=cycles, spread=100, retries={3: 2 if c is ldirect['sw'] else 1},
                                           completed='2026-10-04T12:00:00+02:00'), self.checkout)
        pub = uov.published(self.checkout)
        with mock.patch.dict(uov.gks.CAMPAIGN, {(32, 'sign', 'ldirect'): (('Is',), ('bngfaes', 'sw')),
                                                (512, 'sign', 'sprec'): (('Is',), ('bngfaes',))}, clear=True):
            t = lambda name: uov.table(name, pub, self.results)
            self.assertIn('| 32 KiB | bngfaes | 2 |\n| 32 KiB | sw | 100 |\n\nISS cycles of one signature (a single EXECUTE), 32 KiB DMEM profile; '
                          'the same in all 12 KAT cases (11 where a case in which signing needed a retry is left out;', t('iss:sign/ldirect@32'))
            self.assertIn('| 32 KiB | bngfaes | 50x |\n\nThe cycles of the KAT cases added up per row, sw divided by the tier; a case in which '
                          'signing needed a retry is left out;', t('iss-speedup:sign/ldirect@32'))      # 1,100 / 22, not 1,300 / 124
            self.assertIn('| DMEM | op | param | bngfaes |\n|---|---|---|---:|\n| sprec 512 KiB, ldirect 32 KiB | sign | Is | 4.00x |\n',
                          t('iss-ratio:sign/sprec@512/ldirect@32'))                                  # 88 / 22
            self.assertIn('| 32 KiB | sign | ldirect | Is | bngfaes | 3 | 1 | 102 | 1.96x |\n| 32 KiB | sign | ldirect | Is | sw | 3 | 2 | 200 | - |\n'
                          '| 512 KiB | sign | sprec | Is | bngfaes | 3 | 1 | 108 | - |\n\n', t('iss-retries:all'))
            ratios = t('iss-retries-speedup:all')                                    # no cycles; sprec has no sw run
            self.assertIn('| DMEM | op | kernel | param | KAT case | retries | bngfonly | bnaesonly | bngfaes |\n'
                          '|---|---|---|---|---:|---:|---:|---:|---:|\n| 32 KiB | sign | ldirect | Is | 3 | - | - | - | 1.96x |\n\n', ratios)
            self.assertNotIn('sprec', ratios.split('\n\n')[1])
            self.assertNotIn('200', ratios)
        for n, bad in enumerate(('[PASS]\n', '[PASS]\n  Counter (GPR x8): 0\n  Counter (GPR x8): 1\n', '[PASS]\n  Counter (GPR x8): -1\n',
                                 '[PASS]\n  Counter (GPR x8): \u00b2\n'), 4):
            with self.subTest(bad):                                                  # no counter, two, not a count, not ASCII
                self.write_definition([sprec], name=f'b{n}', created=f'2026-10-0{n + 1}T10:00:00+02:00')
                self.publish(n, sprec, name=f'b{n}', driver=bad)
                with self.assertRaises(uov.Refused) as e:
                    self.table('iss:sign/sprec@512:Is')
                self.assertIn('no single attempt counter', str(e.exception))

    def test_ratios_add_up_the_kept_cases_of_one_campaign(self):
        ldirect = {t: cohort(op='sign', variant='ldirect', tier=t, param='Is', profile=32) for t in ('bngfaes', 'sw')}
        sprec = cohort(op='sign', variant='sprec', param='Is')
        self.write_definition([*ldirect.values(), sprec], name='u', created='2026-10-04T10:00:00+02:00', overlays={'32': {}, '512': {}})
        for n, (c, cycles) in enumerate(((ldirect['bngfaes'], 2), (ldirect['sw'], 100), (sprec, 8)), 1):    # case 3 slower, case 5 retried
            run = RUN(n).replace('iss-512', 'iss-32') if c['profile'] == 32 else RUN(n)
            uov.publish_record(self.record(run, c, name='u', cycles=cycles, spread=100, retries={5: 1},
                                           completed='2026-10-04T12:00:00+02:00'), self.checkout)
        pub = uov.published(self.checkout)
        self.write_definition([ldirect['sw']], name='v', created='2026-10-05T10:00:00+02:00', overlays={'32': {}})
        uov.publish_record(self.record(RUN(4).replace('iss-512', 'iss-32'), ldirect['sw'], name='v', cycles=100, retries={5: 1},
                                       completed='2026-10-05T12:00:00+02:00'), self.checkout)
        mixed = uov.published(self.checkout)                                         # sw now from v, bngfaes still from u
        with mock.patch.dict(uov.gks.CAMPAIGN, {(32, 'sign', 'ldirect'): (('Is',), ('bngfaes', 'sw')),
                                                (512, 'sign', 'sprec'): (('Is',), ('bngfaes',))}, clear=True):
            self.assertIn('| 32 KiB | bngfaes | 9.84x |', uov.table('iss-speedup:sign/ldirect@32', pub, self.results))   # 1,200 / 122
            self.assertIn('| sign | Is | 1.54x |', uov.table('iss-ratio:sign/sprec@512/ldirect@32', pub, self.results))  # 188 / 122
            with self.assertRaises(uov.Refused) as e:
                uov.table('iss-speedup:sign/ldirect@32', mixed, self.results)
            self.assertIn('more than one campaign', str(e.exception))

    def test_the_shipping_kernel_shows_as_tuned(self):
        streamed = cohort(variant='stream', profile=32)
        self.write_definition([streamed], name='w', created='2026-10-04T10:00:00+02:00', overlays={'32': {}})
        uov.publish_record(self.record(RUN(1).replace('iss-512', 'iss-32'), streamed, name='w',
                                       completed='2026-10-04T12:00:00+02:00'), self.checkout)
        pub = uov.published(self.checkout)
        with mock.patch.dict(uov.gks.CAMPAIGN, {(32, 'keygen', 'stream'): (('Ip',), ('bngfaes',))}, clear=True):
            self.assertIn('| 32 KiB | bngfaes | 7 |', uov.table('iss:keygen/stream@32:Ip', pub, self.results))       # the record name
            self.assertIn('| 32 KiB | keygen | tuned | bngfaes | 7 |', uov.table('iss:all@32', pub, self.results))     # shown as tuned
            with self.assertRaises(uov.Refused):
                uov.table('iss:keygen/tuned@32:Ip', pub, self.results)                                             # the shown name is no key

    def test_a_retried_case_leaves_the_whole_group_of_one_campaign(self):
        def rec(name='c', vec='v', retried=()):
            return name, {'run': f'run-{name}-{vec}', 'source': {'vectors': {vec: 'e' * 64}}}, \
                [{'case': str(c), 'cycles': '1', 'retries': int(c in retried)} for c in range(4)]
        self.assertEqual(uov.kept_cases([rec(), rec(retried=(2,))]), {0, 1, 3})     # one record's retry drops the case for all
        for group, why in (([rec(), rec('d')], 'more than one campaign'), ([rec(), rec(vec='w')], 'same vectors'),
                           ([rec(retried=range(4))], 'every case needed a retry')):
            with self.subTest(why), self.assertRaises(uov.Refused) as e:
                uov.kept_cases(group, one_campaign=True)
            self.assertIn(why, str(e.exception))
        self.assertEqual(uov.kept_cases([rec(), rec('d')]), {0, 1, 2, 3})           # a cycle range may span campaigns
        self.assertEqual(uov.lead_cells(('op', 'family'), {'op': 'keygen', 'family': 'stream'}), ['keygen', 'tuned'])

    def test_a_table_needs_every_cell_and_a_known_name(self):
        self.publish(1)
        for name, why in ((self.NAME, 'nothing published for iss:keygen/full/bngfaes/Is@512'),
                          ('iss:keygen/nosuch@512', 'no ISS family'), (self.NAME + ':Ip3', 'no ISS family'),
                          ('iss:all@512', 'nothing published for'), ('mem:all@512', 'list a whole profile'),
                          ('iss:all@512:Ip', 'list a whole profile'), ('iss:all@64', 'no ISS family'),
                          ('iss:keygen@512', 'unknown table'), ('cycles', 'unknown table'), (self.NAME + 'x', 'unknown table'),
                          ('rtl:sign/ldirect@32', 'nothing published'), ('iss-ratio:keygen/full@512', 'names two families'),
                          ('iss:keygen/full@512/full@512', 'names two families'), ('iss-ratio:all@512/x@512', 'names two families'),
                          ('iss-retries:all@512', 'iss-retries:all'), ('iss:keygen/full', 'names no DMEM profile'),
                          ('rtl:all', 'names no DMEM profile'), ('iss-speedup:all@512', 'no family with an sw tier'),
                          ('iss:keygen/tuned@512', 'no ISS family'), ('iss-ratio:keygen/stream@32/full@512', 'protocols differ'),
                          ('iss-retries:all@0', 'iss-retries:all'), ('rtl-speedup:all@0', 'no chip test')):
            with self.subTest(name), self.assertRaises(uov.Refused) as e:
                self.table(name)
            self.assertIn(why, str(e.exception))
        self.assertIn('| bngfaes | 7 |', self.table(self.NAME + ':Ip'))             # the published half alone renders

    def test_the_campaign_defined_later_wins_cell_by_cell(self):
        self.publish(1)
        self.publish(2, COHORT_IS, cycles=9)
        for created, ip in (('2026-10-04T09:00:00+02:00', '5'), ('2026-10-02T09:00:00+02:00', '7')):
            with self.subTest(created):
                self.write_definition([COHORT], name='c2', created=created)
                if not os.path.exists(os.path.join(self.results, RUN(3))):
                    self.publish(3, name='c2', cycles=5)
                    c2 = os.path.join(self.results, RUN(3))
                else:                                                               # the same record under the redated definition
                    _, dsha = uov.load_definition(self.checkout, 'c2')
                    m = json.loads(uov.read(os.path.join(c2, 'manifest.json')))
                    m['definition'] = dsha
                    with open(os.path.join(c2, 'manifest.json'), 'w') as fh:
                        json.dump(m, fh)
                    _, done = uov.campaign_files(self.checkout, 'c2')
                    with open(done, 'w') as fh:
                        json.dump({'campaign': 'c2', 'definition': dsha, 'cohorts': {
                            uov.cohort_key(COHORT): {'run': RUN(3), 'manifest': uov.sha256(os.path.join(c2, 'manifest.json'))}}}, fh)
                t = self.table()
                self.assertIn(f'| bngfaes | {ip} | 9 |', t)
                self.assertIn('(c1, c2)' if ip == '5' else '(c1)', t)

    def test_a_definition_without_a_date_or_a_changed_record_stops(self):
        self.publish(1)
        self.publish(2, COHORT_IS)
        csvp = os.path.join(self.results, RUN(1), 'results.csv')
        good = uov.read(csvp)
        with open(csvp, 'w') as fh:
            fh.write(good.replace(',7\n', ',6\n', 1))
        with self.assertRaises(uov.Stop):
            uov.published(self.checkout)
        with open(csvp, 'w') as fh:
            fh.write(good)
        self.assertEqual(len(uov.published(self.checkout)['iss']), 2)
        self.write_definition([COHORT], name='c0')                                  # created: 'now'
        self.publish(3, name='c0')
        with self.assertRaises(uov.Stop) as e:
            uov.published(self.checkout)
        self.assertIn('created is not a date', str(e.exception))

    def test_only_marked_lines_are_rewritten(self):
        text = ('intro `<!-- table:x -->` in a sentence\n<!-- table:a -->\nold\nlines\n<!-- /table:a -->\nbetween\n'
                '<!-- table:b -->\n<!-- /table:b -->\nend\n')
        out, left = uov.render(text, lambda name: f'[{name}]\n')
        self.assertEqual((out, left), ('intro `<!-- table:x -->` in a sentence\n<!-- table:a -->\n[a]\n<!-- /table:a -->\nbetween\n'
                                       '<!-- table:b -->\n[b]\n<!-- /table:b -->\nend\n', []))
        self.assertEqual(uov.render(out, lambda name: f'[{name}]\n'), (out, []))
        self.assertEqual(uov.render('no tables\n', None), ('no tables\n', []))

        def only_b(name):
            if name == 'a':
                raise uov.Refused('no data')
            return 'new\n'
        self.assertEqual(uov.render(out, only_b), (out.replace('[b]', 'new'), [('a', 'no data')]))    # a keeps its text
        for bad in ('<!-- table:a -->\nx\n', '<!-- /table:a -->\n<!-- table:a -->\n', '<!-- table:a -->\n<!-- /table:b -->\n',
                    '<!-- table:a -->\n<!-- table:b -->\n<!-- /table:a -->\n<!-- /table:b -->\n', '<!-- table:a -->\n<!-- /table:a -->'):
            with self.subTest(bad), self.assertRaises(ValueError):
                uov.render(bad, lambda name: '')

    def test_tables_rewrites_what_the_records_fill_and_reports_the_rest(self):
        p = mock.patch.object(uov, 'REPO', self.checkout)                           # the tree whose READMEs and records are read
        p.start()
        self.addCleanup(p.stop)
        self.publish(1)
        self.publish(2, COHORT_IS)
        marked = f'# x\n<!-- table:{self.NAME} -->\nstale\n<!-- /table:{self.NAME} -->\n'
        for rel in ('a/README.md', 'b/NOTES.md'):
            os.makedirs(os.path.join(self.checkout, os.path.dirname(rel)))
            with open(os.path.join(self.checkout, rel), 'w') as fh:
                fh.write(marked)
        with open(os.path.join(self.checkout, 'plain.md'), 'w') as fh:
            fh.write('no marked table here, only `<!-- table:x -->` in a sentence\n')
        commit_all(self.checkout)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(uov.run_tables(SimpleNamespace(check=True)), 1)
            self.assertEqual(uov.read(os.path.join(self.checkout, 'a/README.md')), marked)
            self.assertEqual(uov.run_tables(SimpleNamespace(check=False)), 0)
            new = uov.read(os.path.join(self.checkout, 'a/README.md'))
            self.assertIn('| bngfaes | 7 | 7 |', new)
            self.assertEqual(uov.read(os.path.join(self.checkout, 'b/NOTES.md')), new)
            self.assertEqual(uov.run_tables(SimpleNamespace(check=True)), 0)
            self.assertEqual(out.getvalue(), (
                'would rewrite a/README.md\nwould rewrite b/NOTES.md\n2 files with tables, 0 up to date, 0 tables left as they are\n'
                'rewrote a/README.md\nrewrote b/NOTES.md\n2 files with tables, 0 up to date, 0 tables left as they are\n'
                '2 files with tables, 2 up to date, 0 tables left as they are\n'))
            with open(os.path.join(self.checkout, 'a/README.md'), 'w') as fh:
                fh.write(marked)                                                    # stale again, and b asks for an unpublished table too
            unpublished = '<!-- table:iss:sign/sprec@512 -->\nkept\n<!-- /table:iss:sign/sprec@512 -->\n'
            with open(os.path.join(self.checkout, 'b/NOTES.md'), 'w') as fh:
                fh.write(unpublished + marked)
            self.assertEqual(uov.run_tables(SimpleNamespace(check=True)), 2)
            self.assertEqual(uov.read(os.path.join(self.checkout, 'a/README.md')), marked)
            self.assertEqual(uov.run_tables(SimpleNamespace(check=False)), 2)      # what can be filled is filled
            self.assertEqual(uov.read(os.path.join(self.checkout, 'a/README.md')), new)
            self.assertEqual(uov.read(os.path.join(self.checkout, 'b/NOTES.md')), unpublished + new)
            self.assertIn('left as it is: b/NOTES.md: iss:sign/sprec@512: nothing published for iss:sign/sprec/bngfaes/Ip@512\n'
                          '2 files with tables, 0 up to date, 1 tables left as they are\n', out.getvalue())
            with open(os.path.join(self.checkout, 'b/NOTES.md'), 'w') as fh:
                fh.write('<!-- table:iss:keygen/full@512 -->\n')              # a marker without its pair: nothing is written
            with open(os.path.join(self.checkout, 'a/README.md'), 'w') as fh:
                fh.write(marked)
            with self.assertRaises(SystemExit) as e:
                uov.run_tables(SimpleNamespace(check=False))
            self.assertEqual(e.exception.code, 2)
            self.assertIn('READMEs unchanged: b/NOTES.md: a table marker without its pair', err.getvalue())
            self.assertEqual(uov.read(os.path.join(self.checkout, 'a/README.md')), marked)


RTL32 = [('sign', '', 'ip', 'bngfaes'), ('sign', '', 'is', 'bngfaes')]
RTL128 = [('keygen', 'sp', 'ip', 'bngfaes'), ('verify', 'full', 'ip3', 'bngfaes')]
LEDGER = 'cell,acc_insn,accept,reject,status\nsign_ip_bngfaes,13,phase SIGN=13,,OK\nsign_is_bngfaes,13,phase SIGN=13,,OK\n'
XML = '<testsuites><testsuite failures="{}" errors="0"/></testsuites>'
DONE = 'collector_exit=0 postcheck_exit=0 archive_exit=0 finished=20261004T080914Z\n'


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def cell_name(c):
    return uov.gcm.target(*c)[:-len('_sim_verilator')]


def console(c):
    protocol = uov.gcm.expected_protocol(c[0], c[1], c[3])
    return ''.join(f'I0 x] meters v2 protocol={protocol} op={c[0]} param={c[2]} family={c[1] or "ldirect"} '
                   f'tier={c[3]} run={role} acc_insn=13 exec_wait=2 host_io_fold=3 op_total_v2=6 app_load=5\r\n'
                   for role in uov.gcm.PROTOCOL_RUNS[protocol]) + 'PASS!\n'


class RtlCatalog(unittest.TestCase):
    def test_every_cell_once_with_its_protocol(self):
        cells = uov.rtl_cells()
        self.assertEqual((len(cells), sum(p == 32 for p, _, _ in cells.values())), (96, 60))
        self.assertTrue(all(proto in uov.gcm.PROTOCOL_RUNS for _, proto, _ in cells.values()))
        sign = 'acc_uov_sign_ip_bngfaes_test'
        good = dict(dict.fromkeys(uov.gcm.ONESHOT_FIELDS, ''), op='sign', family='ldirect', param='ip', tier='bngfaes',
                    contract='2', protocol='accept_negative', run='accept', verdict='PASS', acc_insn='13', exec_wait='2',
                    host_io_fold='3', op_total_v2='6', app_load='5')
        self.assertEqual(uov.rtl_row_problems([sign], [good]), [])
        for what, change in (('another contract', dict(contract='1')), ('no counter', dict(acc_insn='')),
                             ('a counter that is no number', dict(app_load='5.0')),
                             ('a digit that is not 0-9 in a counter outside the brackets', dict(acc_insn='\u00b2')),
                             ('the same in app_load', dict(app_load='1\u0663')),
                             ('brackets larger than the total', dict(exec_wait='4'))):
            with self.subTest(what):
                self.assertIn('not a meters v2 row with its counters', uov.rtl_row_problems([sign], [dict(good, **change)])[0])

    def test_the_runner_source_lists_the_import_tools(self):
        text = uov.read(os.path.join(uov.REPO, 'tools/rtl_campaign.sh'))
        self.assertIn(f'echo "generation {uov.RTL_GENERATION}"', text)
        hashed = re.search(r'\n    for f in (\.bazelrc [^\n]*); do\n      \[ -f "\$f" \] && echo "source', text).group(1).split()
        self.assertEqual({f for f in hashed if f.startswith('tools/')}, set(uov.RTL_TOOLS))

    def test_published_names_are_not_gitignored(self):
        paths = [f'{uov.RESULTS}/rtl-32k-20261004T080914Z/{n}' for n in ('manifest.json', 'results.csv')]
        r = subprocess.run(['git', 'check-ignore', '--no-index', *paths], cwd=uov.REPO, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (1, ''), f'published files the repo would ignore: {r.stderr}')


class RtlImport(unittest.TestCase):
    """rtl-init and rtl-import on a scratch stand-in for this repository, run directories built the way
    rtl_campaign.sh archives them, and a scratch publication checkout. The catalog is cut to four cells;
    the 89-cell profiles are covered by importing the real run directories."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        real, self.tool = uov.REPO, os.path.join(self.tmp.name, 'tool')
        for d in ('tools', 'hw', uov.RTL_TESTS):
            os.makedirs(os.path.join(self.tool, d))
        for f in ('rtl_campaign.sh', 'gather_chip_matrix.py'):
            shutil.copy(os.path.join(real, 'tools', f), os.path.join(self.tool, 'tools', f))
        self.write(self.tool, {'.bazelrc': 'rc\n', '.bazelversion': '8.0.1\n',
                               'MODULE.bazel.lock': '{}\n', 'hw/profile.txt': '32\n', uov.RTL_BASELINE: LEDGER,
                               **{f'{uov.RTL_TESTS}/{f}': f for f in ('sign_test.c', 'gen_sign_chip_testvec.py', 'BUILD',
                                                                      'uov_test.bzl', 'README.md')}})
        git_init(self.tool)
        self.rev = commit_all(self.tool, 'measured')
        self.write(self.tool, {'hw/profile.txt': '128\n'})
        self.patch128 = git(self.tool, 'diff', 'HEAD')
        git(self.tool, 'checkout', '--', 'hw/profile.txt')
        self.write(self.tool, {'tools/later.txt': 'tooling\n'})
        self.head = commit_all(self.tool, 'tooling')
        self.write(self.tmp.name, {'bazelrc-site': 'common --x\n', 'other-rc': 'common --y\n'})
        self.rc = os.path.join(self.tmp.name, 'bazelrc-site')
        self.checkout = os.path.join(self.tmp.name, 'pub')
        git_init(self.checkout)
        os.makedirs(os.path.join(self.checkout, uov.CAMPAIGNS))
        self.committed = {}
        for p in (mock.patch.object(uov, 'REPO', self.tool),
                  mock.patch.object(uov, 'head_blob', lambda checkout, rel: self.committed.get(rel)),
                  mock.patch.object(uov.gcm, 'CELLS', RTL32), mock.patch.object(uov.gcm, 'ONESHOT_CELLS', RTL128)):
            p.start()
            self.addCleanup(p.stop)
        self.defn, self.dsha = self.define()

    @staticmethod
    def write(root, files):
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), 'w', newline='') as fh:
                fh.write(text)

    def define(self, name='r1', commit=True, **kw):
        d = {'schema': 1, 'engine': 'rtl', 'name': name, 'created': 'now', 'note': uov.RTL_NOTE,
             'tooling_commit': self.head, 'measuring_commit': self.rev, 'generation': uov.RTL_GENERATION,
             'config': {'.bazelrc-site': uov.sha256(self.rc)},
             'overlays': {'32': {}, '128': {'hw/profile.txt': [sha('128\n'), '100644']}}, 'baseline': sha(LEDGER),
             'cells': [{'profile': p, 'cell': n, 'protocol': proto} for n, (p, proto, _) in uov.rtl_cells().items()]}
        d.update(kw)
        path, _ = uov.campaign_files(self.checkout, name)
        with open(path, 'w') as fh:
            json.dump(d, fh)
        if commit:
            with open(path, 'rb') as fh:
                self.committed[os.path.relpath(path, self.checkout)] = fh.read()
        return uov.load_rtl_definition(self.checkout, name)

    def archive(self, profile, cells, stamp='20261004T080914Z', head=None, patch=None, untracked='', sources=None,
                rc=None, edit=None, ledger=LEDGER, manifest=()):
        """A run directory as rtl_campaign.sh leaves it; edit(run) changes it before the inventory is taken;
        manifest overrides single lines of manifest.txt (None drops one)."""
        run = os.path.join(self.tmp.name, 'runs', f'rtl-{profile}k-{stamp}')
        res, mode, names = os.path.join(run, 'results'), uov.RTL_MODE[profile], [cell_name(c) for c in cells]
        files = {'tracked-changes.patch': (self.patch128 if profile == 128 else '') if patch is None else patch,
                 'untracked-files.txt': untracked, 'bin/abc': 'binary', 'campaign.log': 'log\n', 'DONE': DONE,
                 'results/run.json': json.dumps({'mode': mode, 'cells': names, 'bazel_exit': 0,
                                                 'baseline': sha(ledger) if profile == 32 else None})}
        if profile == 32:
            files['results/expected_insn_counts_32k.csv'] = ledger
        bep = []
        for c, n in zip(cells, names):
            d = f'results/logs/{n}_sim_verilator'
            files.update({f'{d}/test.log': console(c), f'{d}/test.xml': XML.format(0)})
            bep.append({'id': {'testResult': {'label': f'{uov.gcm.PKG}:{n}_sim_verilator', 'run': 1, 'shard': 1, 'attempt': 1}},
                        'testResult': {'status': 'PASSED',
                                       'testActionOutput': [{'name': 'test.log', 'uri': f'file://{run}/{d}/test.log'}]}})
        files['results/bep.json'] = ''.join(json.dumps(e) + '\n' for e in bep)
        src = {p: uov.blob_sha256(self.rev, p)
               for p in ('.bazelrc', '.bazelversion', 'MODULE.bazel.lock', *uov.RTL_TOOLS,
                         *(f'{uov.RTL_TESTS}/{f}' for f in ('sign_test.c', 'gen_sign_chip_testvec.py', 'BUILD', 'uov_test.bzl')),
                         *([uov.RTL_BASELINE] if profile == 32 else []))}
        src['.bazelrc-site'] = uov.sha256(rc or self.rc)
        src.update(sources or {})
        fields = dict((('stamp', stamp), ('generation', uov.RTL_GENERATION), ('profile', profile), ('head', head or self.rev),
                       ('branch', 'b'), ('snapshot', 'a' * 64), ('dirty_tracked', '0 untracked 0'), ('bazel', 'bazel 8.0.1'),
                       ('output_base', 'default'), ('flags', '--cache_test_results=no'), ('collector', 'python3 x'),
                       ('cells', ' '.join(names))), **dict(manifest))
        files['manifest.txt'] = (''.join(f'{k} {v}\n' for k, v in fields.items() if v is not None)
                                 + ''.join(f'source {p} sha256 {h}\n' for p, h in src.items() if h)
                                 + f'firmware /x/fw.elf sha256 {"b" * 64} cell c\n')
        self.write(run, files)
        shutil.copy(os.path.join(self.tool, 'tools/rtl_campaign.sh'), os.path.join(run, 'rtl_campaign.sh'))
        with open(os.path.join(res, f'results_{profile}k.csv'), 'wb') as fh:
            fh.write(uov.rtl_csv(uov.gcm.replay(res, mode)[2]))
        if edit:
            edit(run)
        subprocess.run(['bash', os.path.join(self.tool, 'tools/rtl_campaign.sh'), '--archive', run], check=True,
                       capture_output=True)
        return run

    def log(self, run, cell=RTL32[0], name='test.log'):
        return os.path.join(run, 'results/logs', cell_name(cell) + '_sim_verilator', name)

    def imp(self, *runs):
        return uov.rtl_publish(self.checkout, 'r1', self.dsha, [uov.rtl_record(r, self.defn, self.dsha) for r in runs])

    def refused(self, why, *runs):
        with self.assertRaises(uov.Stop) as e:
            self.imp(*runs)
        self.assertIn(why, str(e.exception))

    def published(self):
        """(record directories, listed cell keys) of the scratch checkout, read from disk."""
        results = os.path.join(self.checkout, uov.RESULTS)
        _, path = uov.campaign_files(self.checkout, 'r1')
        listed = json.loads(uov.read(path))['cells'] if os.path.exists(path) else {}
        return sorted(d for d in os.listdir(results) if d != 'campaigns'), sorted(listed)

    def test_a_whole_profile_is_published_from_its_runs_in_one_step(self):
        a = self.archive(32, RTL32[:1], stamp='20261001T000000Z')
        b = self.archive(32, RTL32[1:], stamp='20261002T000000Z')
        keys = sorted(uov.rtl_key(cell_name(c), 32) for c in RTL32)
        done = self.imp(a, b)
        self.assertEqual(self.published(), (['rtl-32k-20261001T000000Z', 'rtl-32k-20261002T000000Z'], keys))
        final = os.path.join(self.checkout, uov.RESULTS, 'rtl-32k-20261001T000000Z')
        self.assertEqual(sorted(os.listdir(final)), ['manifest.json', 'results.csv'])
        m = uov.validate_rtl_bundle(final, self.defn, self.dsha)
        self.assertEqual((m['source']['commit'], m['tools']['publishing'], m['completion']),
                         (self.rev, self.head, {'accepted': True, 'cells': 1, 'rows': 1, 'baseline': 'identical'}))
        with open(os.path.join(a, 'results/results_32k.csv'), 'rb') as own, open(os.path.join(final, 'results.csv'), 'rb') as out:
            self.assertEqual(out.read(), own.read())
        self.assertNotIn(self.tmp.name, uov.read(os.path.join(final, 'manifest.json')))      # no path of this machine
        self.assertEqual(done[keys[0]], {'run': 'rtl-32k-20261001T000000Z', 'manifest': uov.sha256(os.path.join(final, 'manifest.json'))})
        before = {f: uov.sha256(os.path.join(r, f)) for r, _, fs in os.walk(self.checkout) for f in fs if '.git' not in r}
        self.assertEqual(self.imp(a, b), done)                                               # a retry changes nothing
        self.assertEqual({f: uov.sha256(os.path.join(r, f)) for r, _, fs in os.walk(self.checkout) for f in fs if '.git' not in r},
                         before)
        self.assertEqual(uov.rtl_completed(self.checkout, 'r1', self.defn, self.dsha), done)
        _, path = uov.campaign_files(self.checkout, 'r1')                                    # a list cut to one of the runs
        self.write(self.checkout, {path: json.dumps({'campaign': 'r1', 'definition': self.dsha, 'cells': {keys[0]: done[keys[0]]}})})
        with self.assertRaises(uov.Stop) as e:
            uov.rtl_completed(self.checkout, 'r1', self.defn, self.dsha)
        self.assertIn('32 KiB has 1 of 2 cells', str(e.exception))

    def test_a_run_without_a_bazel_version_takes_it_from_its_event_log(self):
        started = lambda v: lambda run: self.write(run, {'results/bep.json': uov.read(os.path.join(run, 'results/bep.json'))
                                                         + ''.join(json.dumps({'id': {'started': {}}, 'started': {'buildToolVersion': x}}) + '\n' for x in v)})
        for what, versions in (('no version anywhere', []), ('two versions', ['8.0.1', '7.4.0'])):
            with self.subTest(what):
                run = self.archive(32, RTL32, manifest={'bazel': ''}, edit=started(versions))   # what the runner wrote before its fix
                self.refused('manifest.txt records no Bazel version and the build event log names', run)
                shutil.rmtree(run)
        run = self.archive(32, RTL32, manifest={'bazel': ''}, edit=started(['8.0.1']))
        self.imp(run)
        m = uov.validate_rtl_bundle(os.path.join(self.checkout, uov.RESULTS, os.path.basename(run)), self.defn, self.dsha)
        self.assertEqual(m['execution']['bazel'], "bazel 8.0.1 (from the run's build event log; its manifest recorded no version)")

    def test_tables_show_the_accepting_run_of_each_test(self):
        self.defn, self.dsha = self.define(created='2026-10-04T10:00:00+02:00')
        self.imp(self.archive(32, RTL32, stamp='20261001T000000Z'), self.archive(128, RTL128, stamp='20261005T000000Z'))
        pub, results = uov.published(self.checkout), os.path.join(self.checkout, uov.RESULTS)
        self.assertEqual(uov.table('rtl:sign/ldirect@32', pub, results), (
            '| DMEM | param | tier | ACC instructions | exec+wait | host I/O + fold | whole operation | app load |\n'
            '|---|---|---|---:|---:|---:|---:|---:|\n| 32 KiB | Ip | bngfaes | 13 | 2 | 3 | 6 | 5 |\n| 32 KiB | Is | bngfaes | 13 | 2 | 3 | 6 | 5 |\n\n'
            'Instructions the ACC retired, then Ibex cycles.\n'
            f'Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-10-01 to 2026-10-04 at `{self.rev[:10]}` (r1).\n'))
        only = uov.table('rtl:sign/ldirect@32:Is', pub, results)
        self.assertIn('| Is | bngfaes | 13 |', only)
        self.assertNotIn('| Ip |', only)
        self.assertEqual(uov.table('rtl:keygen/sp@128', pub, results).count('| Ip | bngfaes | 13 | 2 | 3 | 6 | 5 |\n'), 1)
        self.assertIn('| DMEM | op | kernel | param | tier | ACC instructions | exec+wait | host I/O + fold | whole operation | app load | whole test |\n'
                      '|---|---|---|---|---|---:|---:|---:|---:|---:|---:|\n'
                      '| 128 KiB | keygen | sp | Ip | bngfaes | 13 | 2 | 3 | 6 | 5 | - |\n'      # three run roles each, one row each
                      '| 128 KiB | verify | full | Ip3 | bngfaes | 13 | 2 | 3 | 6 | 5 | - |\n\n', uov.table('rtl:all@128', pub, results))
        self.assertIn('| DMEM | tier | Ip | Is |\n|---|---|---:|---:|\n| 32 KiB | bngfaes | 2 | 2 |\n\nexec+wait in Ibex cycles. Chip RTL under Verilator,',
                      uov.table('rtl-cycles:sign/ldirect@32', pub, results))
        self.assertIn('| DMEM | param | tier | accept | restart_b | restart_a2 |\n|---|---|---|---:|---:|---:|\n| 128 KiB | Ip | bngfaes | 2 | 2 | 2 |\n\n',
                      uov.table('rtl-runs:keygen/sp@128', pub, results))
        self.assertIn('| DMEM | param | tier | accept | reject_resident | accept_resident |\n', uov.table('rtl-runs:verify/full@128', pub, results))
        for name in ('rtl:sign/ldirect@32:Ip3', 'rtl:verify/stream@32', 'rtl:all@512', 'rtl-runs:all@128', 'rtl-cycles:all@32',
                     'rtl-speedup:sign/ldirect@32'):                                # the last: no sw test
            with self.subTest(name), self.assertRaises(uov.Refused):
                uov.table(name, pub, results)

    def test_a_partial_profile_publishes_nothing(self):
        one = self.archive(32, RTL32[:1])
        self.refused('32 KiB has 1 of 2 cells', one)
        self.refused('a run directory is given twice', one, one)
        self.assertEqual(self.published(), ([], []))
        both = self.archive(128, RTL128, stamp='20261005T000000Z')                           # the other profile, whole
        self.refused('32 KiB has 1 of 2 cells', both, os.path.join(self.tmp.name, 'runs', 'rtl-32k-20261004T080914Z'))
        self.assertEqual(self.published(), ([], []))
        self.assertEqual(len(self.imp(both)), 2)

    def test_the_128k_tree_must_be_exactly_the_overlay(self):
        added = self.patch128 + 'diff --git a/hw/new.txt b/hw/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/hw/new.txt\n@@ -0,0 +1 @@\n+x\n'
        for what, patch in (('no change', ''), ('one more file', added), ('another value', self.patch128.replace('+128', '+512'))):
            with self.subTest(what):
                run = self.archive(128, RTL128, patch=patch)
                self.refused('not exactly the 128 KiB overlay', run)
                shutil.rmtree(run)
        self.assertEqual(len(self.imp(self.archive(128, RTL128))), 2)

    def test_the_measuring_tree_must_be_the_definitions(self):
        for what, kw, why in (
                ('another commit', dict(head=self.head), f'measured at {self.head[:10]}'),
                ('an untracked file', dict(untracked='x.txt\n'), 'untracked files'),
                ('a changed tool', dict(sources={'tools/gather_chip_matrix.py': 'e' * 64}), "differ from"),
                ('a source line dropped', dict(sources={'tools/gather_chip_matrix.py': None}), "recorded sources: missing ['tools/gather_chip_matrix.py']"),
                ('a source the runner does not record', dict(sources={'tools/later.txt': 'e' * 64}), "unexpected ['tools/later.txt']"),
                ('another local configuration', dict(rc=os.path.join(self.tmp.name, 'other-rc')), "differ from"),
                ('tracked changes at 32 KiB', dict(patch=self.patch128), 'not exactly the 32 KiB overlay'),
                ('no snapshot line', dict(manifest={'snapshot': None}), "manifest.txt lacks ['snapshot']"),
                ('another generation', dict(manifest={'generation': 'chip-meters-g1'}), 'stamp, profile or generation is not this run'),
                ('other cells than run.json', dict(manifest={'cells': cell_name(RTL32[0])}), 'do not name the same 32 KiB cells'),
                ('a local path in the flags', dict(manifest={'flags': '--cache_test_results=no --output_base=/scratch/ob'}),
                 'name a path of the measuring machine'),
                ('another frozen runner', dict(edit=lambda run: self.write(run, {'rtl_campaign.sh': 'echo\n'})), 'the frozen runner is not the recorded one'),
                ('another ledger', dict(ledger=LEDGER + 'sign_ip3_bngfaes,13,phase SIGN=13,,OK\n'), "the baseline gate is not the definition's ledger"),
                ('a count off the ledger', dict(ledger=LEDGER.replace('sign_ip_bngfaes,13,phase SIGN=13', 'sign_ip_bngfaes,14,phase SIGN=14')),
                 "the baseline gate is not the definition's ledger")):
            with self.subTest(what):
                run = self.archive(32, RTL32, **kw)
                self.refused(why, run)
                shutil.rmtree(run)
        run = self.archive(32, RTL32)
        moved = run.replace('20261004T080914Z', '20261005T000000Z')
        os.rename(run, moved)                                                               # its inventory still verifies
        self.refused('stamp, profile or generation is not this run', moved)
        self.assertEqual(self.published(), ([], []))

    def test_only_an_intact_finished_run_is_read(self):
        run = self.archive(32, RTL32)
        for what, text, why in (('no archive exit', DONE.replace(' archive_exit=0', ''), 'DONE is not the one line'),
                                ('a second line', DONE + DONE.replace('collector_exit=0', 'collector_exit=1'), 'DONE is not the one line')):
            with self.subTest(what):
                self.write(run, {'DONE': text})
                self.refused(why, run)
        self.write(run, {'DONE': DONE})
        real = subprocess.run

        def swapped(change):
            def run_then_change(cmd, *a, **k):
                r = real(cmd, *a, **k)
                if '--verify-only' in cmd:
                    change()
                return r
            return mock.patch.object(subprocess, 'run', run_then_change)

        def relink():
            shutil.copy(self.log(run), self.log(run) + '.real')
            os.remove(self.log(run))
            os.symlink(self.log(run) + '.real', self.log(run))
        with self.subTest('a file replaced by a link after the check'), swapped(relink):
            self.refused('test.log is not a regular file of the inventory', run)
        os.remove(self.log(run))
        os.rename(self.log(run) + '.real', self.log(run))
        with self.subTest('bytes changed after the check'), swapped(lambda: self.write(run, {self.log(run): console(RTL32[0]) + 'late\n'})):
            self.refused('test.log differs from the inventory', run)
        self.refused('archived evidence differs from evidence.sha256', run)                # and it stays refused
        run = self.archive(32, RTL32, stamp='20261006T000000Z')
        inv = uov.read(os.path.join(run, 'evidence.sha256'))
        unused = ''.join(line + '\n' for line in inv.splitlines() if not line.endswith('./bin/abc'))
        self.assertNotEqual(unused, inv)
        cut = DONE + DONE.replace('collector_exit=0', 'collector_exit=1').rstrip('\n')    # a second record, unterminated
        for what, files in (('DONE rewritten after the check', {'DONE': DONE + DONE}),
                            ('an inventory line repeated after the check', {'evidence.sha256': inv + inv.splitlines()[0] + '\n'}),
                            ('a well-formed inventory without an unused file, after the check', {'evidence.sha256': unused})):
            with self.subTest(what), swapped(lambda: self.write(run, files)):
                self.refused('evidence.sha256 or DONE changed while the run directory was verified', run)
            self.write(run, {'DONE': DONE, 'evidence.sha256': inv})

        def trusting(cmd, *a, **k):                                                          # a verifier that accepts everything
            return subprocess.CompletedProcess(cmd, 0, '', '') if '--verify-only' in cmd else real(cmd, *a, **k)
        for what, files, why in (('two DONE records', {'DONE': DONE + DONE}, 'DONE is not one clean line'),
                                 ('a second, unterminated DONE record', {'DONE': cut}, 'DONE is not one clean line'),
                                 ('a repeated inventory line', {'evidence.sha256': inv + inv.splitlines()[0] + '\n'},
                                  'bad or repeated inventory line')):
            self.write(run, files)
            with self.subTest(what), mock.patch.object(subprocess, 'run', trusting):
                self.refused(why, run)
            self.write(run, {'DONE': DONE, 'evidence.sha256': inv})
        self.write(run, {'DONE': cut})
        self.refused('DONE is not the one line', run)                                       # and the real verifier refuses it too
        self.write(run, {'DONE': DONE})
        self.assertEqual(len(self.imp(run)), 2)                                             # positive control

    def test_a_failed_cached_or_drifted_run_is_not_imported(self):
        def fail_xml(run):
            self.write(run, {self.log(run, name='test.xml'): XML.format(1)})

        def cached(run):
            bep = uov.read(os.path.join(run, 'results/bep.json')).replace('"status"', '"cachedLocally": true, "status"', 1)
            self.write(run, {'results/bep.json': bep})

        def exit3(run):
            self.write(run, {'results/run.json': uov.read(os.path.join(run, 'results/run.json')).replace('"bazel_exit": 0', '"bazel_exit": 3')})
        for what, edit, why in (('a failing test with its meters intact', fail_xml, 'rows are not the run roles'),
                                ('a result from the cache', cached, 'rows are not the run roles'),
                                ('a failed invocation', exit3, 'bazel exit 3')):
            with self.subTest(what):
                run = self.archive(32, RTL32, edit=edit)
                self.refused(why, run)
                shutil.rmtree(run)
        run = self.archive(32, RTL32)
        own = os.path.join(run, 'results/results_32k.csv')                                    # outside the inventory
        self.write(run, {own: uov.read(own).replace(',13,', ',14,', 1)})
        self.refused("the run's own csv is not what its logs re-read to", run)
        self.assertEqual(self.published(), ([], []))

    def test_a_cell_is_published_from_one_run_only(self):
        first = self.archive(32, RTL32, stamp='20261001T000000Z')
        done = self.imp(first)
        self.refused('already published from another record', self.archive(32, RTL32[:1], stamp='20261002T000000Z'))
        self.assertEqual(self.published(), (['rtl-32k-20261001T000000Z'], sorted(done)))
        shutil.rmtree(first)
        self.refused('rtl-32k-20261001T000000Z is already listed as another record',
                     self.archive(32, RTL32[:1], stamp='20261001T000000Z'))                  # the same name, other content
        first = self.archive(32, RTL32, stamp='20261001T000000Z')
        self.assertEqual(self.imp(first, self.archive(128, RTL128)).keys() - done.keys(),
                         {uov.rtl_key(cell_name(c), 128) for c in RTL128})                   # the list grows, nothing is replaced

    def test_a_retry_finishes_an_interrupted_import(self):
        a = self.archive(32, RTL32[:1], stamp='20261001T000000Z')
        b = self.archive(32, RTL32[1:], stamp='20261002T000000Z')
        rename, calls = os.rename, []

        def second_rename_fails(src, dst):
            calls.append(dst)
            if len(calls) == 2:
                raise OSError('disk full')
            return rename(src, dst)
        with mock.patch.object(os, 'rename', second_rename_fails), self.assertRaises(OSError):
            self.imp(a, b)
        self.assertEqual(self.published(), (['rtl-32k-20261001T000000Z'], []))             # installed, not listed: not published
        self.assertEqual(uov.rtl_completed(self.checkout, 'r1', self.defn, self.dsha), {})
        with mock.patch.object(uov, 'write_atomic', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.imp(a, b)
        self.assertEqual(self.published(), (['rtl-32k-20261001T000000Z', 'rtl-32k-20261002T000000Z'], []))
        shutil.rmtree(os.path.join(self.checkout, uov.RESULTS, 'rtl-32k-20261002T000000Z'))
        opened = open

        def full_disk(path, *args, **kw):                                                   # the second staged record cannot be written
            if '.staging-rtl-32k-20261002T000000Z' in str(path) and 'w' in ''.join(args[:1]):
                raise OSError('disk full')
            return opened(path, *args, **kw)
        with mock.patch('builtins.open', full_disk), self.assertRaises(OSError):
            self.imp(a, b)
        self.assertEqual(self.published(), (['rtl-32k-20261001T000000Z'], []))             # no staging directory left behind
        with mock.patch.object(uov, 'write_atomic', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.imp(a, b)
        left = os.path.join(self.checkout, uov.RESULTS, 'rtl-32k-20261002T000000Z', 'results.csv')
        kept = uov.read(left)
        self.write(self.checkout, {left: kept.replace(',13,', ',14,', 1)})
        self.refused('not published', a, b)                                                # other bytes at the destination
        self.write(self.checkout, {left: kept})
        other = os.path.join(os.path.dirname(left), 'manifest.json')
        kept_manifest = uov.read(other)
        self.write(self.checkout, {other: kept_manifest.replace('"rows": 1', '"rows":  1')})
        self.refused('manifest.json is not the snapshot being checked', a, b)              # another manifest there
        self.write(self.checkout, {other: kept_manifest})
        with self.assertRaises(uov.Stop) as e:                                             # the definition moved on meanwhile
            uov.rtl_publish(self.checkout, 'r1', 'f' * 64, [uov.rtl_record(r, self.defn, self.dsha) for r in (a, b)])
        self.assertIn('changed since the run directories were read', str(e.exception))
        self.assertEqual(self.published()[1], [])
        self.assertEqual(len(self.imp(a, b)), 2)

    def importers(self, *runs):
        code = ('import os, sys, time; sys.path.insert(0, {tools!r}); import uov\n'
                'uov.REPO = {tool!r}\n'
                'uov.gcm.CELLS, uov.gcm.ONESHOT_CELLS = {c32!r}, {c128!r}\n'
                'uov.head_blob = lambda checkout, rel: open(os.path.join(checkout, rel), "rb").read()\n'
                'read = uov.rtl_completed\n'
                'def slow(*a):\n    done = read(*a)\n    time.sleep(1)\n    return done\n'
                'uov.rtl_completed = slow\n'
                'defn, dsha = uov.load_rtl_definition({pub!r}, "r1")\n'
                'try:\n    uov.rtl_publish({pub!r}, "r1", dsha, [uov.rtl_record(sys.argv[1], defn, dsha)])\n'
                'except uov.Stop:\n    sys.exit(3)\n')
        code = code.format(tools=os.path.dirname(os.path.abspath(uov.__file__)), tool=self.tool, c32=RTL32, c128=RTL128,
                           pub=self.checkout)
        procs = [subprocess.Popen([sys.executable, '-c', code, r], stdout=subprocess.DEVNULL) for r in runs]
        return sorted(p.wait() for p in procs)

    def test_concurrent_imports_keep_every_cell_and_one_owner(self):
        # each importer pauses between reading and writing the list: without the lock one profile would be lost
        self.assertEqual(self.importers(self.archive(32, RTL32), self.archive(128, RTL128)), [0, 0])
        self.assertEqual(len(self.published()[1]), 4)
        shutil.rmtree(os.path.join(self.checkout, uov.RESULTS))
        os.makedirs(os.path.join(self.checkout, uov.CAMPAIGNS))
        self.defn, self.dsha = self.define()
        self.assertEqual(self.importers(self.archive(32, RTL32, stamp='20261001T000000Z'),
                                        self.archive(32, RTL32, stamp='20261002T000000Z')), [0, 3])
        runs, cells = self.published()
        self.assertEqual(len(cells), 2)
        self.assertEqual(len({e['run'] for e in uov.rtl_completed(self.checkout, 'r1', self.defn, self.dsha).values()}), 1)

    def test_listed_records_are_checked_before_anything_changes(self):
        self.imp(self.archive(32, RTL32, stamp='20261001T000000Z'))
        final = os.path.join(self.checkout, uov.RESULTS, 'rtl-32k-20261001T000000Z')
        _, path = uov.campaign_files(self.checkout, 'r1')
        good_csv, good_list, good_manifest = (uov.read(os.path.join(final, 'results.csv')), uov.read(path),
                                              uov.read(os.path.join(final, 'manifest.json')))
        other = self.archive(128, RTL128)
        m = json.loads(good_manifest)
        one = dict(json.loads(good_list), cells=dict(list(json.loads(good_list)['cells'].items())[:1]))
        for what, files, why in (
                ('a changed number', {os.path.join(final, 'results.csv'): good_csv.replace(',13,', ',14,', 1)}, 'results.csv differs from the hash'),
                ('a third file', {os.path.join(final, 'notes.txt'): 'x'}, 'the record is not manifest.json and results.csv'),
                ('a rewritten manifest', {os.path.join(final, 'manifest.json'): good_manifest.replace(self.rev, self.head)}, 'is missing or altered'),
                ('a run listed with one of its two cells', {path: json.dumps(one)}, 'is not listed with exactly its cells'),
                ('a record that names another run',
                 {os.path.join(final, 'manifest.json'): good_manifest.replace('rtl-32k-20261001T000000Z', 'rtl-32k-20261009T000000Z'),
                  path: good_list.replace(uov.sha256(os.path.join(final, 'manifest.json')),
                                          sha(good_manifest.replace('rtl-32k-20261001T000000Z', 'rtl-32k-20261009T000000Z')))},
                 'is not listed with exactly its cells'),
                ('one run with two manifests', {path: json.dumps(dict(json.loads(good_list), cells={
                    k: dict(e, manifest=('e' * 64 if i else e['manifest'])) for i, (k, e) in enumerate(json.loads(good_list)['cells'].items())}))},
                 'bad entry'),
                ('another definition', {path: good_list.replace(self.dsha, 'f' * 64)}, 'belongs to another version')):
            with self.subTest(what):
                self.write(self.checkout, files)
                self.refused(why, other)
                self.assertEqual(self.published()[0], ['rtl-32k-20261001T000000Z'])
                if what == 'a third file':
                    os.remove(os.path.join(final, 'notes.txt'))
                self.write(self.checkout, {os.path.join(final, 'results.csv'): good_csv, path: good_list,
                                           os.path.join(final, 'manifest.json'): good_manifest})
        for what, change, why in (('another commit', dict(source=dict(m['source'], commit=self.head)), 'source is not the definition'),
                                  ('another overlay', dict(source=dict(m['source'], overlay={'x': ['a' * 64, '100644']})), 'source is not the definition'),
                                  ('a cell of the other profile', dict(cells=[cell_name(RTL128[0])]), 'cells are not 32 KiB cells'),
                                  ('fewer rows than it counts', dict(completion=dict(m['completion'], rows=3)), 'completion record'),
                                  ('another importer', dict(tools=dict(m['tools'], publishing=self.rev)), 'tools record'),
                                  ('another definition', dict(definition='f' * 64), 'manifest identity'),
                                  ('no Bazel version', dict(execution=dict(m['execution'], bazel='')), 'execution record'),
                                  ('no inventory digest', dict(archive=dict(m['archive'], inventory='x')), 'archive record'),
                                  ('another csv header', dict(evidence={'results.csv': sha(good_csv.replace('acc_insn', 'insns', 1))}),
                                   'results.csv columns'),
                                  ('a row of another contract, hashed as it is', dict(evidence={'results.csv': sha(good_csv.replace(',2,', ',1,', 1))}),
                                   'not a meters v2 row with its counters'),
                                  ('a counter with a digit that is not 0-9, hashed as it is',
                                   dict(evidence={'results.csv': sha(good_csv.replace(',13,', ',\u00b2,', 1))}), 'not a meters v2 row with its counters')):
            with self.subTest(what), tempfile.TemporaryDirectory() as d:
                csv_text = {'another csv header': good_csv.replace('acc_insn', 'insns', 1),
                            'a row of another contract, hashed as it is': good_csv.replace(',2,', ',1,', 1),
                            'a counter with a digit that is not 0-9, hashed as it is': good_csv.replace(',13,', ',\u00b2,', 1)}.get(what, good_csv)
                self.assertTrue('hashed as it is' not in what and what != 'another csv header' or csv_text != good_csv)
                self.write(d, {'manifest.json': json.dumps(dict(m, **change)), 'results.csv': csv_text})
                with self.assertRaises(uov.Refused) as e:
                    uov.validate_rtl_bundle(d, self.defn, self.dsha)
                self.assertIn(why, str(e.exception))
        self.assertEqual(uov.RTL_TOOLS_OF, {
            'contract2-g2': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py', 'tools/acc_bind.py'),
            'chip-meters-g3': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py', 'tools/check_firmware_kernels.py'),
            'chip-meters-g4': ('tools/rtl_campaign.sh', 'tools/gather_chip_matrix.py')})
        g3 = {t: 'a' * 64 for t in uov.RTL_TOOLS_OF['chip-meters-g3']}                    # the tools of each generation, no other
        for gen, tools, ok in (('chip-meters-g3', g3, True), (uov.RTL_GENERATION, g3, False), ('chip-meters-g3', m['tools']['measuring'], False)):
            with self.subTest(gen=gen, tools=sorted(tools)), tempfile.TemporaryDirectory() as d:
                self.write(d, {'manifest.json': json.dumps(dict(m, tools=dict(m['tools'], measuring=tools))), 'results.csv': good_csv})
                defn = dict(self.defn, generation=gen)
                if ok:
                    uov.validate_rtl_bundle(d, defn, self.dsha)
                else:
                    with self.assertRaises(uov.Refused) as e:
                        uov.validate_rtl_bundle(d, defn, self.dsha)
                    self.assertIn('tools record', str(e.exception))
        self.assertEqual(len(self.imp(other)), 4)                                           # positive control: all restored
        whole = json.loads(uov.read(path))
        self.write(self.checkout, {path: json.dumps(dict(whole, cells={k: e for k, e in whole['cells'].items() if k.endswith('@32')
                                                                         or cell_name(RTL128[0]) in k}))})
        with self.assertRaises(uov.Stop) as e:
            uov.rtl_completed(self.checkout, 'r1', self.defn, self.dsha)
        self.assertIn('is not listed with exactly its cells', str(e.exception))

    def test_the_importer_runs_from_a_clean_tree_at_the_tooling_commit(self):
        a = SimpleNamespace(publish_to=self.checkout, campaign='r1', archive=[self.archive(32, RTL32)])

        def run():
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                return uov.run_rtl_import(a), err.getvalue()
        self.write(self.tool, {'tools/later.txt': 'edited\n'})
        self.assertEqual(run()[0], 2)
        self.assertIn('clean tree at the definition\'s tooling commit', run()[1])
        git(self.tool, 'checkout', '--', 'tools/later.txt')
        self.assertEqual(run(), (0, ''))
        self.assertEqual(len(self.published()[1]), 2)
        self.write(self.tool, {'tools/newer.txt': 'x\n'})
        commit_all(self.tool, 'a later commit')
        self.assertEqual(run()[0], 2)

    def test_a_definition_is_read_only_as_committed_and_for_this_catalog(self):
        with self.assertRaises(uov.Stop) as e:
            self.define(name='loose', commit=False)
        self.assertIn('is not committed', str(e.exception))
        for what, kw in (('an ISS-shaped definition', dict(engine='iss')), ('a cell list of another catalog', dict(cells=self.defn['cells'][:-1])),
                         ('no pinned configuration', dict(config={'.bazelrc-site': None})), ('a short commit', dict(measuring_commit='abc'))):
            with self.subTest(what), self.assertRaises(uov.Stop) as e:
                self.define(name='bad', **kw)
            self.assertIn('is not an RTL definition', str(e.exception))

    def test_rtl_init_registers_once(self):
        a = SimpleNamespace(name='new', publish_to=self.checkout, measured_at=self.rev, bazelrc_site=self.rc)

        def init(**kw):
            err = io.StringIO()
            try:
                with mock.patch.object(uov, 'profile_overlays', return_value=self.defn['overlays']), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    uov.rtl_init(SimpleNamespace(**dict(vars(a), **kw)))
            except SystemExit as e:
                return e.code, err.getvalue()
            return 0, ''
        self.assertIn('is not a commit', init(measured_at='0' * 40)[1])
        self.assertIn('is not a file', init(bazelrc_site=os.path.join(self.tmp.name, 'none'))[1])
        self.write(self.tool, {'tools/later.txt': 'edited\n'})
        self.assertIn('tracked changes', init()[1])
        git(self.tool, 'checkout', '--', 'tools/later.txt')
        path, _ = uov.campaign_files(self.checkout, 'new')
        self.assertFalse(os.path.exists(path))
        self.assertEqual(init(), (0, ''))
        with open(path, 'rb') as fh:
            self.committed[os.path.relpath(path, self.checkout)] = fh.read()
        d, _ = uov.load_rtl_definition(self.checkout, 'new')
        want = {k: v for k, v in self.defn.items() if k not in ('name', 'created')}
        self.assertEqual({k: v for k, v in d.items() if k not in ('name', 'created')}, want)
        self.assertEqual(init(), (2, f'uov.py: {path} exists; a definition is never rewritten\n'))


class Provenance(unittest.TestCase):
    """tree_overlay(), provenance() and the committed-definition check on real temp repositories."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def repo(self, name='r'):
        d = os.path.join(self.tmp.name, name)
        git_init(d)
        for f in 'abcef':
            with open(os.path.join(d, f), 'w') as fh:
                fh.write(f)
            os.chmod(os.path.join(d, f), 0o644)
        with open(os.path.join(d, '.gitignore'), 'w') as fh:
            fh.write('.nohooks/\n.bazelrc-site\n')
        return d, commit_all(d)

    def test_overlay_sees_edits_deletions_modes_and_type_changes(self):
        d, _ = self.repo()
        self.assertEqual(uov.tree_overlay(d), {})
        with open(os.path.join(d, 'a'), 'w') as fh:
            fh.write('A')
        os.remove(os.path.join(d, 'b'))
        os.chmod(os.path.join(d, 'c'), 0o755)
        os.remove(os.path.join(d, 'e'))
        os.symlink('a', os.path.join(d, 'e'))
        os.remove(os.path.join(d, 'f'))
        os.mkdir(os.path.join(d, 'f'))
        with open(os.path.join(d, 'f', 'x'), 'w') as fh:
            fh.write('x')
        self.assertEqual(uov.tree_overlay(d), {'a': [uov.sha256(os.path.join(d, 'a')), '100644'], 'b': [None, None],
                                               'c': [uov.sha256(os.path.join(d, 'c')), '100755'],
                                               'e': ['not a regular file', None], 'f': ['not a regular file', None]})

    def test_provenance_accepts_the_commit_and_refuses_each_drift(self):
        def problems(d, head, commit=None):
            defn = {'tooling_commit': commit or head, 'overlays': {'512': {}}, 'config': {'.bazelrc-site': None}}
            with mock.patch.object(uov, 'REPO', d), mock.patch.object(uov, 'actual_layout', return_value=uov.expected_layout(512)):
                return ' | '.join(uov.provenance(defn, 512))
        d, head = self.repo('clean')
        self.assertEqual(problems(d, head), '')
        drifts = {'edit': (lambda d: open(os.path.join(d, 'a'), 'w').write('A'), 'overlay'),
                  'mode': (lambda d: os.chmod(os.path.join(d, 'c'), 0o755), 'overlay'),
                  'deletion': (lambda d: os.remove(os.path.join(d, 'b')), 'overlay'),
                  'staged': (lambda d: (open(os.path.join(d, 'a'), 'w').write('A'), git(d, 'add', 'a')), 'staged changes'),
                  'configuration': (lambda d: open(os.path.join(d, '.bazelrc-site'), 'w').write('x'), 'Bazel configuration')}
        for name, (drift, says) in drifts.items():
            with self.subTest(name):
                d, head = self.repo(name)
                self.assertEqual(problems(d, head), '')                         # passes before the drift
                drift(d)
                self.assertIn(says, problems(d, head))
        d, head = self.repo('other-head')
        self.assertIn('HEAD is not the campaign tooling commit', problems(d, head, commit='f' * 40))

    def test_a_definition_is_read_only_as_committed(self):
        d, _ = self.repo('pub')
        os.makedirs(os.path.join(d, uov.CAMPAIGNS))
        defn = {'schema': 1, 'name': 'c1', 'created': 'now', 'tooling_commit': 'a' * 40, 'config': {'.bazelrc-site': None},
                'overlays': {'512': {}}, 'cohorts': [COHORT]}
        path, _ = uov.campaign_files(d, 'c1')
        with open(path, 'w') as fh:
            json.dump(defn, fh)
        with self.assertRaises(uov.Stop):                                     # not committed yet
            uov.load_definition(d, 'c1')
        commit_all(d, 'campaign c1')
        got, dsha = uov.load_definition(d, 'c1')
        self.assertEqual((got['cohorts'], dsha), ([COHORT], uov.sha256(path)))
        committed = uov.read(path)
        with open(path, 'a') as fh:                                            # edited after the commit
            fh.write(' ')
        self.assertEqual(uov.head_blob(d, os.path.relpath(path, d)).decode(), committed)
        with self.assertRaises(uov.Stop):
            uov.load_definition(d, 'c1')


class Records(unittest.TestCase):
    """finalize_record(): raw collector output in, tidy evidence out, with the same content."""
    COH = dict(COHORT_IS, cases=[0])
    HEADER = 'op,param,tier,variant,case,kat,instructions,cycles'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = os.path.join(self.tmp.name, 'run')
        os.makedirs(os.path.join(self.run, 'kat', 'stats'))
        name = uov.gks.stats_name(*uov.cohort_cells(self.COH)[0])
        self.write('kat/results.csv', f'{self.HEADER}\r\nkeygen,Is,bngfaes,full,0,PASS,5,7\r\n')   # csv.writer default
        self.write(f'kat/stats/{name}', '\nExecution time\n--------------\nACC executed 5 instructions in 7 cycles.\n'
                                        'instruction  count  \n\n\n')
        self.write(f'kat/stats/{name}.log', f'[PASS] Is/bngfaes case0  \n\n=== Is/bngfaes: 1 pass ===\n    elf {self.run}/bin/x.elf\n'
                                            f'Parsing test data from: {uov.REPO}/sw/t\n')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        with open(os.path.join(self.run, rel), 'w', newline='') as fh:
            fh.write(text)

    def test_record_text_is_tidy_and_keeps_its_content(self):
        rec = uov.finalize_record(self.run, 'run-a', self.COH, {})
        m = json.loads(uov.read(os.path.join(rec, 'manifest.json')))
        self.assertEqual(set(m['evidence']), uov.evidence_names(uov.cohort_cells(self.COH)))
        for rel, h in m['evidence'].items():
            p = os.path.join(rec, rel)
            t = uov.read(p, newline='')
            with self.subTest(rel):
                self.assertEqual(uov.sha256(p), h)
                self.assertEqual('\n'.join(x.rstrip() for x in t.strip().split('\n')) + '\n', t)  # the repo lint's form
                r = subprocess.run(['git', 'diff', '--no-index', '--check', '--', '/dev/null', p], capture_output=True, text=True)
                self.assertEqual((r.returncode, r.stdout + r.stderr), (1, ''))   # 1: a new file, no whitespace error
        stem = os.path.join(rec, 'cells', uov.cell_stem(*uov.cohort_cells(self.COH)[0]))
        self.assertEqual(uov.read(os.path.join(rec, 'results.csv')), f'{self.HEADER}\nkeygen,Is,bngfaes,full,0,PASS,5,7\n')
        self.assertEqual(uov.read(stem + '.stats.txt'), 'Execution time\n--------------\n'
                                                       'ACC executed 5 instructions in 7 cycles.\ninstruction  count\n')
        self.assertEqual(uov.read(stem + '.driver.txt'), '[PASS] Is/bngfaes case0\n\n=== Is/bngfaes: 1 pass ===\n    elf x.elf\n'
                                                        'Parsing test data from: sw/t\n')

    def test_csv_fields_tidying_would_change_are_refused(self):
        self.write('kat/results.csv', f'{self.HEADER}\nkeygen,Is,bngfaes,full,0,PASS,5,7 \n')
        with self.assertRaises(uov.Stop):
            uov.finalize_record(self.run, 'run-a', self.COH, {})

    def test_collector_completion_and_counts(self):
        rs = [dict(op='keygen', param='Is', tier='bngfaes', variant='full', case='0', kat='PASS', instructions='5', cycles='7')]
        self.write('collector.log', 'gathering 1 cells\nDONE 1/1 -> x  (all PASS)\n')
        self.assertTrue(uov.collector_completed(self.run, rs, self.COH))
        self.assertFalse(uov.collector_completed(self.run, [], self.COH))
        self.write('collector.log', 'gathering 1 cells\nTraceback\n')
        self.assertFalse(uov.collector_completed(self.run, rs, self.COH))
        def name_of(cell):
            return uov.gks.stats_name(*cell)
        stats = os.path.join(self.run, 'kat', 'stats')
        self.assertEqual(uov.count_problems(stats, rs, name_of, self.COH), [])
        self.assertNotEqual(uov.count_problems(stats, [dict(rs[0], cycles='8')], name_of, self.COH), [])


sys.path[:0] = [os.path.join(uov.REPO, 'util'), os.path.join(uov.REPO, 'hw/ip/acc/util')]
import acc_build


class Profile(unittest.TestCase):
    def setUp(self):
        self.hj = open(os.path.join(uov.REPO, uov.HJSON)).read()
        self.mu = open(os.path.join(uov.REPO, uov.MEMUTIL)).read()
        self.assertIn(uov.current(self.hj), uov.PROFILES)

    def test_round_trip(self):
        for a, b in itertools.permutations(uov.PROFILES, 2):
            here = uov.set_hjson(self.hj, a)
            self.assertEqual(uov.current(here), a)
            self.assertEqual(uov.set_hjson(uov.set_hjson(here, b), a), here)
            self.assertEqual(uov.set_memutil(uov.set_memutil(uov.set_memutil(self.mu, a), b), a), uov.set_memutil(self.mu, a))
        self.assertIn('131072 / 32', uov.set_memutil(self.mu, 128))
        self.assertIn('524288 / 32', uov.set_memutil(self.mu, 512))
        self.assertIn('RegisterMemoryArea("dmem", 0x80000,', uov.set_memutil(self.mu, 128))

    def test_stale_items_comment(self):
        # one profile's value under another's comment: every switch must still reach a consistent profile
        for a, b in itertools.permutations(uov.PROFILES, 2):
            stale = uov.set_hjson(self.hj, a).replace(uov.PROFILES[a][2], uov.PROFILES[b][2])
            self.assertEqual(uov.current(stale), a)
            for c in uov.PROFILES:
                self.assertEqual(uov.set_hjson(stale, c), uov.set_hjson(self.hj, c))

    def test_unknown_state(self):
        self.assertIsNone(uov.current('{ skipto: "0x40000" }\n items: "123", // x'))

    def test_malformed_memutil_refused(self):
        with self.assertRaises(AssertionError):
            uov.set_memutil('no dmem here', 128)

    def test_a_tree_without_git_is_seen_as_such(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(uov, 'REPO', tmp):
            self.assertFalse(uov.in_git())

    def test_unknown_profile_refused_through_main(self):
        bad = '{ skipto: "0x40000" }\n items: "123", // x\n'
        with tempfile.TemporaryDirectory() as tmp:
            for rel, text in ((uov.HJSON, bad), (uov.MEMUTIL, 'no dmem here\n')):
                os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
                with open(os.path.join(tmp, rel), 'w') as fh:
                    fh.write(text)
            with mock.patch.object(uov, 'REPO', tmp), mock.patch.object(uov, 'regen') as regen, \
                    mock.patch.object(sys, 'argv', ['uov.py', 'profile', '--profile', '128']), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
                uov.main()
            self.assertEqual(e.exception.code, 2)
            regen.assert_not_called()
            with open(os.path.join(tmp, uov.HJSON)) as fh:
                self.assertEqual(fh.read(), bad)


class Checksum(unittest.TestCase):
    def checksum(self, data_start, words):
        sec = {'.text': mock.Mock(data=lambda: bytes(4)), '.data': mock.Mock(data=lambda: bytes(4 * words)),
               '.symtab': mock.Mock(get_symbol_by_name=lambda name: [{'st_value': data_start}])}
        with mock.patch.object(acc_build, 'ELFFile', return_value=mock.Mock(get_section_by_name=sec.get)), \
                tempfile.NamedTemporaryFile() as f:
            return acc_build.get_app_checksum(f.name)

    def test_word_index_limit(self):
        self.assertIsInstance(self.checksum(4 * 0x7ffe, 2), int)  # last .data word at index 0x7fff
        self.assertIsNone(self.checksum(4 * 0x7ffe, 3))           # first word past it
        self.assertIsNone(self.checksum(4 * 0x8000, 1))           # a high .data start alone
        self.assertIsInstance(self.checksum(0, 0), int)           # empty .data


class Observe(unittest.TestCase):
    """Observe records (the published trace and span records) rendered for the paper."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.results = os.path.join(self.tmp, 'results')
        src = os.path.join(uov.REPO, uov.RESULTS)
        for name in ('observe-trace-20261018T214345Z', 'observe-span-20261018T214359Z'):
            shutil.copytree(os.path.join(src, name), os.path.join(self.results, name))
        patch = mock.patch.object(uov, 'artifact_image', lambda art: art['image'])
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def artifacts(images):
        return {'run': 'iss-x', 'artifacts': {i: {'image': i} for i in images}}

    def test_records_are_rendered_next_to_the_same_binaries_only(self):
        recs = uov.observe_records(self.results)
        self.assertEqual(sorted(recs), ['span', 'trace'])
        vals = uov.observe_vars(self.results)
        self.assertEqual({k: vals[k] for k in ('ct:Ip:bngfaes:runs', 'ct:Ip:bngfaes:classes', 'ct:Ip:bngfaes:whole',
                                               'ct:Ip:bngfaes:bodies', 'ct:Ip:bngfaes:0:1:cycles', 'ct:Is:sw:whole',
                                               'ct:Is:sw:bodies', 'span:keygen:full:512:Ip:bngfaes:touched')},
                         {'ct:Ip:bngfaes:runs': 147, 'ct:Ip:bngfaes:classes': 6, 'ct:Ip:bngfaes:whole': 1,
                          'ct:Ip:bngfaes:bodies': 1, 'ct:Ip:bngfaes:0:1:cycles': 264574, 'ct:Is:sw:whole': 16,
                          'ct:Is:sw:bodies': 28, 'span:keygen:full:512:Ip:bngfaes:touched': '429696'})
        tabs = uov.observe_tables(vals)
        self.assertIn('\\Var{ct:Ip:bngfaes:runs}', tabs['tab-ct.tex'])
        self.assertIn('\\Var{span:', tabs['tab-span.tex'])
        images = {r['elf_image'] for k in recs for r in recs[k][1]}
        with mock.patch.object(uov, 'record_of', lambda *a: ('c', self.artifacts(images), [])):
            uov.observe_vars(self.results, pub={})
        trace = {r['elf_image'] for r in recs['trace'][1]}
        for kind, gone in (('trace', min(trace)), ('span', min({r['elf_image'] for r in recs['span'][1]} - trace))):
            with self.subTest(kind), mock.patch.object(uov, 'record_of', lambda *a, gone=gone: ('c', self.artifacts(images - {gone}), [])), \
                    self.assertRaises(uov.Refused) as e:                # each record is checked on its own
                uov.observe_vars(self.results, pub={})
            self.assertIn(f'observe-{kind}-', str(e.exception))
            self.assertIn('observed another ELF', str(e.exception))
        cell = ('sign', 'ldirect', 32, 'Ip', 'bngfaes')                # an early row of another ELF, the expected one last
        with mock.patch.object(uov, 'record_of', lambda *a: ('c', self.artifacts({'img-z-good'}), [])), \
                self.assertRaises(uov.Refused):                         # the bad one sorts first: one per cell would miss it
            uov.observed_binaries_match({}, self.results, 'observe-trace-x', {(cell, 'img-a-other'), (cell, 'img-z-good')})

    def test_a_changed_results_csv_is_refused(self):
        run = uov.observe_records(self.results)['span'][0]['run']
        with open(os.path.join(self.results, run, 'results.csv'), 'a') as fh:
            fh.write('x\n')
        with self.assertRaises(uov.Stop):
            uov.observe_records(self.results)



class RetryRecords(unittest.TestCase):
    """Retry records (one sign kernel on a vector set with known retries) rendered for the paper."""
    BASE = {('ldirect', 'Ip'): (269356, 258191), ('sprec', 'Ip'): (1569543, 84526),
            ('ldirect', 'Is'): (283931, 273992), ('sprec', 'Is'): (2157730, 93714)}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.results = os.path.join(self.tmp, 'results')
        patch = mock.patch.object(uov, 'artifact_image', lambda art: art['image'])
        patch.start()
        self.addCleanup(patch.stop)

    def record(self, kernel, cycles=None, created='2026-11-02T18:00:00+01:00', name=None):
        """A retry record of two keys, 32 B, 0-2 retries; cycles(param, key, retries) overrides the counts."""
        profile = uov.RETRY_KERNELS[kernel]
        name = name or f'retry-{profile}-20261102T170000Z-0000000{len(os.listdir(self.results)) if os.path.isdir(self.results) else 0}'
        d = os.path.join(self.results, name)
        os.makedirs(os.path.join(d, 'cells'))
        table = [['kernel', 'profile', 'tier', 'param', 'case', 'key_case', 'msg_len', 'attempts', 'instructions', 'cycles']]
        case = 0
        for p in ('Ip', 'Is'):
            base, step = self.BASE[kernel, p]
            for key in (0, 1):
                for n in (0, 1, 2):
                    c = cycles(p, key, n) if cycles else base + n * step
                    if c is None:
                        continue
                    table.append([kernel, profile, 'bngfaes', p, case, key, 32, n + 1, 1, c])
                    case += 1
        buf = io.StringIO()
        csv.writer(buf, lineterminator='\n').writerows(table)
        with open(os.path.join(d, 'results.csv'), 'w') as fh:
            fh.write(buf.getvalue())
        with open(os.path.join(d, 'cells', 'x.stats.txt'), 'w') as fh:
            fh.write('evidence\n')
        m = {'kernel': kernel, 'profile': profile, 'tier': 'bngfaes', 'run': name, 'created': created,
             'artifacts': {f'//{p}': {'param': p, 'image': f'img-{kernel}-{p}'} for p in ('Ip', 'Is')}, 'vectors': {'v': 'h'},
             'results_sha256': hashlib.sha256(buf.getvalue().encode()).hexdigest(),
             'evidence': {f: uov.sha256(os.path.join(d, f)) for f in ('results.csv', 'cells/x.stats.txt')}}
        with open(os.path.join(d, 'manifest.json'), 'w') as fh:
            json.dump(m, fh)
        return d

    def test_counts_steps_and_model(self):
        self.record('ldirect')
        self.record('sprec')
        vals = uov.retry_vars(self.results)
        self.assertEqual(vals['retrygrid:ldirect:Ip:32:2:cyc'], 269356 + 2 * 258191)
        self.assertEqual(vals['retrygrid:sprec:Is:32:step'], 93714)
        self.assertEqual(vals['retrygrid:Ip:keys'], 2)
        self.assertEqual((vals['retrygrid:Ip:breakeven'], vals['retrygrid:Is:breakeven']), (8, 11))
        self.assertEqual((vals['retrygrid:Ip:pfail'], vals['retrygrid:Is:pfail']), ('0.392', '6.641'))
        self.assertEqual((vals['retrygrid:Ip:ratio'], vals['retrygrid:Ip:tail'], vals['retrygrid:Is:tail']),
                         ('5.81', '5.6e-20', '1.1e-13'))
        self.assertEqual(vals['retrygrid:Ip:over:ldirect'], '0.38')
        tabs = uov.retry_tables(vals)
        self.assertIn(r'\Var{retrygrid:sprec:Ip:32:1:cyc}', tabs['tab-retrygrid.tex'])
        self.assertIn(r'uov-Ip-r2 & 32\,B & \kernel{sprec} & ', tabs['tab-retrygrid.tex'])   # kernel names in the paper's style
        self.assertIn(r'\Var{retrygrid:Is:breakeven}', tabs['tab-retrymodel.tex'])
        self.assertIn(r'\kernel{ldirect} average (cycles) & \kernel{sprec} average (cycles)', tabs['tab-retrymodel.tex'])

    def test_one_kernel_gives_no_model(self):
        self.record('ldirect')
        vals = uov.retry_vars(self.results)
        self.assertIn('retrygrid:ldirect:Ip:32:step', vals)
        self.assertNotIn('retrygrid:Ip:breakeven', vals)
        self.assertNotIn('tab-retrymodel.tex', uov.retry_tables(vals))

    def test_keys_that_disagree_are_refused(self):
        self.record('ldirect', cycles=lambda p, key, n: 1000 + n * 100 + key)
        with self.assertRaisesRegex(uov.Refused, 'the keys give'):
            uov.retry_vars(self.results)

    def test_retries_of_different_cost_are_refused(self):
        self.record('ldirect', cycles=lambda p, key, n: 1000 + n * n * 100)
        with self.assertRaisesRegex(uov.Refused, 'not one cost each'):
            uov.retry_vars(self.results)

    def test_a_changed_or_extra_file_is_refused(self):
        d = self.record('ldirect')
        with open(os.path.join(d, 'results.csv'), 'a') as fh:
            fh.write('ldirect,32,bngfaes,Ip,99,0,32,1,1,5\n')
        with self.assertRaisesRegex(uov.Refused, 'do not match its manifest'):
            uov.retry_records(self.results)
        shutil.rmtree(d)
        d = self.record('ldirect')
        with open(os.path.join(d, 'cells', 'y.txt'), 'w') as fh:
            fh.write('more\n')
        with self.assertRaisesRegex(uov.Refused, 'do not match its manifest'):
            uov.retry_records(self.results)

    def test_a_record_of_another_tier_or_profile_is_refused(self):
        d = self.record('ldirect')
        m = json.load(open(os.path.join(d, 'manifest.json')))
        m['tier'] = 'sw'
        json.dump(m, open(os.path.join(d, 'manifest.json'), 'w'))
        with self.assertRaisesRegex(uov.Refused, 'not a bngfaes record'):
            uov.retry_records(self.results)

    def test_two_records_of_a_kernel_are_refused(self):
        self.record('ldirect')
        self.record('ldirect')
        with self.assertRaisesRegex(uov.Refused, 'two retry records of ldirect'):
            uov.retry_records(self.results)

    def test_records_of_different_vectors_are_refused(self):
        self.record('ldirect')
        d = self.record('sprec')
        m = json.load(open(os.path.join(d, 'manifest.json')))
        m['vectors'] = {'other': 'x'}
        json.dump(m, open(os.path.join(d, 'manifest.json'), 'w'))
        with self.assertRaisesRegex(uov.Refused, 'different vector files'):
            uov.retry_records(self.results)

    def test_a_missing_retry_or_key_is_refused(self):
        self.record('ldirect', cycles=lambda p, key, n: 1000 + n * 100 if n < 2 else None)
        with self.assertRaisesRegex(uov.Refused, 'not one cost each'):
            uov.retry_vars(self.results)

    def test_other_binaries_than_the_published_ones_are_refused(self):
        self.record('ldirect')
        with mock.patch.object(uov, 'record_of', lambda pub, e, key, rd: ('c', {'artifacts': {'x': {'image': 'img-other'}},
                                                                             'run': 'iss-x'}, [])):
            with self.assertRaisesRegex(uov.Refused, 'observed another ELF'):
                uov.retry_vars(self.results, pub={})

    def test_the_committed_index_matches_its_vector_files(self):
        index = uov.retry_index('retrygrid')
        for p in ('Ip', 'Ip3', 'Is'):
            self.assertEqual(len(index[p]), 36)
            self.assertEqual(sorted({key for key, _, _ in index[p]}), [0, 1, 2, 3])
            self.assertEqual(sorted(a for _, _, a in index[p]), [1] * 12 + [2] * 12 + [3] * 12)
            path = f'{uov.gks.HANDWRITTEN_DIR}/test_data/testvectors-{p}-pkc-skc.retrygrid'
            self.assertEqual(uov.gks.vector_cases(path), 36)

    def test_an_index_that_does_not_describe_its_vectors_stops(self):
        td = os.path.join(self.tmp, 'td')
        src = os.path.dirname(uov.retry_index_path('retrygrid'))
        os.makedirs(td)
        for f in ('testvectors-Ip-pkc-skc', 'testvectors-Ip-pkc-skc.retrygrid'):
            shutil.copy(os.path.join(src, f), td)
        good = open(os.path.join(src, 'testvectors-retrygrid-index.csv')).read().split('\n')
        head, ip = good[0], [x for x in good if x.startswith('Ip,')]
        for bad in (ip[0].replace(',0,0,1', ',0,32,1'), ip[0].replace('Ip-pkc-skc,0,', 'Ip-pkc-skc,1,')):
            with self.subTest(row=bad):
                with open(os.path.join(td, 'testvectors-retrygrid-index.csv'), 'w') as fh:
                    fh.write('\n'.join([head, bad] + ip[1:]) + '\n')
                with mock.patch.object(uov, 'retry_index_path', lambda v: os.path.join(td, f'testvectors-{v}-index.csv')):
                    with self.assertRaisesRegex(uov.Stop, 'does not describe its vector'):
                        uov.retry_index('retrygrid')

    def test_an_index_out_of_order_stops(self):
        path = os.path.join(self.tmp, 'testvectors-bad-index.csv')
        with open(path, 'w') as fh:
            fh.write('param,case,key_file,key_case,msg_len,attempts\nIp,1,f,0,0,1\n')
        with mock.patch.object(uov, 'retry_index_path', lambda v: path):
            with self.assertRaisesRegex(uov.Stop, 'out of order'):
                uov.retry_index('bad')

    def test_uniform_tuned_table_reads_the_published_ratios(self):
        vals = {'ratio:keygen:stream_uniform:32:tuned:32:Ip:sw': '1.00', 'iss:keygen:stream_uniform:32:Ip:sw:lo': 5,
                'iss:keygen:stream_uniform:32:Ip:sw:hi': 5, 'iss:keygen:tuned:32:Ip:sw:lo': 4, 'iss:keygen:tuned:32:Ip:sw:hi': 6}
        tab = uov.uniform_tuned_table(vals)['tab-uniform-tuned.tex']
        self.assertIn(r'\num{\Var{iss:keygen:stream_uniform:32:Ip:sw:lo}} &', tab)
        self.assertIn(r'\num{\Var{iss:keygen:tuned:32:Ip:sw:lo}}--\num{\Var{iss:keygen:tuned:32:Ip:sw:hi}}', tab)
        self.assertEqual(uov.uniform_tuned_table({}), {})

    def test_speedups_over_another_base_use_the_same_kept_cases(self):
        def rec(cycles, retried=()):
            return 'c', {'run': 'r', 'source': {'vectors': {'v': 'e' * 64}}}, \
                [{'case': str(c), 'cycles': str(n), 'retries': int(c in retried)} for c, n in enumerate(cycles)]
        tiers = ('sw', 'bngfonly', 'bnaesonly', 'bngfaes')
        cells = {('sw', 'Is'): rec([1000] * 4), ('bngfonly', 'Is'): rec([300, 300, 300, 900]),
                 ('bnaesonly', 'Is'): rec([50, 50, 50, 999999], retried=(3,)), ('bngfaes', 'Is'): rec([10, 10, 10, 100])}
        self.assertEqual(uov.speedups(cells, tiers, 'Is')['bngfaes'], '100x')
        self.assertEqual(uov.speedups(cells, tiers, 'Is', 'bngfonly')['bngfaes'], '30x')
        self.assertEqual(uov.speedups(cells, tiers, 'Is', 'bnaesonly')['bngfaes'], '5x')     # case 3 retried: left out

    def test_paper_claims_compute_the_quoted_numbers_and_refuse_a_broken_one(self):
        vals = {'ratio:verify:stream_uniform:32:tuned:32:Ip:bngfaes': '1.25', 'ratio:verify:stream_uniform:32:tuned:32:Ip:sw': '1.00',
                'ratio:verify:stream_uniform:32:tuned:32:Ip:bngfonly': '1.10', 'span:sign:ldirect:32:Ip:bngfaes:touched': 13164,
                'spd:verify:stream_uniform:32:Ip:bngfonly': '2.5', 'spd:verify:stream_uniform:32:Ip:bnaesonly': '14.3',
                'spd:verify:stream_uniform:32:Ip:bngfaes': '100', 'spd:verify:tuned:32:Ip:bngfaes': '125',
                'spd:verify:tuned:32:Ip:bngfonly': '2.75',
                'ct:Ip:bngfaes:whole': 1, 'ct:Ip:bngfaes:bodies': 1, 'ct:Ip:sw:whole': 16, 'ct:Ip:bngfaes:runs': 147,
                'ct:Is:bngfaes:runs': 168, 'retrygrid:Ip:ratio': '5.81', 'retrygrid:Ip:keys': 4, 'retrygrid:Is:keys': 4,
                'retrygrid:ldirect:Ip:32:0:cyc': 1000, 'retrygrid:ldirect:Ip:32:step': 950,
                'retrygrid:sprec:Ip:32:0:cyc': 5000, 'retrygrid:sprec:Ip:32:step': 300,
                'iss:keygen:min:128:Ip:sw:sum': 5000, 'iss:keygen:sp:128:Ip:sw:sum': 1000,
                'iss:keygen:min:128:Ip:bnaesonly:sum': 1100, 'iss:keygen:sp:128:Ip:bnaesonly:sum': 1000,
                'iss:keygen:min:128:Ip:bngfaes:sum': 220, 'iss:keygen:sp:128:Ip:bngfaes:sum': 100,
                'mem:keygen:min:128:Ip:bngfaes:bss': 60000, 'mem:keygen:sp:128:Ip:bngfaes:bss': 88000}
        sums = {('stream_uniform', 'sw'): 1000, ('stream_uniform', 'bngfonly'): 400, ('stream_uniform', 'bnaesonly'): 70,
                ('stream_uniform', 'bngfaes'): 10, ('tuned', 'sw'): 1000, ('tuned', 'bngfonly'): 364, ('tuned', 'bngfaes'): 8}
        for (k, t), n in sums.items():
            vals[f'iss:verify:{k}:32:Ip:{t}:sum'] = n
        out = uov.paper_claims(vals)
        self.assertEqual((out['claim:uniform-max'], out['claim:gain:tuned'], out['claim:gain:uniform']), ('1.25', '125', '100'))
        self.assertEqual(out['claim:gain:what'], 'uov-Ip-r2 verification with both instructions')   # 1.25 beats bngfonly's 1.10
        self.assertEqual((out['claim:sbuild:Ip'], out['claim:sbuild:Is'], out['claim:sbuf:Ip:kib'], out['claim:sbuf:Ip:over']),
                         ('19', '27.3', 129, '10'))                 # 68*67*44^2 / (68*67*44 + 2*68*44^2); 131648 B / 13164 B
        self.assertEqual((out['claim:ct:runs:min'], out['claim:ct:runs:max']), (147, 168))
        self.assertEqual((out['claim:minsp:aesonly:max'], out['claim:minsp:noaes:min'], out['claim:minsp:both:max'],
                          out['claim:minsp:Ip:save']), ('1.1', '5', '2.2', 32))      # 28000 / 88000 = 31.8 %
        for bad, why in (({'spd:verify:tuned:32:Ip:bngfaes': '99.9'}, 'below the uniform'),
                         ({'ratio:verify:stream_uniform:32:tuned:32:Ip:sw': '0.99'}, 'slower than its uniform'),
                         ({'iss:verify:tuned:32:Ip:sw:sum': 1001}, 'tuned kernel is slower'),
                         ({'iss:verify:stream_uniform:32:Ip:bngfaes:sum': 30}, 'product of the single'),
                         ({'spd:verify:stream_uniform:32:Ip:bngfaes': '35.7'}, 'product of the single'),       # shown 2.5 x 14.3 = 35.75
                         ({'iss:verify:stream_uniform:32:Ip:bnaesonly:sum': 500}, 'bn.aes128 alone does not gain'),
                         ({'mem:sign:ldirect:32:Ip:bngfaes:bss': 32769}, 'does not fit 32 KiB'),
                         ({'mem:sign:sprec:512:Ip:bngfaes:bss': 131072}, 'would fit 128 KiB'),
                         ({'retrygrid:Ip:ratio': '0.98'}, 'not slower than ldirect on average'),
                         ({'retrygrid:Is:keys': 3}, 'different numbers of retry-grid keys'),
                         ({'retrygrid:ldirect:Ip:32:step': 800}, 'less than 90 %'),
                         ({'retrygrid:sprec:Ip:32:0:cyc': 900}, 'sprec is not slower without a retry'),
                         ({'retrygrid:sprec:Ip:32:step': 1000}, 'sprec is not slower without a retry'),
                         ({'ct:Ip:bngfaes:whole': 2}, 'traces differ although'), ({'ct:Ip:sw:whole': 1}, 'no longer gives traces'),
                         ({'iss:keygen:sp:128:Ip:bngfaes:sum': 220}, 'sp is not faster than min'),
                         ({'mem:keygen:sp:128:Ip:bngfaes:bss': 60000}, 'min does not use less memory'),
                         ({'iss:keygen:min:128:Ip:bnaesonly:sum': 6000}, 'not cheaper relative to sp')):
            with self.subTest(bad=bad), self.assertRaisesRegex(uov.Refused, why):
                uov.paper_claims({**vals, **bad})

    def test_contrib_table_reads_the_published_speedups(self):
        row = {f'spd:sign:ldirect:32:Is:{t}': '1' for t in uov.SPEEDUP_TIERS}
        row.update({f'both:sign:ldirect:32:Is:{t}': '1' for t in ('bnaesonly', 'bngfonly')})
        tab = uov.contrib_table(row)['tab-contrib.tex']
        self.assertIn('sign & uov-Is & \\Var{spd:sign:ldirect:32:Is:bngfonly}$\\times$ & ', tab)
        self.assertIn('\\Var{both:sign:ldirect:32:Is:bnaesonly}$\\times$ & \\Var{both:sign:ldirect:32:Is:bngfonly}$\\times$ \\\\\n', tab)
        self.assertEqual(uov.contrib_table({}), {})
        part = uov.contrib_table({k: v for k, v in row.items() if 'bnaesonly' not in k})['tab-contrib.tex']
        self.assertIn('sign & uov-Is & \\Var{spd:sign:ldirect:32:Is:bngfonly}$\\times$ & -- & ', part)      # a missing number shows --
        self.assertIn('keygen & uov-Ip-r2 & -- & -- & -- & -- & -- \\\\\n', part)                               # every row is there
        self.assertIn('keygen & uov-Ip & -- & -- & -- & -- & -- \\\\\n', part)                                  # Ip3: the Round-3 set has the plain name


class MemUsage(unittest.TestCase):
    def test_regions(self):
        syms = {'ctrl': (0, 'linked'), 'slice': (32, 'linked'), 'slice_end': (96, 'linked'), 'o': (96, 'linked'),
                'stack': (128, 'linked'), 'L': (160, 'linked'), 'stack_end': (256, 'linked'), 'msg': (256, 'linked'),
                'p2buf': (31744, 'abs'), 'ivb': (32512, 'abs')}
        got = uov.mem_regions(syms, 320)
        self.assertEqual(got, [('ctrl', 'fixed', 0, 32), ('slice', 'stream', 32, 96), ('o', 'fixed', 96, 128),
                               ('stack', 'fixed', 128, 256),        # the labels inside the stack block are dropped
                               ('msg', 'msg', 256, 320),             # the last linked region ends at _dmem_bss_end
                               ('p2buf', 'stream', 31744, 32512), ('ivb', 'fixed', 32512, 32768)])
        with self.assertRaises(uov.Refused):
            uov.mem_regions({'a': (0, 'linked'), 'b': (0, 'linked')}, 32)

    def test_borrowed(self):
        got = uov.borrowed_regions([('ctrl', 'fixed', 0, 32), ('msgwin', 'stream', 32, 900), ('caprows', 'fixed', 900, 1000)])
        self.assertEqual(got, [('ctrl', 'fixed', 0, 32), ('msgwin', 'stream', 32, 31744), ('scratch', 'fixed', 31744, 32768)])

    def test_cell_split(self):
        regions = [('ctrl', 'fixed', 0, 32), ('slice', 'stream', 32, 128), ('msg', 'msg', 128, 192)]
        obs = {'read': [[0, 3], [40, 70], [130, 130]], 'written': [[64, 64]]}
        with mock.patch.object(uov, 'elf_dmem', return_value=(100, 192, {})), \
             mock.patch.object(uov, 'elf_facts', return_value={'entry': 0, 'segments': []}):
            row, reg = uov.mem_usage_cell('x.elf', obs, regions)
        self.assertEqual((row['dmem'], row['dmem_fixed'], row['dmem_stream'], row['msg'], row['touched']), (96, 32, 64, 64, 128))
        self.assertEqual([(r['region'], r['touched'], r['touched_bytes']) for r in reg], [('ctrl', 32, 4), ('slice', 64, 31), ('msg', 32, 1)])
        with mock.patch.object(uov, 'elf_dmem', return_value=(100, 192, {})):
            with self.assertRaises(uov.Refused):                    # a touched byte outside every region
                uov.mem_usage_cell('x.elf', {'read': [[500, 500]], 'written': []}, regions)


if __name__ == '__main__':
    unittest.main()

"""Schema portability tests plus real Linux native checks (no synthetic leak claim)."""
import csv
import ctypes as ct
import gzip
import io
import json
import os
from pathlib import Path
import platform
import random
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from experiment_schema import LINUX, WINDOWS, schema_for
from recovery import Budget, Sampler, raw_columns
from research_pipeline import (digest, export, load_manifest, manifest_schema, save,
                               schema_metadata, sources, train)
from splits import make_secrets
from timing_model import features

ROOT = Path(__file__).resolve().parent


class LinuxSchemaTests(unittest.TestCase):
    def test_linux_sampler_keeps_thread_time_units_and_counts_excluded_batches(self):
        calls = 0
        def measure(guess, batch):
            nonlocal calls
            calls += 1
            # Exclude the first batch by migration, but keep and charge it.
            return SimpleNamespace(wall_ns=100, tsc_ticks=200, thread_cpu_ns=80,
                                   aux_start=0, aux_end=int(calls == 1))
        stream = io.StringIO()
        config = {'measurement_backend': LINUX, 'warmup': 0, 'batch': 10}
        budget = Budget(measure, lambda g: False, 1000, 1)
        sampler = Sampler(budget, b'ab', b'', 4, 'naive', config, random.Random(7),
                          csv.writer(stream), ['id', 'train', 's', 'correct', 'naive', 'calibration'])
        result = sampler.extend(4)
        self.assertEqual(result['usable_samples'], [3, 4] if sampler.rounds[0][0] is None else [4, 3])
        self.assertEqual(budget.timed_calls, 80)
        self.assertEqual(len(list(csv.reader(io.StringIO(stream.getvalue())))), 8)
        self.assertEqual(raw_columns(config)[14], 'thread_cpu_ns_total')
        self.assertEqual(raw_columns({})[14], 'thread_cycles_total')
        self.assertEqual(len(result['features'][0]), 42)

    def test_schemas_reject_silent_cycle_to_nanosecond_relabeling(self):
        schema = schema_for(LINUX)
        manifest = {**schema_metadata(schema), 'config': {'measurement_backend': LINUX}}
        self.assertEqual(manifest_schema(manifest), schema)
        for key, value in (('feature_names', schema_for(WINDOWS)['feature_names']),
                           ('schema_version', 2), ('feature_version', 2),
                           ('metric_units', schema_for(WINDOWS)['metric_units'])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                manifest_schema({**manifest, key: value})
        legacy = {**schema_metadata(schema_for(WINDOWS)), 'config': {}}
        legacy.pop('measurement_backend')
        self.assertEqual(manifest_schema(legacy)['measurement_backend'], WINDOWS)

    def test_fingerprints_select_only_the_active_native_backend(self):
        with patch('research_pipeline.digest', side_effect=lambda path: path.name):
            linux = sources(LINUX)
            windows = sources(WINDOWS)
        self.assertIn('native_linux.so', linux)
        self.assertIn('native_linux.build.json', linux)
        self.assertNotIn('native_windows.dll', linux)
        self.assertIn('native_windows.dll', windows)
        self.assertNotIn('native_linux.so', windows)

    def test_linux_training_and_export_are_portable_and_never_open_test_features(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.test-research-') as temporary:
            dataset = Path(temporary)
            schema = schema_for(LINUX)
            entries = make_secrets(9, 'ab01', 4, 4, 7)
            config = {'measurement_backend': LINUX, 'checker': 'naive', 'alphabet': 'ab01',
                      'sessions': 1, 'min_samples': 4, 'max_samples': 4, 'checkpoints': [4]}
            manifest = {**schema_metadata(schema), 'complete': True, 'config': config,
                        'passwords': entries, 'shards': {}}
            for entry in entries:
                path = dataset / f'{entry["secret_id"]}.jsonl.gz'
                session = entry['split'] + '-r0'
                shard = {'secret_id': entry['secret_id'], 'split': entry['split'], 'session_id': session,
                         'features': path.name, 'groups': 0, 'features_sha256': 'unread-test-shard'}
                if entry['split'] != 'test':
                    with gzip.open(path, 'wt', encoding='utf-8') as stream:
                        for position in range(4):
                            for valid in ([True] if position == 0 else [True, False]):
                                target = 'ab01'.index(entry['secret'][position])
                                rounds = [[{m: 10 + 20 * int(valid and i == target)
                                            for m in schema['metrics']} for i in range(4)] for _ in range(4)]
                                group = features(rounds, position == 3, position / 4, schema['metrics'])
                                prefix = entry['secret'][:position]
                                if not valid:
                                    prefix = ('b' if prefix[0] == 'a' else 'a') + prefix[1:]
                                group.update(secret_id=entry['secret_id'], split=entry['split'], session_id=session,
                                             length=4, position=position, prefix_hex=prefix.encode().hex(),
                                             prefix_valid=valid, prefix_kind='correct' if valid else 'wrong0',
                                             target=target if valid else None, last=position == 3)
                                stream.write(json.dumps(group) + '\n')
                                shard['groups'] += 1
                    shard['features_sha256'] = digest(path)
                manifest['shards'][f'{entry["secret_id"]}-r0'] = shard
            save(dataset / 'manifest.json', manifest)
            with patch('builtins.print'):
                train(SimpleNamespace(dataset=str(dataset), output=str(dataset / 'model.json'), epochs=2, seed=7))
            model = json.loads((dataset / 'model.json').read_text())
            self.assertEqual(model['schema_version'], 3)
            self.assertIn('thread_cpu_ns_q50', model['feature_names'])
            self.assertFalse(model['test_used_for_selection'])
            self.assertFalse({p['secret_id'] for p in entries if p['split'] == 'test'} &
                             set(model['train_password_ids'] + model['validation_password_ids']))
            # Export needs all feature shards; materialize a matching empty test shard only now.
            for shard in manifest['shards'].values():
                if shard['split'] == 'test':
                    with gzip.open(dataset / shard['features'], 'wt'):
                        pass
                    shard['features_sha256'] = digest(dataset / shard['features'])
            save(dataset / 'manifest.json', manifest)
            with patch('builtins.print'):
                export(SimpleNamespace(dataset=str(dataset), output=str(dataset / 'bundle.zip')))
            with zipfile.ZipFile(dataset / 'bundle.zip') as archive:
                self.assertIn('experiment_schema.py', archive.namelist())
                self.assertIn('feature_ablation.py', archive.namelist())
                self.assertFalse(any(n.endswith(('.so', '.dll', '.c')) or '/raw/' in n
                                     for n in archive.namelist()))


@unittest.skipUnless(sys.platform == 'linux' and platform.machine() == 'x86_64' and
                     (ROOT / 'native_linux.so').exists(), 'requires Linux x86-64 and built .so')
class NativeLinuxTests(unittest.TestCase):
    def test_all_lengths_mismatch_positions_and_timer_channels(self):
        from native_attack import NativeLab
        for length in range(4, 17):
            secret = b'a0z9b1y8c2x7d3w6'[:length]
            lab = NativeLab(secret)
            try:
                for mode in (0, 1):
                    self.assertTrue(lab.check(secret, mode))
                    for position in range(length):
                        guess = secret[:position] + b'!' + secret[position + 1:]
                        self.assertFalse(lab.check(guess, mode), (length, mode, position))
                    for guess in (b'', secret[:-1], secret + b'a'):
                        self.assertFalse(lab.check(guess, mode))
                for mode in (0, 1, 2):
                    reading = lab.measure(secret, mode, 1000)
                    self.assertGreater(reading.wall_ns, 0)
                    self.assertGreater(reading.tsc_ticks, 0)
                    self.assertGreater(reading.thread_cpu_ns, 0)
                    self.assertFalse(hasattr(reading, 'thread_cycles'))
            finally:
                lab.close()

    def test_affinity_is_restored_after_success_and_invalid_cpu(self):
        from native_attack import NativeLab
        original = os.sched_getaffinity(0)
        lab = NativeLab(b'ab01', cpu=min(original))
        try:
            self.assertEqual(os.sched_getaffinity(0), {min(original)})
        finally:
            lab.close()
        self.assertEqual(os.sched_getaffinity(0), original)
        invalid = next(i for i in range(1025) if i not in original)
        with self.assertRaisesRegex(RuntimeError, '5=affinity'):
            NativeLab(b'ab01', cpu=invalid)
        self.assertEqual(os.sched_getaffinity(0), original)

    def test_reject_amplification_modes_and_invalid_batches_without_closing_active_lab(self):
        from native_attack import NativeLab
        with self.assertRaises(ValueError):
            NativeLab(b'ab01', work=1)
        lab = NativeLab(b'ab01')
        try:
            for batch in (0, -1, 1000001, 2 ** 32):
                with self.assertRaises(ValueError):
                    lab.measure(b'ab01', 0, batch)
            for mode in (3, 4, 5, 6, -1):
                with self.assertRaises(ValueError):
                    lab.measure(b'ab01', mode, 1)
                with self.assertRaises(ValueError):
                    lab.check(b'ab01', mode)
            with self.assertRaises(RuntimeError):
                NativeLab(b'zz99')
            self.assertTrue(lab.check(b'ab01', 0))
        finally:
            lab.close()
        with self.assertRaises(RuntimeError):
            lab.measure(b'ab01', 0, 1)
        # The C entrypoint also rejects amplification, bypassing Python validation.
        self.assertEqual(lab.dll.lab_init(b'ab01', 4, 1, -1), 8)


if __name__ == '__main__':
    unittest.main()

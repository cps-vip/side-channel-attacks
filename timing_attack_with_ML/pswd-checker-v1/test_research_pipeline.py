import csv
import io
import gzip
import json
import random
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from research_pipeline import audit_manifest, digest, make_secrets, recover_blind, save_json, train
from timing_model import FEATURE_NAMES, FEATURE_VERSION, choose, fit, make_features, summarize


def example_group(target, last=False):
    distributions = []
    for index in range(4):
        # Ground truth is deliberately not always at the same alphabet index.
        base = 20 if index == target else 10
        distributions.append({metric: [base + jitter for jitter in (-.2, 0, .1, .2)]
                              for metric in ('tsc_ticks', 'wall_ns', 'thread_cycles')})
    features, medians = make_features(distributions, last)
    return {'features': features, 'median_tsc': medians, 'target': target,
            'secret_id': f's{target}', 'length': 4, 'position': 3 if last else 0}


class ResearchTests(unittest.TestCase):
    def test_checkpoint_retries_transient_windows_lock(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent,
                                         prefix='.test-research-') as temporary:
            path = Path(temporary) / 'checkpoint.json'
            original_replace = Path.replace
            attempts = []
            def replace(source, target):
                attempts.append(1)
                if len(attempts) < 3:
                    raise PermissionError('simulated transient file lock')
                return original_replace(source, target)
            with patch.object(Path, 'replace', replace), patch('research_pipeline.time.sleep'):
                save_json(path, {'complete': True})
            self.assertEqual(len(attempts), 3)
            self.assertEqual(json.loads(path.read_text()), {'complete': True})

    def test_training_does_not_open_held_out_test_features(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent,
                                         prefix='.test-research-') as temporary:
            dataset = Path(temporary)
            entries = make_secrets(9, 'abcd', 4, 4, 7)
            manifest = {'passwords': entries, 'complete': True, 'source_sha256': {},
                        'feature_names': FEATURE_NAMES, 'feature_version': FEATURE_VERSION,
                        'config': {'sessions': 1, 'alphabet': 'abcd'}, 'shards': {}}
            for entry in entries:
                path = dataset / f'{entry["secret_id"]}.jsonl.gz'
                session_id = f'{entry["split"]}-r0'
                shard = {'split': entry['split'], 'features': path.name,
                         'session_id': session_id, 'features_sha256': 'intentionally_missing_test_file'}
                if entry['split'] != 'test':
                    with gzip.open(path, 'wt') as stream:
                        for position, character in enumerate(entry['secret']):
                            group = example_group('abcd'.index(character), position == 3)
                            group.update(secret_id=entry['secret_id'], split=entry['split'],
                                         session_id=session_id, position=position)
                            stream.write(json.dumps(group) + '\n')
                    shard['features_sha256'] = digest(path)
                manifest['shards'][f'{entry["secret_id"]}-r0'] = shard
            (dataset / 'manifest.json').write_text(json.dumps(manifest))
            output = dataset / 'model.json'
            with patch('builtins.print'):
                train(SimpleNamespace(dataset=str(dataset), output=str(output), epochs=2, seed=7))
            model = json.loads(output.read_text())
            self.assertFalse(model['test_used_for_selection'])
            test_ids = {e['secret_id'] for e in entries if e['split'] == 'test'}
            self.assertFalse(test_ids & set(model['train_password_ids']))
            self.assertFalse(test_ids & set(model['validation_password_ids']))

    def test_password_stratification_and_disjoint_splits(self):
        entries = make_secrets(260, 'abcdefghijklmnopqrstuvwxyz0123456789', 4, 16, 7)
        audit_manifest({'passwords': entries})
        self.assertEqual(entries, make_secrets(260, 'abcdefghijklmnopqrstuvwxyz0123456789', 4, 16, 7))
        self.assertEqual(len({p['secret'] for p in entries}), 260)
        self.assertEqual({s: sum(p['split'] == s for p in entries)
                          for s in ('train', 'validation', 'test')},
                         {'train': 182, 'validation': 39, 'test': 39})
        for length in range(4, 17):
            self.assertEqual({p['split'] for p in entries if p['length'] == length},
                             {'train', 'validation', 'test'})
        with self.assertRaises(ValueError):
            make_secrets(3, 'abcd', 4, 16, 7)

    def test_model_learns_timing_signal_at_any_candidate_index(self):
        groups = [example_group(i, last) for _ in range(3) for last in (False, True) for i in range(4)]
        weights = fit(groups, epochs=15)
        for i in range(4):
            for last in (False, True):
                group = example_group(i, last)
                self.assertEqual(choose(weights, group['features']), i)
        self.assertEqual(summarize(groups, weights)['buckets']['all']['model_accuracy'], 1.0)
        self.assertEqual(len(weights), len(FEATURE_NAMES))

    def test_equal_timings_cannot_distinguish_candidates(self):
        distributions = [{m: [10, 10, 10] for m in ('tsc_ticks', 'wall_ns', 'thread_cycles')}
                         for _ in range(36)]
        features, _ = make_features(distributions, False)
        self.assertTrue(all(row == [0.0] * len(FEATURE_NAMES) for row in features))
        with self.assertRaises(ValueError):
            make_features([{'tsc_ticks': [], 'wall_ns': [], 'thread_cycles': []}], False)

    def test_blind_recovery_only_uses_oracle_measurements(self):
        secret = b'b1ab'
        alphabet = b'ab01'
        def oracle(guess, batch):
            matched = 0
            for a, b in zip(guess, secret):
                if a != b:
                    break
                matched += 1
            value = (10 + matched * 10) * batch
            return SimpleNamespace(tsc_ticks=value, wall_ns=value,
                                   thread_cycles=value, aux_start=0, aux_end=0)
        weights = fit([example_group(i, last) for i in range(4) for last in (False, True)], epochs=15)
        for method in ('model', 'median'):
            guess, _ = recover_blind(oracle, alphabet, 4,
                                     {'samples': 3, 'batch': 2, 'warmup': 0},
                                     weights, method, random.Random(1),
                                     csv.writer(io.StringIO()), ['id', 'test', 's', 'blind', 'vulnerable', method])
            self.assertEqual(guess, secret)


if __name__ == '__main__':
    unittest.main()

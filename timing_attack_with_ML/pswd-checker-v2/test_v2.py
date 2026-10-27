import ast
import csv
import gzip
import io
import json
from pathlib import Path
import random
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recovery import (ABLATIONS, Budget, BudgetExhausted, RAW_COLUMNS, Sampler,
                      default_timing_budget, recover, units)
from research_pipeline import checkpoints, digest, load_groups, load_manifest, save, train
from splits import make_secrets
from timing_model import (DETECTOR_NAMES, FEATURE_NAMES, FEATURE_VERSION, choose_detector_threshold,
                          detector_metrics, features, fit, prefix_score, rank)
from feature_ablation import BASIC_INDICES, train_basic

ROOT = Path(__file__).resolve().parent


def readings(count=4, target=1, valid=True, rounds=8):
    result = []
    for sample in range(rounds):
        row = []
        for i in range(count):
            value = 10 + (20 if valid and i == target else 0) + (sample % 3) * .1
            row.append({metric: value for metric in ('tsc_ticks', 'wall_ns', 'thread_cycles')})
        result.append(row)
    return result


def training_group(target, valid=True, last=False):
    g = features(readings(target=target, valid=valid), last, .5)
    g.update(target=target if valid else None, prefix_valid=valid, last=last,
             secret_id=f'id{target}', session_id='train-r0', position=2, length=4)
    return g


def model_fixture():
    # Highest TSC median scores highest; detector has a hand-specified peak rule.
    weights = [0.0] * len(FEATURE_NAMES)
    weights[1] = 1.0
    detector = [-3.0] + [0.0] * len(DETECTOR_NAMES)
    detector[1] = 1.0
    return {'weights': weights, 'detector_weights': detector,
            'detector_threshold': .5, 'sampling_thresholds': {'model': .5, 'median': .5}}


def fake_oracle(secret):
    def measure(guess, batch):
        matched = 0
        for actual, expected in zip(guess, secret):
            if actual != expected:
                break
            matched += 1
        value = (10 + 20 * matched) * batch
        return SimpleNamespace(wall_ns=value, tsc_ticks=value, thread_cycles=value,
                               aux_start=0, aux_end=0)
    return measure, lambda guess: guess == secret


class V2Tests(unittest.TestCase):
    def config(self):
        return {'batch': 2, 'warmup': 0, 'min_samples': 4, 'max_samples': 8,
                'checkpoints': [4, 8], 'beam_width': 3, 'reserve_size': 32}

    def test_split_excludes_previously_seen_passwords(self):
        a = make_secrets(60, 'ab01', 4, 5, 7)
        b = make_secrets(60, 'ab01', 4, 5, 7, {p['secret'] for p in a})
        self.assertFalse({p['secret'] for p in a} & {p['secret'] for p in b})
        self.assertEqual({p['split'] for p in b}, {'train', 'validation', 'test'})

    def test_chunk_candidates_and_checkpoint_validation(self):
        self.assertEqual(len(units(b'ab01', 4, 0, 'staged')), 16)
        self.assertEqual(len(units(b'ab01', 5, 4, 'staged')), 4)
        self.assertEqual(checkpoints(6, 24), [6, 12, 24])
        with self.assertRaises(ValueError):
            checkpoints(2, 8)

    def test_feature_schema_and_no_signal(self):
        positive = features(readings(), False, .5)
        negative = features(readings(valid=False), False, .5)
        self.assertEqual(len(positive['features'][0]), 42)
        self.assertEqual(len(positive['detector_features']), 14)
        self.assertEqual(positive['stable_tsc_winner'], 1)
        self.assertTrue(all(row == [0.0] * 42 for row in negative['features']))
        with self.assertRaises(ValueError):
            features([[None] * 4] * 4, False, .5)

    def test_ranker_and_detector_learn_without_character_identity(self):
        groups = [training_group(i, valid, last) for i in range(4)
                  for valid in (True, False) for last in (True, False)]
        positives = [g for g in groups if g['prefix_valid']]
        model = {'weights': fit(positives, .001, 15, 7),
                 'detector_weights': fit(groups, .001, 30, 7, detector=True)}
        for i in range(4):
            self.assertEqual(rank(training_group(i), model, 'model')[0][0], i)
        threshold, metrics = choose_detector_threshold(groups, model)
        self.assertLessEqual(metrics['false_rejection_rate'], .02)
        self.assertGreater(metrics['wrong_prefix_detection_rate'], .9)
        self.assertGreater(prefix_score(training_group(0), model), threshold)

    def test_basic_feature_mask_preserves_exactly_18_quantile_features(self):
        self.assertEqual(len(BASIC_INDICES), 18)
        group = training_group(1)
        masked = {**group, 'features': [[v if i in BASIC_INDICES else 0.0
                                       for i, v in enumerate(row)] for row in group['features']]}
        weights = fit([masked], .001, 3, 7)
        self.assertTrue(all(weights[i] == 0 for i in range(len(weights)) if i not in BASIC_INDICES))

    def test_budget_is_hard_and_counts_warmup_and_verification(self):
        measure, check = fake_oracle(b'ab01')
        budget = Budget(measure, check, 10, 1)
        budget.measure(b'ab01', 4, warmup=True)
        budget.measure(b'ab01', 6)
        with self.assertRaises(BudgetExhausted):
            budget.measure(b'ab01', 1)
        self.assertTrue(budget.check(b'ab01'))
        with self.assertRaises(BudgetExhausted):
            budget.check(b'ab01')
        self.assertEqual(budget.counts()['total_checker_calls'], 11)

    def test_every_ablation_recovers_on_clean_synthetic_oracle(self):
        config, alphabet, secret = self.config(), b'ab01', b'b1ab'
        for ablation in ABLATIONS:
            for method in ('model', 'median'):
                measure, check = fake_oracle(secret)
                budget = Budget(measure, check, 5000, 100)
                result = recover(budget, alphabet, 4, 'naive', config, model_fixture(), method,
                                 ablation, random.Random(7), csv.writer(io.StringIO()),
                                 ['id', 'test', 's', 'blind', 'naive', method])
                self.assertTrue(result['success'], (method, ablation, result))
                self.assertEqual(result['guess'], secret.decode())
                self.assertLessEqual(result['total_checker_calls'], 5100)

    def test_adaptive_sampler_saves_calls_and_final_verification_is_logged(self):
        config, alphabet = self.config(), b'ab01'
        counts = {}
        for ablation in ('verify', 'adaptive'):
            measure, check = fake_oracle(b'b1ab')
            stream = io.StringIO()
            result = recover(Budget(measure, check, 10000, 20), alphabet, 4, 'naive', config,
                             model_fixture(), 'model', ablation, random.Random(7),
                             csv.writer(io.StringIO()), ['id', 'test', 's', 'blind', 'naive', 'm'],
                             csv.writer(stream))
            self.assertTrue(result['success'])
            self.assertEqual(len(stream.getvalue().splitlines()), result['verification_calls'])
            counts[ablation] = result['timed_checker_calls']
        self.assertLess(counts['adaptive'], counts['verify'])

    def test_budget_exhaustion_reports_failure_without_overrun(self):
        measure, check = fake_oracle(b'b1ab')
        result = recover(Budget(measure, check, 5, 1), b'ab01', 4, 'naive', self.config(),
                         model_fixture(), 'model', 'full', random.Random(7), csv.writer(io.StringIO()),
                         ['id', 'test', 's', 'blind', 'naive', 'm'])
        self.assertFalse(result['success'])
        self.assertIn('budget exhausted', result['status'])
        self.assertLessEqual(result['total_checker_calls'], 6)

    def test_wrong_prefix_pruning_keeps_an_alternative_path(self):
        secret = b'b1ab'
        original, check = fake_oracle(secret)
        # At the first position only, make an incorrect candidate look slightly better.
        def measure(guess, batch):
            if guess[1:] == b'\x00\x00\x00' and guess[0:1] == b'a':
                return SimpleNamespace(wall_ns=31 * batch, tsc_ticks=31 * batch,
                                       thread_cycles=31 * batch, aux_start=0, aux_end=0)
            return original(guess, batch)
        result = recover(Budget(measure, check, 10000, 100), b'ab01', 4, 'naive', self.config(),
                         model_fixture(), 'model', 'full', random.Random(7),
                         csv.writer(io.StringIO()), ['id', 'test', 's', 'blind', 'naive', 'm'])
        self.assertTrue(result['success'])
        self.assertGreaterEqual(result['detector_rejections'], 1)

    def test_early_wrong_prefix_rejection_saves_measurement_budget(self):
        secret = b'b1ab'
        original, check = fake_oracle(secret)
        def measure(guess, batch):
            if guess[1:] == b'\x00\x00\x00' and guess[0:1] == b'a':
                return SimpleNamespace(wall_ns=31 * batch, tsc_ticks=31 * batch,
                                       thread_cycles=31 * batch, aux_start=0, aux_end=0)
            return original(guess, batch)
        calls = {}
        for ablation in ('beam', 'full'):
            result = recover(Budget(measure, check, 10000, 100), b'ab01', 4, 'naive',
                             self.config(), model_fixture(), 'model', ablation,
                             random.Random(7), csv.writer(io.StringIO()),
                             ['id', 'test', 's', 'blind', 'naive', 'm'])
            self.assertTrue(result['success'])
            calls[ablation] = result['timed_checker_calls']
        self.assertLess(calls['full'], calls['beam'])

    def test_beam_backtracks_to_a_deferred_alternative(self):
        config = self.config()
        config['beam_width'] = 2
        class ScriptedSampler:
            def __init__(self, budget, alphabet, prefix, *args):
                self.prefix, self.budget = prefix, budget
            def extend(self, count):
                self.budget.measure(b'ab01', 1)
                g = training_group(0)
                values = ({b'': [.1, 0, -10, -10], b'a': [10, 9.9, -10, -10],
                           b'b': [0, 0, 0, .1], b'b1': [10, 0, 0, 0]}
                          .get(self.prefix, [0, 0, 0, 0]))
                g['features'] = [[0.0] * len(FEATURE_NAMES) for _ in range(4)]
                for row, value in zip(g['features'], values):
                    row[1] = value
                g.update(stable_tsc_winner=None, samples=count)
                return g
        measure, check = fake_oracle(b'b1ab')
        with patch('recovery.Sampler', ScriptedSampler):
            result = recover(Budget(measure, check, 10000, 1000), b'ab01', 4, 'naive', config,
                             model_fixture(), 'model', 'beam', random.Random(7),
                             csv.writer(io.StringIO()), ['id', 'test', 's', 'blind', 'naive', 'm'])
        self.assertTrue(result['success'], result)
        self.assertGreater(result['backtracks'], 0)

    def test_training_never_reads_test_features(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.test-research-') as temporary:
            dataset = Path(temporary)
            entries = make_secrets(9, 'ab01', 4, 4, 7)
            config = {'checker': 'naive', 'alphabet': 'ab01', 'sessions': 1,
                      'min_samples': 4, 'max_samples': 8, 'checkpoints': [4, 8]}
            manifest = {'schema_version': 2, 'complete': True, 'feature_names': FEATURE_NAMES,
                        'detector_names': DETECTOR_NAMES, 'config': config,
                        'passwords': entries, 'shards': {}}
            for entry in entries:
                path = dataset / f'{entry["secret_id"]}.jsonl.gz'
                session = f'{entry["split"]}-r0'
                shard = {'secret_id': entry['secret_id'], 'split': entry['split'],
                         'session_id': session, 'features': path.name,
                         'features_sha256': 'deliberately missing test file', 'groups': 0}
                if entry['split'] != 'test':
                    with gzip.open(path, 'wt', encoding='utf-8') as stream:
                        for position in range(4):
                            for valid in ([True] if not position else [True, False]):
                                for sample_count in (4, 8):
                                    target = 'ab01'.index(entry['secret'][position])
                                    group = features(readings(target=target, valid=valid, rounds=sample_count), position == 3, position / 4)
                                    prefix = entry['secret'][:position]
                                    if not valid:
                                        prefix = ('b' if prefix[0] == 'a' else 'a') + prefix[1:]
                                    group.update(secret_id=entry['secret_id'], split=entry['split'],
                                                 session_id=session, length=4, position=position,
                                                 prefix_hex=prefix.encode().hex(), prefix_valid=valid,
                                                 prefix_kind='correct' if valid else 'wrong0',
                                                 target=target if valid else None, last=position == 3)
                                    stream.write(json.dumps(group) + '\n')
                                    shard['groups'] += 1
                    shard['features_sha256'] = digest(path)
                manifest['shards'][f'{entry["secret_id"]}-r0'] = shard
            save(dataset / 'manifest.json', manifest)
            with patch('builtins.print'):
                train(SimpleNamespace(dataset=str(dataset), output=str(dataset / 'model.json'), epochs=2, seed=7))
            model = json.loads((dataset / 'model.json').read_text())
            self.assertFalse(model['test_used_for_selection'])
            test_ids = {e['secret_id'] for e in entries if e['split'] == 'test'}
            self.assertFalse(test_ids & set(model['train_password_ids']))
            with patch('builtins.print'):
                train_basic(dataset, dataset / 'model.json', str(dataset / 'basic.json'), epochs=2)
            basic = json.loads((dataset / 'basic.json').read_text())
            self.assertEqual(basic['detector_weights'], model['detector_weights'])
            self.assertEqual(len(basic['feature_ablation']['active_features']), 18)


@unittest.skipUnless(sys.platform == 'win32' and (ROOT / 'native_windows.dll').exists(),
                     'requires Windows and built v2 DLL')
class NativeV2Tests(unittest.TestCase):
    def test_all_variants_accept_only_exact_match_across_lengths(self):
        from native_attack import NativeLab
        for length in range(4, 17):
            secret = b'a0z9b1y8c2x7d3w6'[:length]
            lab = NativeLab(secret)
            try:
                for mode in (0, 1, 3, 4, 5, 6):
                    self.assertTrue(lab.check(secret, mode), (length, mode))
                    for candidate in (secret[:-1], b'!' + secret[1:], b'b' + secret[1:]):
                        self.assertFalse(lab.check(candidate, mode), (length, mode, candidate))
                    reading = lab.measure(secret, mode, 5)
                    self.assertGreater(reading.wall_ns, 0)
                    self.assertGreater(reading.tsc_ticks, 0)
            finally:
                lab.close()


if __name__ == '__main__':
    unittest.main()

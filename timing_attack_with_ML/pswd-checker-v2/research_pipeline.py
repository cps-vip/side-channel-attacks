"""V2: local synthetic timing collection, supervised training and budgeted ablations."""
import argparse
from array import array
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import statistics
import time
import zipfile

from lab_config import DEFAULT_ALPHABET, validate_alphabet
from recovery import (ABLATIONS, CHECKERS, RAW_COLUMNS, Budget, Sampler,
                      default_timing_budget, positions, recover, units, write_reading)
from splits import audit_manifest, make_secrets
from timing_model import (DETECTOR_NAMES, FEATURE_NAMES, FEATURE_VERSION, character_metrics,
                          choose_detector_threshold, choose_sampling_threshold,
                          detector_metrics, fit)

ROOT = Path(__file__).resolve().parent
CORE_FILES = ('lab_config.py', 'native_attack.py', 'native_windows.c', 'native_windows.dll',
              'recovery.py', 'timing_model.py', 'splits.py', 'research_pipeline.py')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def sources():
    return {name: digest(ROOT / name) for name in CORE_FILES}


def replace(source, target):
    for attempt in range(7):
        try:
            source.replace(target)
            return
        except PermissionError:
            if attempt == 6:
                raise
            time.sleep(.05 * 2 ** attempt)


def save(path, data):
    temporary = path.with_suffix(path.suffix + '.tmp')
    payload = json.dumps(data, indent=2, allow_nan=False)
    for attempt in range(7):
        try:
            temporary.write_text(payload, encoding='utf-8')
            replace(temporary, path)
            return
        except PermissionError:
            if attempt == 6:
                raise
            time.sleep(.05 * 2 ** attempt)


def output_path(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('output must stay inside pswd-checker-v2')
    return path


def checkpoints(minimum, maximum):
    if minimum < 4 or maximum < minimum:
        raise ValueError('require 4 <= min-samples <= max-samples')
    result, count = [], minimum
    while count < maximum:
        result.append(count)
        count *= 2
    return sorted(set(result + [maximum]))


def exclusions(extra):
    """Only explicit dataset manifests are opened; never environment files."""
    paths = list((ROOT.parent / 'pswd-checker-v1' / 'datasets').glob('*/manifest.json'))
    paths += list((ROOT / 'datasets').glob('*/manifest.json'))
    paths += [Path(p).resolve() / 'manifest.json' for p in extra]
    seen, records = set(), []
    for path in sorted(set(paths)):
        data = json.loads(path.read_text(encoding='utf-8'))
        seen.update(p['secret'] for p in data['passwords'])
        records.append({'path': str(path), 'sha256': digest(path)})
    return seen, records


def collect(args):
    from native_attack import NativeLab
    alphabet = args.alphabet.encode('ascii')
    validate_alphabet(alphabet)
    if not 4 <= args.min_length <= args.max_length <= 16:
        raise ValueError('lengths must stay within 4–16')
    if (args.sessions < 1 or args.warmup < 0 or args.negative_prefixes < 1 or args.cpu < -1):
        raise ValueError('invalid collection settings')
    batch = args.batch if args.batch is not None else (1 if args.checker == 'staged' else 1000)
    if not 1 <= batch <= 1000000:
        raise ValueError('batch must be 1–1000000')
    config = {k: getattr(args, k) for k in ('checker', 'passwords', 'alphabet', 'min_length',
              'max_length', 'sessions', 'min_samples', 'max_samples', 'warmup',
              'negative_prefixes', 'cpu', 'seed', 'exclude_dataset')}
    config.update(batch=batch, checkpoints=checkpoints(args.min_samples, args.max_samples), work=0)
    output = output_path(args.output)
    source_hashes = sources()
    if args.resume:
        manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
        if manifest['config'] != config or manifest['source_sha256'] != source_hashes:
            raise ValueError('resume requires identical settings and source/DLL hashes')
    else:
        if output.exists():
            raise ValueError('dataset already exists; use --resume or a fresh output name')
        excluded, excluded_sources = exclusions(args.exclude_dataset)
        passwords = make_secrets(args.passwords, args.alphabet, args.min_length,
                                 args.max_length, args.seed, excluded)
        output.mkdir(parents=True)
        manifest = {'schema_version': 2, 'feature_version': FEATURE_VERSION,
                    'feature_names': FEATURE_NAMES, 'detector_names': DETECTOR_NAMES,
                    'config': config, 'passwords': passwords,
                    'excluded_manifests': excluded_sources,
                    'excluded_password_ids': sorted(hashlib.sha256(s.encode()).hexdigest()[:16] for s in excluded),
                    'source_sha256': source_hashes, 'created_utc': now(),
                    'platform': platform.platform(), 'processor': platform.processor(),
                    'python': platform.python_version(), 'notes': args.notes,
                    'shards': {}, 'complete': False}
        save(output / 'manifest.json', manifest)
    audit_manifest(manifest)
    (output / 'raw').mkdir(exist_ok=True)
    (output / 'features').mkdir(exist_ok=True)
    tasks, order_rng = [], random.Random(args.seed)
    for session in range(args.sessions):
        split_order = ['train', 'validation', 'test']
        order_rng.shuffle(split_order)
        for split in split_order:
            entries = [p for p in manifest['passwords'] if p['split'] == split]
            order_rng.shuffle(entries)
            tasks.extend((session, p) for p in entries)
    started, done = time.perf_counter(), 0
    for session, entry in tasks:
        key = f'{entry["secret_id"]}-r{session}'
        if key in manifest['shards']:
            shard = manifest['shards'][key]
            for kind in ('raw', 'features'):
                if digest(output / shard[kind]) != shard[f'{kind}_sha256']:
                    raise ValueError(f'checksum mismatch: {key}/{kind}')
            continue
        raw = output / 'raw' / f'{key}.csv.gz'
        derived = output / 'features' / f'{key}.jsonl.gz'
        raw_tmp, derived_tmp = raw.with_suffix('.partial'), derived.with_suffix('.partial')
        secret = entry['secret'].encode('ascii')
        rng = random.Random(f'{args.seed}/{key}')
        lab = NativeLab(secret, 0, args.cpu)
        mode = CHECKERS[args.checker]
        budget = Budget(lambda guess, n: lab.measure(guess, mode, n),
                        lambda guess: lab.check(guess, mode), 10 ** 18, 0)
        session_id = f'{entry["split"]}-r{session}'
        shard_started, groups = now(), 0
        try:
            with gzip.open(raw_tmp, 'wt', newline='', encoding='utf-8') as stream, \
                    gzip.open(derived_tmp, 'wt', encoding='utf-8') as feature_stream:
                writer = csv.writer(stream)
                writer.writerow(RAW_COLUMNS)
                baseline_context = [entry['secret_id'], entry['split'], session_id, 'baseline', 'empty', 'baseline']
                for i in range(20):
                    reading = lab.measure(secret, 2, batch)
                    write_reading(writer, baseline_context, b'', -1, i, -1, secret,
                                  batch, reading, 'baseline')
                for position in positions(len(secret), args.checker):
                    prefix = secret[:position]
                    prefixes = [('correct', prefix, True)]
                    if position:
                        for negative in range(args.negative_prefixes):
                            wrong = bytearray(prefix)
                            at = rng.randrange(len(wrong))
                            wrong[at] = rng.choice([c for c in alphabet if c != wrong[at]])
                            prefixes.append((f'wrong{negative}', bytes(wrong), False))
                    rng.shuffle(prefixes)
                    for kind, measured_prefix, valid in prefixes:
                        context = [entry['secret_id'], entry['split'], session_id, kind, args.checker, 'calibration']
                        sampler = Sampler(budget, alphabet, measured_prefix, len(secret),
                                          args.checker, config, rng, writer, context)
                        for checkpoint in config['checkpoints']:
                            group = sampler.extend(checkpoint)
                            target = sampler.candidates.index(secret[position:position + len(sampler.candidates[0])]) if valid else None
                            group.update(secret_id=entry['secret_id'], split=entry['split'],
                                         session_id=session_id, length=len(secret), position=position,
                                         prefix_hex=measured_prefix.hex(), prefix_kind=kind,
                                         prefix_valid=valid, target=target,
                                         last=position + len(sampler.candidates[0]) == len(secret))
                            feature_stream.write(json.dumps(group, allow_nan=False) + '\n')
                            groups += 1
        finally:
            lab.close()
        replace(raw_tmp, raw)
        replace(derived_tmp, derived)
        manifest['shards'][key] = {'raw': raw.relative_to(output).as_posix(),
                                  'features': derived.relative_to(output).as_posix(),
                                  'raw_sha256': digest(raw), 'features_sha256': digest(derived),
                                  'secret_id': entry['secret_id'], 'split': entry['split'],
                                  'session_id': session_id, 'groups': groups,
                                  'started_utc': shard_started, 'finished_utc': now(),
                                  'calls': budget.counts(), 'baseline_checker_calls': 20 * batch}
        save(output / 'manifest.json', manifest)
        done += 1
        remaining = len(tasks) - len(manifest['shards'])
        print(f'{len(manifest["shards"])}/{len(tasks)} shards; ETA '
              f'{remaining * (time.perf_counter() - started) / done / 60:.1f} min', flush=True)
        if args.limit_shards and done >= args.limit_shards:
            break
    manifest['complete'] = len(manifest['shards']) == len(tasks)
    manifest['updated_utc'] = now()
    manifest['split_counts'] = {s: sum(p['split'] == s for p in manifest['passwords'])
                                for s in ('train', 'validation', 'test')}
    save(output / 'manifest.json', manifest)
    print('Complete:', manifest['complete'], '; password split:', manifest['split_counts'])


def load_manifest(dataset):
    manifest = json.loads((dataset / 'manifest.json').read_text(encoding='utf-8'))
    audit_manifest(manifest)
    if (manifest.get('schema_version') != 2 or not manifest['complete'] or
            manifest['feature_names'] != FEATURE_NAMES or manifest['detector_names'] != DETECTOR_NAMES):
        raise ValueError('incomplete or incompatible v2 dataset')
    expected = {f'{p["secret_id"]}-r{r}' for p in manifest['passwords']
                for r in range(manifest['config']['sessions'])}
    if expected != set(manifest['shards']):
        raise ValueError('missing or unexpected shards')
    return manifest


def load_groups(dataset, manifest, split):
    """Do not open shards from another split. Validate labels only in the harness."""
    config = manifest['config']
    entries = {p['secret_id']: p for p in manifest['passwords'] if p['split'] == split}
    alphabet = config['alphabet'].encode('ascii')
    groups = []
    for shard in manifest['shards'].values():
        if shard['split'] != split:
            continue
        path = dataset / shard['features']
        if digest(path) != shard['features_sha256']:
            raise ValueError('feature checksum mismatch')
        keys = set()
        with gzip.open(path, 'rt', encoding='utf-8') as stream:
            for line in stream:
                g = json.loads(line)
                entry = entries.get(g['secret_id'])
                if (entry is None or g['secret_id'] != shard['secret_id'] or g['split'] != split or
                        g['session_id'] != shard['session_id'] or not g['session_id'].startswith(split + '-') or
                        g['length'] != entry['length'] or g['samples'] not in config['checkpoints'] or
                        g['position'] not in positions(entry['length'], config['checker'])):
                    raise ValueError('split/session/group mismatch')
                prefix = bytes.fromhex(g['prefix_hex'])
                secret = entry['secret'].encode('ascii')
                candidates = units(alphabet, len(secret), g['position'], config['checker'])
                valid = prefix == secret[:g['position']]
                if len(prefix) != g['position'] or valid != g['prefix_valid']:
                    raise ValueError('incorrect prefix-validity label')
                target = candidates.index(secret[g['position']:g['position'] + len(candidates[0])]) if valid else None
                if target != g['target'] or len(g['features']) != len(candidates):
                    raise ValueError('incorrect rank label or candidate count')
                if (any(len(row) != len(FEATURE_NAMES) or any(not math.isfinite(v) for v in row)
                        for row in g['features']) or len(g['detector_features']) != len(DETECTOR_NAMES) or
                        any(not math.isfinite(v) for v in g['detector_features'])):
                    raise ValueError('invalid feature schema')
                key = g['position'], g['prefix_kind'], g['samples']
                if key in keys:
                    raise ValueError('duplicate snapshot')
                keys.add(key)
                # Compact numeric storage avoids Python-float overhead on large datasets.
                g['features'] = [array('f', row) for row in g['features']]
                groups.append(g)
        if len(keys) != shard['groups']:
            raise ValueError('incomplete feature shard')
    if not groups:
        raise ValueError(f'empty {split} split')
    return groups


def train(args):
    dataset, output = Path(args.dataset).resolve(), output_path(args.output)
    if output.exists() or args.epochs < 1:
        raise ValueError('choose a new model filename and positive epoch count')
    manifest = load_manifest(dataset)
    training = load_groups(dataset, manifest, 'train')
    validation = load_groups(dataset, manifest, 'validation')
    if {g['session_id'] for g in training} & {g['session_id'] for g in validation}:
        raise ValueError('training and validation sessions overlap')
    positive = [g for g in training if g['prefix_valid'] and g['samples'] in
                (manifest['config']['min_samples'], manifest['config']['max_samples'])]
    detector_training = [g for g in training if g['samples'] in
                         (manifest['config']['min_samples'], manifest['config']['max_samples'])]
    best, experiments = None, []
    detector_best, detector_experiments = None, []
    for l2 in (0.0, .001, .01):
        weights = fit(positive, l2, args.epochs, args.seed)
        candidate = {'weights': weights}
        metrics = character_metrics(validation, candidate)
        selection = metrics['all']['model_accuracy']
        experiments.append({'l2': l2, 'validation_character_metrics': metrics})
        if best is None or selection > best[0]:
            best = selection, weights, l2
        print(f'l2={l2}: validation rank accuracy {selection:.3f}', flush=True)
        detector_weights = fit(detector_training, l2, args.epochs, args.seed, detector=True)
        candidate['detector_weights'] = detector_weights
        threshold, detector_result = choose_detector_threshold(validation, candidate)
        detector_experiments.append({'l2': l2, 'threshold': threshold, 'validation': detector_result})
        if detector_best is None or detector_result['balanced_accuracy'] > detector_best[0]:
            detector_best = detector_result['balanced_accuracy'], detector_weights, threshold, l2
    model = {'schema_version': 2, 'feature_version': FEATURE_VERSION,
             'feature_names': FEATURE_NAMES, 'detector_names': DETECTOR_NAMES,
             'model_type': 'linear_group_softmax_plus_logistic_prefix_detector',
             'weights': best[1], 'l2': best[2], 'detector_weights': detector_best[1],
             'detector_l2': detector_best[3], 'detector_threshold': detector_best[2],
             'epochs': args.epochs, 'seed': args.seed, 'created_utc': now(),
             'training_platform': platform.platform(), 'training_python': platform.python_version(),
             'dataset_manifest_sha256': digest(dataset / 'manifest.json'),
             'collection_config': manifest['config'], 'training_source_sha256': sources_for_training(),
             'train_password_ids': sorted({g['secret_id'] for g in training}),
             'validation_password_ids': sorted({g['secret_id'] for g in validation}),
             'validation_rank_experiments': experiments,
             'validation_detector_experiments': detector_experiments,
             'test_used_for_selection': False, 'sampling_thresholds': {}, 'sampling_validation': {}}
    for method in ('model', 'median'):
        selected, trials = choose_sampling_threshold(validation, model, method)
        model['sampling_thresholds'][method] = selected['threshold']
        model['sampling_validation'][method] = {'selected': selected, 'trials': trials}
    output.parent.mkdir(parents=True, exist_ok=True)
    save(output, model)
    print(f'Saved {output}; detector threshold={model["detector_threshold"]}; '
          f'adaptive thresholds={model["sampling_thresholds"]}. No test features were read.')


def sources_for_training():
    return {name: digest(ROOT / name) for name in CORE_FILES if name not in
            ('native_windows.c', 'native_windows.dll', 'native_attack.py')}


def wilson(successes, n):
    p, z = successes / n, 1.96
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0, center - margin), min(1, center + margin)]


def evaluate(args):
    from native_attack import NativeLab
    dataset, output = Path(args.dataset).resolve(), output_path(args.output)
    manifest = load_manifest(dataset)
    model_path = Path(args.model).resolve()
    model = json.loads(model_path.read_text(encoding='utf-8'))
    if model['dataset_manifest_sha256'] != digest(dataset / 'manifest.json'):
        raise ValueError('model/dataset fingerprint mismatch')
    if sources() != manifest['source_sha256']:
        raise ValueError('source or DLL changed since collection; collect a new versioned dataset')
    if any(value != manifest['source_sha256'].get(name)
           for name, value in model['training_source_sha256'].items()):
        raise ValueError('training code differs from the collected experiment version')
    if (model.get('schema_version') != 2 or model['feature_names'] != FEATURE_NAMES or
            model['detector_names'] != DETECTOR_NAMES or len(model['weights']) != len(FEATURE_NAMES) or
            len(model['detector_weights']) != len(DETECTOR_NAMES) + 1 or
            any(not math.isfinite(v) for v in model['weights'] + model['detector_weights'])):
        raise ValueError('invalid or incompatible model')
    if args.beam_width < 1 or args.reserve_size < 0 or args.timing_budget < 0 or args.verification_budget < 0:
        raise ValueError('invalid search budgets')
    ablations = args.ablations.split(',')
    methods = args.methods.split(',')
    if (len(set(ablations)) != len(ablations) or any(a not in ABLATIONS for a in ablations) or
            len(set(methods)) != len(methods) or any(m not in ('model', 'median') for m in methods)):
        raise ValueError('invalid or duplicate methods/ablations')
    test = load_groups(dataset, manifest, 'test')
    test_ids = {g['secret_id'] for g in test}
    if test_ids & (set(model['train_password_ids']) | set(model['validation_password_ids'])):
        raise ValueError('held-out passwords overlap training or validation')
    output.mkdir(parents=True, exist_ok=False)
    config = {**manifest['config'], 'beam_width': args.beam_width, 'reserve_size': args.reserve_size}
    alphabet, checker = config['alphabet'].encode('ascii'), config['checker']
    modes = [(checker, CHECKERS[checker]), ('control', 6 if checker == 'staged' else 1)]
    entries = [p for p in manifest['passwords'] if p['split'] == 'test']
    rng = random.Random(args.seed)
    rng.shuffle(entries)
    started, results = now(), []
    evaluation_config = {'beam_width': args.beam_width, 'reserve_size': args.reserve_size,
                         'timing_budget': args.timing_budget, 'verification_budget': args.verification_budget,
                         'seed': args.seed, 'ablations': ablations, 'methods': methods}
    save(output / 'evaluation_config.json', evaluation_config)
    for entry in entries:
        secret = entry['secret'].encode('ascii')
        lab = NativeLab(secret, 0, config['cpu'])
        try:
            runs = [(mode_name, mode, method, ablation) for mode_name, mode in modes
                    for method in methods for ablation in ablations]
            rng.shuffle(runs)
            for mode_name, mode, method, ablation in runs:
                label = f'{method}-{ablation}'
                context = [entry['secret_id'], 'test', 'test-fresh-recovery', 'blind', mode_name, label]
                timed_limit = args.timing_budget or default_timing_budget(alphabet, len(secret), checker, config)
                final_position = positions(len(secret), checker)[-1]
                verification_limit = args.verification_budget or len(units(
                    alphabet, len(secret), final_position, checker)) * args.beam_width
                budget = Budget(lambda guess, n: lab.measure(guess, mode, n),
                                lambda guess: lab.check(guess, mode), timed_limit, verification_limit)
                raw = output / f'{entry["secret_id"]}-{mode_name}-{label}.csv.gz'
                verification = raw.with_name(raw.name.replace('.csv.gz', '-verification.csv.gz'))
                with gzip.open(raw, 'wt', newline='', encoding='utf-8') as stream, \
                        gzip.open(verification, 'wt', newline='', encoding='utf-8') as check_stream:
                    writer, check_writer = csv.writer(stream), csv.writer(check_stream)
                    writer.writerow(RAW_COLUMNS)
                    check_writer.writerow(['secret_id', 'split', 'session_id', 'phase', 'checker',
                                           'method', 'candidate_hex', 'accepted', 'verification_call'])
                    result = recover(budget, alphabet, len(secret), checker, config, model,
                                     method, ablation,
                                     random.Random(f'{args.seed}/{entry["secret_id"]}/{mode_name}/{label}'),
                                     writer, context, check_writer)
                # Ground truth is used only AFTER secret-blind recovery to score the result.
                guess = result['guess'].encode('ascii')
                result.update(secret_id=entry['secret_id'], length=len(secret), checker=mode_name,
                              method=method, ablation=ablation,
                              correct_positions=sum(a == b for a, b in zip(guess, secret)),
                              raw_sha256=digest(raw), verification_raw_sha256=digest(verification))
                results.append(result)
                save(output / 'progress.json', results)
                print(f'{entry["secret_id"]} {mode_name}/{label}: '
                      f'{result["success"]}; calls={result["total_checker_calls"]}; '
                      f'{result["status"]}', flush=True)
        finally:
            lab.close()
    aggregates = {}
    for mode_name, _ in modes:
        for method in methods:
            for ablation in ablations:
                rows = [r for r in results if r['checker'] == mode_name and
                        r['method'] == method and r['ablation'] == ablation]
                successes = sum(r['success'] for r in rows)
                aggregates[f'{mode_name}/{method}/{ablation}'] = {
                    'passwords': len(rows), 'recovered': successes, 'recovery_rate': successes / len(rows),
                    'wilson_95_interval': wilson(successes, len(rows)),
                    'mean_total_checker_calls': statistics.mean(r['total_checker_calls'] for r in rows),
                    'mean_timed_calls': statistics.mean(r['timed_checker_calls'] for r in rows),
                    'mean_warmup_calls': statistics.mean(r['warmup_checker_calls'] for r in rows),
                    'mean_verification_calls': statistics.mean(r['verification_calls'] for r in rows),
                    'mean_elapsed_seconds': statistics.mean(r['elapsed_seconds'] for r in rows),
                    'macro_character_accuracy': statistics.mean(r['correct_positions'] / r['length'] for r in rows),
                    'backtracks': sum(r['backtracks'] for r in rows),
                    'detector_rejections': sum(r['detector_rejections'] for r in rows)}
    report = {'schema_version': 2, 'started_utc': started, 'finished_utc': now(),
              'dataset_manifest_sha256': digest(dataset / 'manifest.json'), 'model_sha256': digest(model_path),
              'source_sha256': sources(), 'evaluation_config': evaluation_config,
              'platform': platform.platform(), 'python': platform.python_version(),
              'calibration_character_metrics': character_metrics(test, model),
              'test_prefix_detector_metrics': detector_metrics(test, model, model['detector_threshold']),
              'results': aggregates, 'runs': results,
              'limitations': ['Password length and candidate alphabet are known.',
                              'All models use timing-derived inputs; secrets label/score experiments only.',
                              'Every ablation has identical per-password timing/warmup and verification caps.',
                              'Actual calls differ and are reported; enumeration is separately identified.',
                              'Beam scores and detector outputs are not calibrated confidence probabilities.',
                              'Library/trie modes use the fixed-byte negative control, not a matched-cost control.',
                              'Staged mode compares two-character SHA-256 components and uses a full-stage-work control.',
                              'Staged component hashing is deliberately flawed authentication architecture, not password storage advice.',
                              'Collection blocks on one machine do not establish day/machine generalization.',
                              'TSC ticks are reference ticks, not actual core cycles.']}
    save(output / 'report.json', report)
    lines = ['# V2 held-out recovery ablations', '',
             f'Checker: `{checker}`; password split: `{manifest["split_counts"]}`.', '',
             '| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |',
             '| --- | --- | --- | ---: | ---: | ---: | ---: |']
    for key, value in aggregates.items():
        mode_name, method, ablation = key.split('/')
        lines.append(f'| {mode_name} | {method} | {ablation} | {value["recovered"]}/{value["passwords"]} '
                     f'({value["recovery_rate"]:.1%}) | {value["mean_total_checker_calls"]:,.0f} | '
                     f'{value["mean_verification_calls"]:.1f} | {value["mean_elapsed_seconds"]:.3f} |')
    lines += ['', '## Interpretation', ''] + [f'- {x}' for x in report['limitations']]
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('Report:', output / 'REPORT.md')


def export(args):
    dataset, output = Path(args.dataset).resolve(), output_path(args.output)
    manifest = load_manifest(dataset)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in CORE_FILES:
            if name not in ('native_windows.c', 'native_windows.dll', 'native_attack.py'):
                archive.write(ROOT / name, name)
        archive.write(dataset / 'manifest.json', 'dataset/manifest.json')
        for shard in manifest['shards'].values():
            path = dataset / shard['features']
            if digest(path) != shard['features_sha256']:
                raise ValueError('feature checksum mismatch')
            archive.write(path, f'dataset/{shard["features"]}')
    print('Portable training bundle:', output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    c = commands.add_parser('collect')
    c.add_argument('--output', required=True)
    c.add_argument('--checker', choices=CHECKERS, default='naive')
    c.add_argument('--passwords', type=int, default=260)
    c.add_argument('--alphabet', default=DEFAULT_ALPHABET)
    c.add_argument('--min-length', type=int, default=4)
    c.add_argument('--max-length', type=int, default=16)
    c.add_argument('--sessions', type=int, default=2)
    c.add_argument('--min-samples', type=int, default=6)
    c.add_argument('--max-samples', type=int, default=24)
    c.add_argument('--batch', type=int)
    c.add_argument('--warmup', type=int, default=1)
    c.add_argument('--negative-prefixes', type=int, default=1)
    c.add_argument('--cpu', type=int, default=-1)
    c.add_argument('--seed', type=int, default=20261023)
    c.add_argument('--exclude-dataset', action='append', default=[])
    c.add_argument('--notes', default='')
    c.add_argument('--resume', action='store_true')
    c.add_argument('--limit-shards', type=int, default=0)
    c.set_defaults(action=collect)
    t = commands.add_parser('train')
    t.add_argument('--dataset', required=True)
    t.add_argument('--output', required=True)
    t.add_argument('--epochs', type=int, default=20)
    t.add_argument('--seed', type=int, default=7)
    t.set_defaults(action=train)
    e = commands.add_parser('evaluate')
    e.add_argument('--dataset', required=True)
    e.add_argument('--model', required=True)
    e.add_argument('--output', required=True)
    e.add_argument('--ablations', default='fixed,verify,adaptive,beam,full')
    e.add_argument('--methods', default='model,median')
    e.add_argument('--beam-width', type=int, default=3)
    e.add_argument('--reserve-size', type=int, default=32)
    e.add_argument('--timing-budget', type=int, default=0, help='timed + warmup calls per run; 0 = fixed-greedy full-sample budget')
    e.add_argument('--verification-budget', type=int, default=0, help='checks per run; 0 = final candidate count times beam width')
    e.add_argument('--seed', type=int, default=101)
    e.set_defaults(action=evaluate)
    x = commands.add_parser('export')
    x.add_argument('--dataset', required=True)
    x.add_argument('--output', required=True)
    x.set_defaults(action=export)
    args = parser.parse_args()
    try:
        args.action(args)
    except (ValueError, RuntimeError, FileExistsError, UnicodeEncodeError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()

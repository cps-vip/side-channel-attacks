"""Collect, train, and evaluate the local Windows timing research lab.

Collection/evaluation need the Windows DLL. Training uses only the Python
standard library and runs on Windows, Linux, or Google Colab.
"""
import argparse
import csv
import gzip
import hashlib
import json
import math
import platform
import random
import statistics
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from lab_config import DEFAULT_ALPHABET, validate_alphabet
from timing_model import (FEATURE_NAMES, FEATURE_VERSION, METRICS, choose, fit,
                          make_features, summarize)

ROOT = Path(__file__).resolve().parent
RAW_COLUMNS = ['secret_id', 'split', 'session_id', 'phase', 'mode', 'method',
               'position', 'sample', 'candidate_index', 'candidate_hex', 'batch',
               'wall_ns_total', 'tsc_ticks_total', 'thread_cycles_total',
               'aux_start', 'aux_end', 'endpoint_migration']


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    payload = json.dumps(value, indent=2)
    for attempt in range(7):
        try:
            temporary.write_text(payload, encoding='utf-8')
            temporary.replace(path)
            return
        except PermissionError:
            # OneDrive/Windows scanners can temporarily hold checkpoint handles.
            # Keep the old checkpoint intact and retry for at most 3.15 seconds.
            if attempt == 6:
                raise
            time.sleep(.05 * 2 ** attempt)


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def source_hashes():
    return {name: digest(ROOT / name) for name in
            ('native_windows.c', 'native_windows.dll', 'native_attack.py',
             'lab_config.py', 'timing_model.py', 'research_pipeline.py')}


def safe_output(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('output must stay inside the project folder')
    return path


def make_secrets(count, alphabet, min_length, max_length, seed):
    """Balance lengths and stratify whole unique secrets, never timing rows.

    Largest-remainder allocation approximates 70/15/15 within each length.
    Ties alternate to avoid systematically favoring validation over test.
    At least one secret per split/length is required.
    """
    rng = random.Random(seed)
    entries, seen = [], set()
    lengths = list(range(min_length, max_length + 1))
    if count < 3 * len(lengths):
        raise ValueError('need at least 3 passwords per requested length')
    for offset, length in enumerate(lengths):
        n = count // len(lengths) + int(offset < count % len(lengths))
        if n > len(alphabet) ** length:
            raise ValueError('not enough distinct passwords for this alphabet and length')
        passwords = []
        while len(passwords) < n:
            secret = ''.join(rng.choice(alphabet) for _ in range(length))
            if secret not in seen:
                seen.add(secret)
                passwords.append(secret)
        # Reserve one per split, then approximate the requested percentages.
        exact = [n * .7, n * .15, n * .15]
        counts = [max(1, math.floor(x)) for x in exact]
        while sum(counts) > n:
            i = max((i for i in range(3) if counts[i] > 1),
                    key=lambda i: counts[i] - exact[i])
            counts[i] -= 1
        while sum(counts) < n:
            order = [0, 1, 2] if offset % 2 == 0 else [0, 2, 1]
            i = max(order, key=lambda i: exact[i] - counts[i])
            counts[i] += 1
        start = 0
        for split, size in zip(('train', 'validation', 'test'), counts):
            for secret in passwords[start:start + size]:
                entries.append({'secret_id': hashlib.sha256(secret.encode()).hexdigest()[:16],
                                'secret': secret, 'length': length, 'split': split})
            start += size
    rng.shuffle(entries)
    return entries


def audit_manifest(manifest):
    entries = manifest['passwords']
    if len({p['secret'] for p in entries}) != len(entries):
        raise ValueError('duplicate passwords in manifest')
    if len({p['secret_id'] for p in entries}) != len(entries):
        raise ValueError('duplicate password IDs in manifest')
    if {p['split'] for p in entries} != {'train', 'validation', 'test'}:
        raise ValueError('all three splits are required')
    for entry in entries:
        if entry['length'] != len(entry['secret']):
            raise ValueError('incorrect length in manifest')


def measure_group(measure, alphabet, prefix, length, samples, batch, warmup,
                  rng, writer, context, position):
    """No secret or labels are passed to this measurement/feature routine."""
    sentinel = next(bytes([i]) for i in range(256) if i not in alphabet)
    guesses = [prefix + bytes([c]) + sentinel * (length - position - 1) for c in alphabet]
    distributions = [{metric: [] for metric in METRICS} for _ in alphabet]
    for guess in guesses:
        for _ in range(warmup):
            measure(guess, batch)
    migrated = 0
    for sample in range(samples):
        order = list(range(len(alphabet)))
        rng.shuffle(order)
        for i in order:
            result = measure(guesses[i], batch)
            migration = int(result.aux_start != result.aux_end)
            migrated += migration
            writer.writerow([*context, position, sample, i, guesses[i].hex(), batch,
                             result.wall_ns, result.tsc_ticks, result.thread_cycles,
                             result.aux_start, result.aux_end, migration])
            if not migration:
                for metric in METRICS:
                    distributions[i][metric].append(getattr(result, metric) / batch)
    features, medians = make_features(distributions, position == length - 1)
    return {'features': features, 'median_tsc': medians,
            'usable_samples': [len(d['tsc_ticks']) for d in distributions],
            'migrated_batches': migrated}


def collect(args):
    from native_attack import NativeLab
    alphabet = args.alphabet.encode('ascii')
    validate_alphabet(alphabet)
    if not 4 <= args.min_length <= args.max_length <= 16:
        raise ValueError('length range must be within 4–16')
    if not (0 <= args.work <= 1000000 and 1 <= args.batch <= 1000000 and
            args.samples >= 2 and args.sessions >= 1 and args.warmup >= 0 and args.cpu >= -1):
        raise ValueError('invalid measurement parameters')
    output = safe_output(args.output)
    config = {key: getattr(args, key) for key in
              ('passwords', 'alphabet', 'min_length', 'max_length', 'seed',
               'sessions', 'samples', 'batch', 'work', 'warmup', 'cpu')}
    hashes = source_hashes()
    if args.resume:
        manifest = json.loads((output / 'manifest.json').read_text())
        if manifest['config'] != config or manifest['source_sha256'] != hashes:
            raise ValueError('resume requires identical configuration and source/DLL hashes')
    else:
        output.mkdir(parents=True, exist_ok=False)
        manifest = {'schema_version': 1, 'feature_version': FEATURE_VERSION,
                    'feature_names': FEATURE_NAMES, 'created_utc': utc_now(),
                    'platform': platform.platform(), 'processor': platform.processor(),
                    'machine': platform.machine(), 'python': platform.python_version(),
                    'source_sha256': hashes, 'config': config,
                    'notes': args.notes, 'passwords': make_secrets(
                        args.passwords, args.alphabet, args.min_length, args.max_length, args.seed),
                    'shards': {}, 'complete': False}
        save_json(output / 'manifest.json', manifest)
    audit_manifest(manifest)
    (output / 'raw').mkdir(exist_ok=True)
    (output / 'features').mkdir(exist_ok=True)
    tasks = []
    rng = random.Random(args.seed + 100)
    for session in range(args.sessions):
        split_order = ['train', 'validation', 'test']
        rng.shuffle(split_order)
        for split in split_order:
            entries = [p for p in manifest['passwords'] if p['split'] == split]
            rng.shuffle(entries)
            for entry in entries:
                tasks.append((session, entry))
    start, done = time.perf_counter(), 0
    for session, entry in tasks:
        key = f'{entry["secret_id"]}-r{session}'
        if key in manifest['shards']:
            for kind in ('raw', 'features'):
                path = output / manifest['shards'][key][kind]
                if digest(path) != manifest['shards'][key][f'{kind}_sha256']:
                    raise ValueError(f'corrupt completed shard: {path}')
            continue
        raw = output / 'raw' / f'{key}.csv.gz'
        feature = output / 'features' / f'{key}.jsonl.gz'
        # Uncommitted .partial shards are replaced on resume, completed shards never are.
        raw_tmp = raw.with_suffix('.partial')
        feature_tmp = feature.with_suffix('.partial')
        secret = entry['secret'].encode('ascii')
        lab = NativeLab(secret, args.work, args.cpu)
        session_id = f'{entry["split"]}-r{session}'
        context = [entry['secret_id'], entry['split'], session_id, 'calibration', 'vulnerable', 'all_candidates']
        started = utc_now()
        shard_rng = random.Random(f'{args.seed}/{key}')
        try:
            with gzip.open(raw_tmp, 'wt', newline='', encoding='utf-8') as stream, \
                    gzip.open(feature_tmp, 'wt', encoding='utf-8') as feature_stream:
                writer = csv.writer(stream)
                writer.writerow(RAW_COLUMNS)
                for sample in range(20):
                    result = lab.measure(secret, 2, args.batch)
                    writer.writerow([*context[:3], 'baseline', 'empty', 'baseline',
                                     -1, sample, -1, '', args.batch, result.wall_ns,
                                     result.tsc_ticks, result.thread_cycles, result.aux_start,
                                     result.aux_end, int(result.aux_start != result.aux_end)])
                for position in range(len(secret)):
                    group = measure_group(lambda guess, batch: lab.measure(guess, 0, batch),
                                          alphabet, secret[:position], len(secret), args.samples,
                                          args.batch, args.warmup, shard_rng, writer, context, position)
                    # Labeling happens AFTER feature extraction in the collection harness.
                    group.update(secret_id=entry['secret_id'], split=entry['split'],
                                 session_id=session_id, length=len(secret), position=position,
                                 target=alphabet.index(secret[position]))
                    feature_stream.write(json.dumps(group) + '\n')
        finally:
            lab.close()
        raw_tmp.replace(raw)
        feature_tmp.replace(feature)
        manifest['shards'][key] = {'raw': raw.relative_to(output).as_posix(),
                                  'features': feature.relative_to(output).as_posix(),
                                  'raw_sha256': digest(raw), 'features_sha256': digest(feature),
                                  'started_utc': started, 'finished_utc': utc_now(),
                                  'split': entry['split'], 'session_id': session_id}
        save_json(output / 'manifest.json', manifest)
        done += 1
        elapsed = time.perf_counter() - start
        remaining = len(tasks) - len(manifest['shards'])
        print(f'{len(manifest["shards"])}/{len(tasks)} shards; '
              f'{elapsed / done:.2f}s/shard; ETA {remaining * elapsed / done / 60:.1f} min', flush=True)
        if args.limit_shards and done >= args.limit_shards:
            break
    manifest['complete'] = len(manifest['shards']) == len(tasks)
    manifest['updated_utc'] = utc_now()
    manifest['split_counts'] = {s: sum(p['split'] == s for p in manifest['passwords'])
                                for s in ('train', 'validation', 'test')}
    save_json(output / 'manifest.json', manifest)
    print(f'Collection complete: {manifest["complete"]}; passwords: {manifest["split_counts"]}')


def load_manifest(dataset):
    manifest = json.loads((dataset / 'manifest.json').read_text())
    audit_manifest(manifest)
    if not manifest['complete']:
        raise ValueError('collection is incomplete; resume before training/evaluation')
    if manifest['feature_version'] != FEATURE_VERSION or manifest['feature_names'] != FEATURE_NAMES:
        raise ValueError('incompatible feature schema')
    expected = {f'{p["secret_id"]}-r{r}' for p in manifest['passwords']
                for r in range(manifest['config']['sessions'])}
    if set(manifest['shards']) != expected:
        raise ValueError('missing or unexpected collection shards')
    return manifest


def load_groups(dataset, manifest, split):
    # Do not open feature files from the other splits.
    entries = {p['secret_id']: p for p in manifest['passwords'] if p['split'] == split}
    groups = []
    sessions = set()
    for key, shard in manifest['shards'].items():
        if shard['split'] != split:
            continue
        path = dataset / shard['features']
        if digest(path) != shard['features_sha256']:
            raise ValueError(f'feature checksum mismatch: {path}')
        positions = set()
        with gzip.open(path, 'rt', encoding='utf-8') as stream:
            for line in stream:
                group = json.loads(line)
                entry = entries.get(group['secret_id'])
                if (entry is None or group['split'] != split or
                        group['session_id'] != shard['session_id'] or
                        group['length'] != entry['length'] or
                        not 0 <= group['position'] < entry['length'] or
                        group['position'] in positions):
                    raise ValueError('split/session/group integrity failure')
                if (len(group['features']) != len(manifest['config']['alphabet']) or
                        any(len(row) != len(FEATURE_NAMES) or
                            any(not math.isfinite(x) for x in row) for row in group['features']) or
                        group['target'] != manifest['config']['alphabet'].index(
                            entry['secret'][group['position']])):
                    raise ValueError('invalid feature dimensions or target')
                positions.add(group['position'])
                sessions.add(group['session_id'])
                groups.append(group)
        if len(positions) != entry['length']:
            raise ValueError('incomplete positions in feature shard')
    if not groups:
        raise ValueError(f'empty {split} split')
    return groups, sessions


def train(args):
    dataset = Path(args.dataset).resolve()
    manifest = load_manifest(dataset)
    train_groups, train_sessions = load_groups(dataset, manifest, 'train')
    val_groups, val_sessions = load_groups(dataset, manifest, 'validation')
    if train_sessions & val_sessions:
        raise ValueError('sessions overlap between train and validation')
    if args.epochs < 1:
        raise ValueError('epochs must be positive')
    experiments = []
    best = None
    for l2 in (0.0, .001, .01):
        weights = fit(train_groups, l2=l2, epochs=args.epochs, seed=args.seed)
        validation = summarize(val_groups, weights)
        experiments.append({'l2': l2, 'validation': validation})
        # Pick by validation password-macro character accuracy, then loss.
        selection = (validation['macro_password_character_accuracy'], -validation['cross_entropy'])
        if best is None or selection > best[0]:
            best = selection, weights, l2
        print(f'l2={l2}: validation model={validation["buckets"]["all"]["model_accuracy"]:.3f}; '
              f'median={validation["buckets"]["all"]["median_accuracy"]:.3f}', flush=True)
    model = {'model_type': 'linear_group_softmax', 'feature_version': FEATURE_VERSION,
             'feature_names': FEATURE_NAMES, 'weights': best[1], 'l2': best[2],
             'epochs': args.epochs, 'seed': args.seed, 'created_utc': utc_now(),
             'dataset_manifest_sha256': digest(dataset / 'manifest.json'),
             'collection_config': manifest['config'], 'source_sha256': manifest['source_sha256'],
             'train_password_ids': sorted({g['secret_id'] for g in train_groups}),
             'validation_password_ids': sorted({g['secret_id'] for g in val_groups}),
             'training_metrics': summarize(train_groups, best[1]),
             'validation_experiments': experiments,
             'test_used_for_selection': False}
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError('model output already exists; choose a new filename')
    output.parent.mkdir(parents=True, exist_ok=True)
    save_json(output, model)
    print(f'Model saved: {output}. No test features were read.')


def recover_blind(measure, alphabet, length, config, weights, method, rng, writer, context):
    """Predict from measurements; no secret, labels, or candidate identity features."""
    prefix, trace = b'', []
    for position in range(length):
        group = measure_group(measure, alphabet, prefix, length, config['samples'],
                              config['batch'], config['warmup'], rng, writer, context, position)
        index = (choose(weights, group['features']) if method == 'model' else
                 max(range(len(alphabet)), key=group['median_tsc'].__getitem__))
        prefix += bytes([alphabet[index]])
        trace.append({'position': position, 'chosen_index': index,
                      'migrated_batches': group['migrated_batches']})
    return prefix, trace


def wilson(successes, total):
    z = 1.96
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def evaluate(args):
    from native_attack import NativeLab
    dataset = Path(args.dataset).resolve()
    manifest = load_manifest(dataset)
    model = json.loads(Path(args.model).read_text())
    if model['dataset_manifest_sha256'] != digest(dataset / 'manifest.json'):
        raise ValueError('model was trained against a different dataset manifest')
    if (model['feature_names'] != FEATURE_NAMES or model['feature_version'] != FEATURE_VERSION or
            len(model['weights']) != len(FEATURE_NAMES) or
            any(not math.isfinite(w) for w in model['weights'])):
        raise ValueError('incompatible model')
    current_hashes = source_hashes()
    changed_sources = [name for name, value in current_hashes.items()
                       if value != manifest['source_sha256'].get(name)]
    if changed_sources:
        if (changed_sources != ['research_pipeline.py'] or not args.allow_driver_change):
            raise ValueError('source/DLL changed since collection; collect a new versioned dataset. '
                             'A reviewed orchestration-only change can use --allow-driver-change.')
        print('Recorded driver-only source change: measurement DLL, C source, native wrapper, '
              'password configuration and feature/model module hashes are unchanged.', flush=True)
    test_groups, _ = load_groups(dataset, manifest, 'test')
    test_ids = {g['secret_id'] for g in test_groups}
    if test_ids & (set(model['train_password_ids']) | set(model['validation_password_ids'])):
        raise ValueError('test passwords overlap with model training/selection')
    output = safe_output(args.output)
    output.mkdir(parents=True, exist_ok=False)
    config = manifest['config']
    alphabet = config['alphabet'].encode('ascii')
    entries = [p for p in manifest['passwords'] if p['split'] == 'test']
    rng = random.Random(args.seed)
    rng.shuffle(entries)
    results = []
    started = utc_now()
    for entry in entries:
        secret = entry['secret'].encode('ascii')
        lab = NativeLab(secret, config['work'], config['cpu'])
        try:
            runs = [(mode, method) for mode in (0, 1) for method in ('model', 'median')]
            rng.shuffle(runs)
            for mode, method in runs:
                mode_name = 'constant' if mode else 'vulnerable'
                context = [entry['secret_id'], 'test', 'test-fresh-recovery',
                           'blind_recovery', mode_name, method]
                path = output / f'{entry["secret_id"]}-{mode_name}-{method}.csv.gz'
                with gzip.open(path, 'wt', newline='', encoding='utf-8') as stream:
                    writer = csv.writer(stream)
                    writer.writerow(RAW_COLUMNS)
                    guess, trace = recover_blind(
                        lambda guess, batch: lab.measure(guess, mode, batch), alphabet,
                        len(secret), config, model['weights'], method,
                        random.Random(f'{args.seed}/{entry["secret_id"]}/{mode}/{method}'),
                        writer, context)
                results.append({'secret_id': entry['secret_id'], 'length': len(secret),
                                'mode': mode_name, 'method': method, 'guess': guess.decode(),
                                'success': lab.check(guess, mode),
                                'correct_positions': sum(a == b for a, b in zip(guess, secret)),
                                'timed_checker_calls': len(secret) * len(alphabet) * config['samples'] * config['batch'],
                                'warmup_checker_calls': len(secret) * len(alphabet) * config['warmup'] * config['batch'],
                                'verification_calls': 1, 'trace': trace,
                                'raw_sha256': digest(path)})
                save_json(output / 'recovery_progress.json', results)
                print(f'{entry["secret_id"]} length={len(secret)} {mode_name}/{method}: '
                      f'verified={results[-1]["success"]}', flush=True)
        finally:
            lab.close()
    aggregates = {}
    for mode in ('vulnerable', 'constant'):
        for method in ('model', 'median'):
            rows = [r for r in results if r['mode'] == mode and r['method'] == method]
            successes = sum(r['success'] for r in rows)
            aggregates[f'{mode}/{method}'] = {
                'passwords': len(rows), 'recovered': successes,
                'recovery_rate': successes / len(rows),
                'wilson_95_interval_across_passwords': wilson(successes, len(rows)),
                'macro_password_character_accuracy': statistics.mean(
                    r['correct_positions'] / r['length'] for r in rows)}
    report = {'created_utc': utc_now(), 'started_utc': started,
              'collection_source_sha256': manifest['source_sha256'],
              'evaluation_source_sha256': current_hashes,
              'driver_change_acknowledged': bool(changed_sources),
              'dataset_manifest_sha256': digest(dataset / 'manifest.json'),
              'model_sha256': digest(Path(args.model)), 'seed': args.seed,
              'platform': platform.platform(), 'python': platform.python_version(),
              'calibration_test': summarize(test_groups, model['weights']),
              'blind_recovery': aggregates, 'runs': results,
              'limitations': ['Calibration supplies true prefixes; blind recovery supplies predicted prefixes.',
                              'Control uses the same candidate alphabet and budget, on independently measured adaptive paths.',
                              'The control here is a recovery negative control, not a matched fixed-candidate detector benchmark.',
                              'Model softmax scores are not calibrated confidence estimates.',
                              'One machine and collection blocks do not establish cross-machine/session generalization.',
                              'TSC ticks are reference ticks, not actual core execution cycles.']}
    save_json(output / 'report.json', report)
    lines = ['# Held-out timing model evaluation', '',
             f'Dataset password split counts: `{manifest["split_counts"]}`.', '',
             '| Checker | Method | Recovered | Rate | 95% Wilson interval |',
             '| --- | --- | ---: | ---: | --- |']
    for key, value in aggregates.items():
        mode, method = key.split('/')
        interval = value['wilson_95_interval_across_passwords']
        lines.append(f'| {mode} | {method} | {value["recovered"]}/{value["passwords"]} | '
                     f'{value["recovery_rate"]:.1%} | {interval[0]:.1%}–{interval[1]:.1%} |')
    lines += ['', '## Calibration with known correct prefixes', '',
              '| Positions | Groups | Model accuracy | Median accuracy |',
              '| --- | ---: | ---: | ---: |']
    for name, bucket in report['calibration_test']['buckets'].items():
        lines.append(f'| {name} | {bucket["groups"]} | {bucket["model_accuracy"]:.1%} | '
                     f'{bucket["median_accuracy"]:.1%} |')
    lines += ['', '## Interpretation', ''] + [f'- {x}' for x in report['limitations']]
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Report: {output / "REPORT.md"}')


def export(args):
    dataset = Path(args.dataset).resolve()
    manifest = load_manifest(dataset)
    output = safe_output(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ('research_pipeline.py', 'timing_model.py', 'lab_config.py'):
            archive.write(ROOT / name, name)
        archive.write(dataset / 'manifest.json', 'dataset/manifest.json')
        for shard in manifest['shards'].values():
            path = dataset / shard['features']
            if digest(path) != shard['features_sha256']:
                raise ValueError(f'feature checksum mismatch: {path}')
            archive.write(path, f'dataset/{shard["features"]}')
    print(f'Colab bundle: {output}; raw timing CSVs remain in the local dataset.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    collector = commands.add_parser('collect', help='Windows: collect labeled synthetic timing distributions')
    collector.add_argument('--output', required=True)
    collector.add_argument('--passwords', type=int, default=130)
    collector.add_argument('--alphabet', default=DEFAULT_ALPHABET)
    collector.add_argument('--min-length', type=int, default=4)
    collector.add_argument('--max-length', type=int, default=16)
    collector.add_argument('--sessions', type=int, default=2)
    collector.add_argument('--samples', type=int, default=40)
    collector.add_argument('--batch', type=int, default=1000)
    collector.add_argument('--warmup', type=int, default=5)
    collector.add_argument('--work', type=int, default=0)
    collector.add_argument('--cpu', type=int, default=-1)
    collector.add_argument('--seed', type=int, default=20261021)
    collector.add_argument('--notes', default='', help='record power plan, load, thermal conditions, virtualization, etc.')
    collector.add_argument('--resume', action='store_true')
    collector.add_argument('--limit-shards', type=int, default=0, help='stop after N new shards to test resume')
    collector.set_defaults(action=collect)
    trainer = commands.add_parser('train', help='Windows or Colab: fit timing classifier without reading test features')
    trainer.add_argument('--dataset', required=True)
    trainer.add_argument('--output', required=True)
    trainer.add_argument('--epochs', type=int, default=50)
    trainer.add_argument('--seed', type=int, default=7)
    trainer.set_defaults(action=train)
    evaluator = commands.add_parser('evaluate', help='Windows: held-out calibration and fresh blind recovery')
    evaluator.add_argument('--dataset', required=True)
    evaluator.add_argument('--model', required=True)
    evaluator.add_argument('--output', required=True)
    evaluator.add_argument('--seed', type=int, default=101)
    evaluator.add_argument('--allow-driver-change', action='store_true',
                           help='explicitly acknowledge a reviewed driver-only update; other source/DLL changes still fail')
    evaluator.set_defaults(action=evaluate)
    exporter = commands.add_parser('export', help='package portable training code and features for Colab')
    exporter.add_argument('--dataset', required=True)
    exporter.add_argument('--output', required=True)
    exporter.set_defaults(action=export)
    args = parser.parse_args()
    try:
        args.action(args)
    except (ValueError, RuntimeError, FileExistsError) as error:
        parser.exit(2, f'Error: {error}\n')


if __name__ == '__main__':
    main()

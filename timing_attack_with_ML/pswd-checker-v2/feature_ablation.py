"""Train an 18-feature ranker, with the rich model's prefix detector frozen.

This isolates timing feature changes on the same data. Run before examining
test outcomes. Only training and validation feature files are opened.
"""
import argparse
import json
from pathlib import Path

from research_pipeline import (digest, load_groups, load_manifest, now, output_path,
                               save, sources_for_training)
from timing_model import FEATURE_NAMES, character_metrics, choose_sampling_threshold, fit

BASIC_INDICES = [i for i, name in enumerate(FEATURE_NAMES)
                 if any(f'_{q}' in name for q in ('q10', 'q50', 'q90')) and 'paired' not in name]


def train_basic(dataset, base_path, output, epochs=20, seed=7):
    dataset, base_path, output = Path(dataset).resolve(), Path(base_path).resolve(), output_path(output)
    if output.exists() or epochs < 1:
        raise ValueError('choose a new output name and positive epochs')
    manifest = load_manifest(dataset)
    model = json.loads(base_path.read_text(encoding='utf-8'))
    if model['dataset_manifest_sha256'] != digest(dataset / 'manifest.json'):
        raise ValueError('base model/dataset mismatch')
    if model['training_source_sha256'] != sources_for_training():
        raise ValueError('training sources changed since the base model')
    training = load_groups(dataset, manifest, 'train')
    validation = load_groups(dataset, manifest, 'validation')
    positives = []
    for g in training:
        if g['prefix_valid'] and g['samples'] in (manifest['config']['min_samples'], manifest['config']['max_samples']):
            positives.append({**g, 'features': [[v if i in BASIC_INDICES else 0.0
                                               for i, v in enumerate(row)] for row in g['features']]})
    best, experiments = None, []
    for l2 in (0.0, .001, .01):
        weights = fit(positives, l2, epochs, seed)
        assert all(weights[i] == 0.0 for i in range(len(weights)) if i not in BASIC_INDICES)
        metrics = character_metrics(validation, {'weights': weights})
        score = metrics['all']['model_accuracy']
        experiments.append({'l2': l2, 'validation_character_metrics': metrics})
        if best is None or score > best[0]:
            best = score, weights, l2
        print(f'basic18 l2={l2}: validation rank accuracy {score:.3f}', flush=True)
    model.update(weights=best[1], l2=best[2], epochs=epochs, seed=seed, created_utc=now(),
                 model_type='basic18_group_softmax_plus_frozen_prefix_detector',
                 validation_rank_experiments=experiments,
                 feature_ablation={'active_features': [manifest['feature_names'][i] for i in BASIC_INDICES],
                                   'base_model_sha256': digest(base_path),
                                   'script_sha256': digest(Path(__file__)),
                                   'detector_frozen_from_base': True})
    selected, trials = choose_sampling_threshold(validation, model, 'model')
    model['sampling_thresholds']['model'] = selected['threshold']
    model['sampling_validation']['model'] = {'selected': selected, 'trials': trials}
    output.parent.mkdir(parents=True, exist_ok=True)
    save(output, model)
    print(f'Saved {output}; test features were not read; detector remains frozen.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--base-model', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--epochs', type=int, default=20)
    parser.add_argument('--seed', type=int, default=7)
    args = parser.parse_args()
    try:
        train_basic(args.dataset, args.base_model, args.output, args.epochs, args.seed)
    except (ValueError, RuntimeError) as error:
        parser.exit(2, f'Error: {error}\n')

"""Dependency-free listwise timing classifier; also runs in Linux/Colab.

One group contains timing distributions for all next-character candidates.
Only derived timing features enter the model, never character identities,
candidate bytes, password IDs, or labels.
"""
import math
import random
import statistics

METRICS = ('tsc_ticks', 'wall_ns', 'thread_cycles')
QUANTILES = (0.1, 0.5, 0.9)
BASE_FEATURES = [f'{metric}_q{int(q * 100)}_relative'
                 for metric in METRICS for q in QUANTILES]
FEATURE_NAMES = BASE_FEATURES + [f'{name}_last_position' for name in BASE_FEATURES]
FEATURE_VERSION = 1


def quantile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    lo = int(index)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def make_features(distributions, last_position):
    """Accept only per-candidate timing dictionaries, in alphabet order.

    Center each quantile across candidates; scale by the larger of across-
    candidate IQR and median within-candidate IQR. No learned preprocessing
    or labels are used. Clamp noise spikes before the linear classifier.
    """
    features = [[] for _ in distributions]
    medians = []
    for metric in METRICS:
        if any(not candidate[metric] for candidate in distributions):
            raise ValueError('every candidate needs a usable sample for every metric')
        noise = statistics.median(quantile(c[metric], .75) - quantile(c[metric], .25)
                                  for c in distributions)
        for q in QUANTILES:
            values = [quantile(c[metric], q) for c in distributions]
            center = statistics.median(values)
            scale = max(quantile(values, .75) - quantile(values, .25), noise, 1e-9)
            for row, value in zip(features, values):
                row.append(max(-20.0, min(20.0, (value - center) / scale)))
            if metric == 'tsc_ticks' and q == .5:
                medians = values
    for row in features:
        row.extend([value * int(last_position) for value in row[:]])
    return features, medians


def scores(weights, features):
    return [sum(w * x for w, x in zip(weights, row)) for row in features]


def probabilities(values):
    top = max(values)
    exps = [math.exp(v - top) for v in values]
    total = sum(exps)
    return [value / total for value in exps]


def choose(weights, features):
    values = scores(weights, features)
    return max(range(len(values)), key=values.__getitem__)


def fit(groups, l2=.001, epochs=50, seed=7, learning_rate=.03):
    """Minimize group softmax cross-entropy with mini-batch Adam.

    Each group has exactly one positive among all alphabet candidates, so
    the objective handles the candidate imbalance without oversampling.
    """
    if not groups:
        raise ValueError('empty training split')
    weights = [0.0] * len(FEATURE_NAMES)
    first = [0.0] * len(weights)
    second = [0.0] * len(weights)
    rng = random.Random(seed)
    ordered = list(groups)
    step = 0
    for _ in range(epochs):
        rng.shuffle(ordered)
        for start in range(0, len(ordered), 32):
            batch = ordered[start:start + 32]
            gradient = [0.0] * len(weights)
            for group in batch:
                features, target = group['features'], group['target']
                probs = probabilities(scores(weights, features))
                for i, row in enumerate(features):
                    error = probs[i] - int(i == target)
                    for j, value in enumerate(row):
                        gradient[j] += error * value
            step += 1
            for j in range(len(weights)):
                g = gradient[j] / len(batch) + l2 * weights[j]
                first[j] = .9 * first[j] + .1 * g
                second[j] = .999 * second[j] + .001 * g * g
                weights[j] -= learning_rate * (first[j] / (1 - .9 ** step)) / (
                    math.sqrt(second[j] / (1 - .999 ** step)) + 1e-8)
    return weights


def summarize(groups, weights):
    buckets = {}
    losses = []
    by_secret = {}
    for group in groups:
        predicted = choose(weights, group['features'])
        median = max(range(len(group['median_tsc'])), key=group['median_tsc'].__getitem__)
        target = group['target']
        p = probabilities(scores(weights, group['features']))[target]
        losses.append(-math.log(max(p, 1e-15)))
        correct = int(predicted == target)
        by_secret.setdefault(group['secret_id'], []).append(correct)
        for name in ('all', f'length_{group["length"]}',
                     'last_position' if group['position'] == group['length'] - 1 else 'earlier_positions'):
            bucket = buckets.setdefault(name, {'groups': 0, 'model_correct': 0, 'median_correct': 0})
            bucket['groups'] += 1
            bucket['model_correct'] += correct
            bucket['median_correct'] += int(median == target)
    for bucket in buckets.values():
        bucket['model_accuracy'] = bucket['model_correct'] / bucket['groups']
        bucket['median_accuracy'] = bucket['median_correct'] / bucket['groups']
    return {'buckets': buckets, 'cross_entropy': statistics.mean(losses),
            'macro_password_character_accuracy': statistics.mean(
                statistics.mean(values) for values in by_secret.values()),
            'unique_passwords': len(by_secret)}

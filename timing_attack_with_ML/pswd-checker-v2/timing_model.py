"""CPU-only timing ranker and separately trained prefix-validity detector."""
import math
import random
import statistics

METRICS = ('tsc_ticks', 'wall_ns', 'thread_cycles')
STAT_NAMES = ('q10', 'q50', 'q90', 'iqr', 'mad', 'paired_q50', 'round_wins')
BASE_NAMES = [f'{m}_{s}' for m in METRICS for s in STAT_NAMES]
FEATURE_NAMES = BASE_NAMES + [f'{s}_last' for s in BASE_NAMES]
DETECTOR_NAMES = [f'{m}_{s}' for m in METRICS
                  for s in ('peak', 'gap', 'separation', 'winner_consistency')] + ['last', 'depth']
FEATURE_VERSION = 2


def quantile(values, q):
    data = sorted(values)
    x = (len(data) - 1) * q
    i = int(x)
    return data[i] + (data[min(i + 1, len(data) - 1)] - data[i]) * (x - i)


def clip(x):
    return max(-20.0, min(20.0, x))


def features(rounds, last, depth, metrics=METRICS):
    """Rows contain aligned candidate readings or None for endpoint migration.

    No candidate bytes, identities, labels, or secret enter this function.
    Paired features subtract the same-round median to reduce shared drift.
    """
    count = len(rounds[0])
    result = [[] for _ in range(count)]
    detector = []
    median_tsc = []
    for metric in metrics:
        values = [[r[i][metric] for r in rounds if r[i] is not None] for i in range(count)]
        if any(not row for row in values):
            raise ValueError('a candidate has no retained samples')
        centers = [statistics.median(row) for row in values]
        iqrs = [quantile(row, .75) - quantile(row, .25) for row in values]
        noise = max(statistics.median(iqrs), 1e-9)
        paired = [[] for _ in range(count)]
        wins = [0] * count
        for row in rounds:
            present = [(i, r[metric]) for i, r in enumerate(row) if r is not None]
            if not present:
                continue
            center = statistics.median(v for _, v in present)
            maximum = max(v for _, v in present)
            tied = sum(v == maximum for _, v in present)
            for i, value in present:
                paired[i].append(value - center)
                if value == maximum:
                    wins[i] += 1 / tied
        tables = [[quantile(row, q) for row in values] for q in (.1, .5, .9)]
        tables += [iqrs, [statistics.median(abs(x - center) for x in row)
                          for row, center in zip(values, centers)],
                   [statistics.median(row) for row in paired],
                   [w / len(rounds) for w in wins]]
        for table in tables:
            center = statistics.median(table)
            scale = max(quantile(table, .75) - quantile(table, .25),
                        noise if table is not tables[-1] else .05, 1e-9)
            for i, value in enumerate(table):
                result[i].append(clip((value - center) / scale))
        ordered = sorted(range(count), key=centers.__getitem__, reverse=True)
        top, second = ordered[:2]
        other_high = statistics.median(quantile(values[i], .9) for i in ordered[1:])
        detector.extend([clip((centers[top] - statistics.median(centers)) / noise),
                         clip((centers[top] - centers[second]) / noise),
                         clip((quantile(values[top], .1) - other_high) / noise),
                         wins[top] / len(rounds)])
        if metric == 'tsc_ticks':
            median_tsc = centers
    for row in result:
        row.extend([v * int(last) for v in row[:]])
    detector.extend([int(last), depth])
    half_winners = []
    mid = len(rounds) // 2
    for half in (rounds[:mid], rounds[mid:]):
        data = [[r[i]['tsc_ticks'] for r in half if r[i] is not None] for i in range(count)]
        half_winners.append(max(range(count), key=lambda i: statistics.median(data[i]))
                            if all(data) else None)
    stable = half_winners[0] if half_winners[0] == half_winners[1] else None
    return {'features': result, 'detector_features': detector, 'median_tsc': median_tsc,
            'stable_tsc_winner': stable, 'samples': len(rounds),
            'usable_samples': [sum(r[i] is not None for r in rounds) for i in range(count)]}


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def softmax(values):
    top = max(values)
    exps = [math.exp(v - top) for v in values]
    total = sum(exps)
    return [v / total for v in exps]


def sigmoid(x):
    return 1 / (1 + math.exp(-max(-40, min(40, x))))


def rank(group, model, method):
    values = ([dot(model['weights'], row) for row in group['features']] if method == 'model'
              else [row[1] for row in group['features']])
    order = sorted(range(len(values)), key=values.__getitem__, reverse=True)
    return order, softmax(values), values[order[0]] - values[order[1]]


def prefix_score(group, model):
    return sigmoid(dot(model['detector_weights'], [1.0] + list(group['detector_features'])))


def fit(groups, l2, epochs, seed, detector=False):
    size = len(DETECTOR_NAMES) + 1 if detector else len(FEATURE_NAMES)
    weights, first, second = [0.0] * size, [0.0] * size, [0.0] * size
    ordered = list(groups)
    rng, step = random.Random(seed), 0
    for _ in range(epochs):
        rng.shuffle(ordered)
        for start in range(0, len(ordered), 32):
            batch = ordered[start:start + 32]
            gradient = [0.0] * size
            for group in batch:
                if detector:
                    row = [1.0] + list(group['detector_features'])
                    error = sigmoid(dot(weights, row)) - int(group['prefix_valid'])
                    for j, value in enumerate(row):
                        gradient[j] += error * value
                else:
                    probs = softmax([dot(weights, row) for row in group['features']])
                    for i, row in enumerate(group['features']):
                        error = probs[i] - int(i == group['target'])
                        if abs(error) < 1e-12:
                            continue
                        for j, value in enumerate(row):
                            gradient[j] += error * value
            step += 1
            for j in range(size):
                g = gradient[j] / len(batch) + l2 * weights[j]
                first[j] = .9 * first[j] + .1 * g
                second[j] = .999 * second[j] + .001 * g * g
                weights[j] -= .03 * (first[j] / (1 - .9 ** step)) / (
                    math.sqrt(second[j] / (1 - .999 ** step)) + 1e-8)
    return weights


def character_metrics(groups, model):
    positives = [g for g in groups if g['prefix_valid']]
    maximums = {}
    for group in positives:
        key = (group['secret_id'], group['session_id'], group['position'])
        if key not in maximums or group['samples'] > maximums[key]['samples']:
            maximums[key] = group
    buckets = {}
    for g in maximums.values():
        for name in ('all', 'last' if g['last'] else 'earlier', f'length_{g["length"]}'):
            bucket = buckets.setdefault(name, {'groups': 0, 'model_correct': 0, 'median_correct': 0})
            bucket['groups'] += 1
            for method in ('model', 'median'):
                bucket[f'{method}_correct'] += int(rank(g, model, method)[0][0] == g['target'])
    for bucket in buckets.values():
        for method in ('model', 'median'):
            bucket[f'{method}_accuracy'] = bucket[f'{method}_correct'] / bucket['groups']
    return buckets


def detector_metrics(groups, model, threshold):
    valid = [g for g in groups if g['prefix_valid']]
    invalid = [g for g in groups if not g['prefix_valid']]
    if not valid or not invalid:
        raise ValueError('prefix detector needs both positive and wrong-prefix groups')
    false_rejection = sum(prefix_score(g, model) < threshold for g in valid) / len(valid)
    detection = sum(prefix_score(g, model) < threshold for g in invalid) / len(invalid)
    return {'valid_groups': len(valid), 'wrong_prefix_groups': len(invalid),
            'false_rejection_rate': false_rejection, 'wrong_prefix_detection_rate': detection,
            'balanced_accuracy': (1 - false_rejection + detection) / 2}


def choose_detector_threshold(groups, model):
    candidates = []
    for threshold in (0.0, .05, .1, .2, .35, .5, .65, .8, .95):
        metrics = detector_metrics(groups, model, threshold)
        if metrics['false_rejection_rate'] <= .02:
            candidates.append((metrics['balanced_accuracy'], threshold, metrics))
    _, threshold, metrics = max(candidates, key=lambda x: (x[0], -x[1]))
    return threshold, metrics


def choose_sampling_threshold(groups, model, method):
    by_group = {}
    for group in groups:
        if group['prefix_valid']:
            key = (group['secret_id'], group['session_id'], group['position'])
            by_group.setdefault(key, []).append(group)
    trials = []
    fixed_correct = sum(rank(max(items, key=lambda g: g['samples']), model, method)[0][0]
                        == items[0]['target'] for items in by_group.values())
    for threshold in (.5, 1.0, 2.0, 4.0, 8.0, 1e9):
        correct, samples = 0, 0
        for items in by_group.values():
            items.sort(key=lambda g: g['samples'])
            selected = items[-1]
            for group in items[:-1]:
                order, _, margin = rank(group, model, method)
                if order[0] == group['stable_tsc_winner'] and margin >= threshold:
                    selected = group
                    break
            correct += rank(selected, model, method)[0][0] == selected['target']
            samples += selected['samples']
        trials.append({'threshold': threshold, 'correct': correct, 'groups': len(by_group),
                       'samples_sum': samples})
    eligible = [t for t in trials if t['correct'] / t['groups'] >= fixed_correct / len(by_group) - .005]
    return min(eligible, key=lambda t: (t['samples_sum'], -t['correct'], -t['threshold'])), trials

"""Budgeted, secret-blind sampling and prefix search for local lab oracles."""
import itertools
import math
import statistics
import time

from timing_model import METRICS, features, prefix_score, rank

CHECKERS = {'naive': 0, 'library': 3, 'trie': 4, 'staged': 5}
RAW_COLUMNS = ['secret_id', 'split', 'session_id', 'phase', 'checker', 'method',
               'position', 'prefix_hex', 'sample', 'candidate_index', 'candidate_hex',
               'batch', 'wall_ns_total', 'tsc_ticks_total', 'thread_cycles_total',
               'aux_start', 'aux_end', 'endpoint_migration', 'measurement_kind']


class BudgetExhausted(Exception):
    pass


class Budget:
    def __init__(self, measure, check, timed_limit, verification_limit):
        self.oracle_measure, self.oracle_check = measure, check
        self.timed_limit, self.verification_limit = timed_limit, verification_limit
        self.timed_calls = self.warmup_calls = self.verification_calls = 0

    def measure(self, guess, batch, warmup=False):
        if self.timed_calls + self.warmup_calls + batch > self.timed_limit:
            raise BudgetExhausted('timing/warmup call budget exhausted')
        if warmup:
            self.warmup_calls += batch
        else:
            self.timed_calls += batch
        return self.oracle_measure(guess, batch)

    def check(self, guess):
        if self.verification_calls >= self.verification_limit:
            raise BudgetExhausted('verification call budget exhausted')
        self.verification_calls += 1
        return self.oracle_check(guess)

    def counts(self):
        return {'timed_checker_calls': self.timed_calls, 'warmup_checker_calls': self.warmup_calls,
                'verification_calls': self.verification_calls,
                'total_checker_calls': self.timed_calls + self.warmup_calls + self.verification_calls,
                'timing_warmup_limit': self.timed_limit, 'verification_limit': self.verification_limit}


def units(alphabet, length, position, checker):
    width = min(2 if checker == 'staged' else 1, length - position)
    return [bytes(chars) for chars in itertools.product(alphabet, repeat=width)]


def positions(length, checker):
    return list(range(0, length, 2 if checker == 'staged' else 1))


def write_reading(writer, context, prefix, position, sample, index, guess, batch, result, kind):
    writer.writerow([*context, position, prefix.hex(), sample, index, guess.hex(), batch,
                     result.wall_ns, result.tsc_ticks, result.thread_cycles,
                     result.aux_start, result.aux_end,
                     int(result.aux_start != result.aux_end), kind])


class Sampler:
    def __init__(self, budget, alphabet, prefix, length, checker, config, rng, writer, context):
        self.budget, self.prefix, self.position = budget, prefix, len(prefix)
        self.candidates = units(alphabet, length, self.position, checker)
        sentinel = next(bytes([i]) for i in range(256) if i not in alphabet)
        self.guesses = [prefix + unit + sentinel * (length - len(prefix) - len(unit))
                        for unit in self.candidates]
        self.length, self.config, self.rng = length, config, rng
        self.writer, self.context, self.rounds = writer, context, []
        # Warmups are charged and retained as raw data, excluded from features.
        for i, guess in enumerate(self.guesses):
            for sample in range(config['warmup']):
                result = budget.measure(guess, config['batch'], warmup=True)
                write_reading(writer, context, prefix, self.position, sample, i, guess,
                              config['batch'], result, 'warmup')

    def extend(self, target):
        batch = self.config['batch']
        while len(self.rounds) < target:
            row = [None] * len(self.guesses)
            order = list(range(len(self.guesses)))
            self.rng.shuffle(order)
            sample = len(self.rounds)
            for i in order:
                result = self.budget.measure(self.guesses[i], batch)
                write_reading(self.writer, self.context, self.prefix, self.position,
                              sample, i, self.guesses[i], batch, result, 'timed')
                if result.aux_start == result.aux_end:
                    row[i] = {metric: getattr(result, metric) / batch for metric in METRICS}
            self.rounds.append(row)
        last = len(self.prefix) + len(self.candidates[0]) == self.length
        return features(self.rounds, last, len(self.prefix) / self.length)


ABLATIONS = {
    'fixed': {'adaptive': False, 'beam': False, 'detect': False, 'verify': False},
    'verify': {'adaptive': False, 'beam': False, 'detect': False, 'verify': True},
    'adaptive': {'adaptive': True, 'beam': False, 'detect': False, 'verify': True},
    'beam': {'adaptive': True, 'beam': True, 'detect': False, 'verify': True},
    'full': {'adaptive': True, 'beam': True, 'detect': True, 'verify': True},
}


def default_timing_budget(alphabet, length, checker, config):
    return sum(len(units(alphabet, length, p, checker)) for p in positions(length, checker)) * (
        config['max_samples'] + config['warmup']) * config['batch']


def recover(budget, alphabet, length, checker, config, model, method, ablation,
            rng, writer, context, verification_writer=None):
    """Only oracle callables, public length/alphabet and trained weights enter search."""
    options = ABLATIONS[ablation]
    width = config['beam_width'] if options['beam'] else 1
    beam, reserve, visited = [(b'', 0.0)], [], set()
    trace, guess, success, status = [], b'', False, 'no_candidates'
    started = time.perf_counter()
    backtracks = rejected = 0

    def refill():
        nonlocal beam, reserve, backtracks
        reserve = [s for s in reserve if s[0] not in visited]
        if not options['beam'] or not reserve:
            return False
        reserve.sort(key=lambda s: s[1] / max(1, len(s[0])), reverse=True)
        depth = len(reserve[0][0])
        beam = [s for s in reserve if len(s[0]) == depth][:width]
        chosen = {s[0] for s in beam}
        reserve = [s for s in reserve if s[0] not in chosen]
        backtracks += 1
        return True

    try:
        while beam:
            expanded = []
            for prefix, path_score in beam:
                if prefix in visited:
                    continue
                visited.add(prefix)
                guess = prefix
                candidates = units(alphabet, length, len(prefix), checker)
                last = len(prefix) + len(candidates[0]) == length
                if last and options['verify']:
                    order = list(range(len(candidates)))
                    rng.shuffle(order)
                    for index in order:
                        guess = prefix + candidates[index]
                        accepted = budget.check(guess)
                        if verification_writer is not None:
                            verification_writer.writerow([*context, guess.hex(), int(accepted),
                                                           budget.verification_calls])
                        if accepted:
                            success, status = True, 'verified'
                            break
                    trace.append({'prefix_hex': prefix.hex(), 'position': len(prefix),
                                  'event': 'final_unit_verification', 'accepted': success})
                    if success:
                        break
                    continue
                sampler = Sampler(budget, alphabet, prefix, length, checker, config, rng, writer, context)
                checkpoints = config['checkpoints'] if options['adaptive'] else [config['max_samples']]
                group = None
                for checkpoint in checkpoints:
                    try:
                        group = sampler.extend(checkpoint)
                    except ValueError:
                        # Migration-only candidates need more rounds; keep all raw readings.
                        if checkpoint == checkpoints[-1]:
                            raise
                        continue
                    order, probs, margin = rank(group, model, method)
                    # Flat wrong-prefix groups otherwise consume the maximum
                    # samples before being rejected, starving the other beams.
                    # The detector was validated on these partial snapshots.
                    if (options['detect'] and prefix and
                            prefix_score(group, model) < model['detector_threshold']):
                        break
                    if (options['adaptive'] and order[0] == group['stable_tsc_winner'] and
                            margin >= model['sampling_thresholds'][method]):
                        break
                if group is None:
                    raise ValueError('no usable candidate group')
                order, probs, margin = rank(group, model, method)
                validity = prefix_score(group, model)
                reject = options['detect'] and bool(prefix) and validity < model['detector_threshold']
                trace.append({'prefix_hex': prefix.hex(), 'position': len(prefix),
                              'samples': group['samples'], 'ranked_indices': order[:width],
                              'margin_score': margin, 'prefix_validity_score': validity,
                              'rejected_by_detector': reject})
                if reject:
                    rejected += 1
                    continue
                for index in order[:width]:
                    child = prefix + candidates[index]
                    score = path_score + math.log(max(probs[index], 1e-15))
                    expanded.append((child, score))
            if success:
                break
            if expanded:
                expanded.sort(key=lambda s: s[1], reverse=True)
                beam = expanded[:width]
                if options['beam']:
                    reserve.extend(expanded[width:])
                    reserve.sort(key=lambda s: s[1] / max(1, len(s[0])), reverse=True)
                    reserve = reserve[:config['reserve_size']]
                if len(beam[0][0]) == length:
                    guess = beam[0][0]
                    success = budget.check(guess)
                    if verification_writer is not None:
                        verification_writer.writerow([*context, guess.hex(), int(success),
                                                       budget.verification_calls])
                    status = 'verified' if success else 'final_guess_rejected'
                    break
            elif not refill():
                status = 'no_signal_or_verification_failed'
                break
    except BudgetExhausted as error:
        status = str(error)
    except ValueError as error:
        status = f'unusable_measurements: {error}'
    return {'guess': guess.decode('ascii'), 'success': success, 'status': status,
            'elapsed_seconds': time.perf_counter() - started, 'backtracks': backtracks,
            'detector_rejections': rejected, 'trace': trace, **budget.counts()}

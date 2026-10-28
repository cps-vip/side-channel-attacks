"""Explicit measurement units and portable dataset schemas for each backend.

Training selects a schema from the dataset, never from the training host's OS.
The original Windows schema remains readable on Linux and macOS.
"""
import platform
import sys

WINDOWS = 'windows-x86_64'
LINUX = 'linux-x86_64'
STAT_NAMES = ('q10', 'q50', 'q90', 'iqr', 'mad', 'paired_q50', 'round_wins')


def native_backend():
    machine = platform.machine().lower()
    if machine not in ('x86_64', 'amd64'):
        raise RuntimeError('Native measurements require x86-64 with RDTSCP and invariant TSC; '
                           f'found {sys.platform}/{machine}. Portable training still works.')
    if sys.platform == 'linux':
        return LINUX
    if sys.platform == 'win32':
        return WINDOWS
    raise RuntimeError('Native measurements require Linux or Windows x86-64.')


def schema_for(backend=WINDOWS):
    if backend not in (WINDOWS, LINUX):
        raise ValueError(f'unknown measurement backend: {backend}')
    linux = backend == LINUX
    metrics = ('tsc_ticks', 'wall_ns', 'thread_cpu_ns' if linux else 'thread_cycles')
    base = [f'{metric}_{stat}' for metric in metrics for stat in STAT_NAMES]
    return {
        'measurement_backend': backend,
        'schema_version': 3 if linux else 2,
        'feature_version': 3 if linux else 2,
        'metrics': metrics,
        'metric_units': {'tsc_ticks': 'reference_ticks', 'wall_ns': 'nanoseconds',
                         metrics[2]: 'nanoseconds' if linux else 'thread_cycle_accounting'},
        'feature_names': base + [f'{name}_last' for name in base],
        'detector_names': [f'{metric}_{stat}' for metric in metrics
                           for stat in ('peak', 'gap', 'separation', 'winner_consistency')]
                          + ['last', 'depth'],
    }


def config_schema(config):
    # Existing Windows datasets predate the explicit backend field.
    return schema_for(config.get('measurement_backend', WINDOWS))


def require_checker(backend, checker):
    if backend == LINUX and checker != 'naive':
        raise ValueError('The Linux pilot supports --checker naive only (plus its control and baseline).')

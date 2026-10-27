# Expanded password alphabet verification

Tested locally on 2026-10-21 after rebuilding `native_windows.dll` from source with `build_native.ps1`.

Supported synthetic secrets contain 4–16 lowercase ASCII letters or digits. The default attack alphabet is `abcdefghijklmnopqrstuvwxyz0123456789`. The attack still receives the password length; length inference is not implemented. Guesses may contain the outside-alphabet sentinel used to prevent accidental suffix matches.

## Correctness

`python -m unittest -v` passed all five tests. Tests cover all 13 supported lengths, mixed letters/digits, exact matches, incorrect candidates, and rejected secret lengths/characters. Native tests also exercise C initialization validation directly. Both vulnerable and fixed-work checkers are covered. The native wrapper and Python oracle factory validate secrets before constructing the experiment; the Python comparison primitives remain usable as low-level byte comparators.

## Observed recovery runs

All runs below used the full 36-symbol alphabet and seed 7. Native runs requested CPU 0. Existing result directories were preserved.

| Result directory | Length | Amplification | Samples | Batch | Guess | Verified |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `results/alphanumeric-4` | 4 | 0 | 400 | 1000 | `a0ze` | false |
| `results/alphanumeric-16` | 16 | 0 | 400 | 1000 | `a0z9b1y8c2x7d3wg` | false |
| `results/alphanumeric-4-amplified` | 4 | 200 | 100 | 10 | `a0z9` | true |
| `results/alphanumeric-16-amplified` | 16 | 200 | 100 | 10 | `a0z9b1y8c2x7d3w6` | true |
| `results/alphanumeric-python-4` | 4 | 2000 | 40 | 10 | `a0z9` | true |

The unamplified native runs selected the correct first 3/4 and 15/16 characters respectively, then chose an incorrect final character. These are unsuccessful full recoveries and are retained as such. The amplified runs demonstrate end-to-end operation with the expanded alphabet, not reliable unamplified recovery. The final character has a weaker timing distinction because an incorrect final byte also traverses every preceding byte. Repeated trials across independent secrets and sessions are needed to estimate success rates.

Raw CSV measurements and summaries are stored in each result directory. No model has been trained by these verification runs.

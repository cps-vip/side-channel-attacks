# V2 held-out recovery ablations

Checker: `trie`; password split: `{'train': 6, 'validation': 2, 'test': 1}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| trie | model | fixed | 1/1 (100.0%) | 144,001 | 1.0 | 0.012 |
| trie | model | full | 0/1 (0.0%) | 144,000 | 0.0 | 0.017 |
| trie | median | fixed | 0/1 (0.0%) | 144,001 | 1.0 | 0.019 |
| trie | median | full | 0/1 (0.0%) | 144,000 | 0.0 | 0.015 |
| control | model | fixed | 0/1 (0.0%) | 144,001 | 1.0 | 0.010 |
| control | model | full | 0/1 (0.0%) | 144,000 | 0.0 | 0.033 |
| control | median | fixed | 0/1 (0.0%) | 144,001 | 1.0 | 0.017 |
| control | median | full | 0/1 (0.0%) | 144,000 | 0.0 | 0.013 |

## Interpretation

- Password length and candidate alphabet are known.
- All models use timing-derived inputs; secrets label/score experiments only.
- Every ablation has identical per-password timing/warmup and verification caps.
- Actual calls differ and are reported; enumeration is separately identified.
- Beam scores and detector outputs are not calibrated confidence probabilities.
- Library/trie modes use the fixed-byte negative control, not a matched-cost control.
- Staged mode compares two-character SHA-256 components and uses a full-stage-work control.
- Staged component hashing is deliberately flawed authentication architecture, not password storage advice.
- Collection blocks on one machine do not establish day/machine generalization.
- TSC ticks are reference ticks, not actual core cycles.

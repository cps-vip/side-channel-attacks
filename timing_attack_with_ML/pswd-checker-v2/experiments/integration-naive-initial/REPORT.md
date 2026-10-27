# V2 held-out recovery ablations

Checker: `naive`; password split: `{'train': 12, 'validation': 3, 'test': 3}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| naive | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.070 |
| naive | model | verify | 3/3 (100.0%) | 1,872,014 | 14.3 | 0.058 |
| naive | model | adaptive | 2/3 (66.7%) | 1,200,027 | 26.7 | 0.044 |
| naive | model | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.097 |
| naive | model | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.096 |
| naive | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.135 |
| naive | median | verify | 1/3 (33.3%) | 1,872,028 | 27.7 | 0.048 |
| naive | median | adaptive | 2/3 (66.7%) | 1,872,022 | 21.7 | 0.079 |
| naive | median | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.092 |
| naive | median | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.079 |
| control | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.078 |
| control | model | verify | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.078 |
| control | model | adaptive | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.067 |
| control | model | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.124 |
| control | model | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.104 |
| control | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.137 |
| control | median | verify | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.067 |
| control | median | adaptive | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.063 |
| control | median | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.148 |
| control | median | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.116 |

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

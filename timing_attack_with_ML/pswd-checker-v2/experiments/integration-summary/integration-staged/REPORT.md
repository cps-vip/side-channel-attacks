# V2 held-out recovery ablations

Checker: `staged`; password split: `{'train': 6, 'validation': 2, 'test': 1}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| staged | model | fixed | 0/1 (0.0%) | 289 | 1.0 | 0.043 |
| staged | model | verify | 1/1 (100.0%) | 156 | 12.0 | 0.011 |
| staged | model | adaptive | 1/1 (100.0%) | 92 | 12.0 | 0.005 |
| staged | model | beam | 1/1 (100.0%) | 154 | 10.0 | 0.023 |
| staged | model | full | 1/1 (100.0%) | 147 | 3.0 | 0.020 |
| staged | median | fixed | 0/1 (0.0%) | 289 | 1.0 | 0.030 |
| staged | median | verify | 1/1 (100.0%) | 158 | 14.0 | 0.029 |
| staged | median | adaptive | 1/1 (100.0%) | 85 | 5.0 | 0.006 |
| staged | median | beam | 1/1 (100.0%) | 156 | 12.0 | 0.019 |
| staged | median | full | 1/1 (100.0%) | 150 | 6.0 | 0.017 |
| control | model | fixed | 0/1 (0.0%) | 289 | 1.0 | 0.022 |
| control | model | verify | 0/1 (0.0%) | 160 | 16.0 | 0.017 |
| control | model | adaptive | 0/1 (0.0%) | 160 | 16.0 | 0.027 |
| control | model | beam | 0/1 (0.0%) | 192 | 48.0 | 0.015 |
| control | model | full | 1/1 (100.0%) | 183 | 39.0 | 0.019 |
| control | median | fixed | 0/1 (0.0%) | 289 | 1.0 | 0.017 |
| control | median | verify | 0/1 (0.0%) | 160 | 16.0 | 0.009 |
| control | median | adaptive | 0/1 (0.0%) | 160 | 16.0 | 0.033 |
| control | median | beam | 0/1 (0.0%) | 192 | 48.0 | 0.018 |
| control | median | full | 0/1 (0.0%) | 192 | 48.0 | 0.017 |

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

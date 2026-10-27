# V2 held-out recovery ablations

Checker: `naive`; password split: `{'train': 12, 'validation': 3, 'test': 3}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| naive | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.154 |
| naive | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.149 |
| control | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.188 |
| control | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.160 |

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

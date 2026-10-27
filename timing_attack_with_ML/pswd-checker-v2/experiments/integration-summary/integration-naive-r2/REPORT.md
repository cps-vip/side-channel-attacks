# V2 held-out recovery ablations

Checker: `naive`; password split: `{'train': 12, 'validation': 3, 'test': 3}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| naive | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.185 |
| naive | model | verify | 1/3 (33.3%) | 1,872,030 | 30.3 | 0.123 |
| naive | model | adaptive | 3/3 (100.0%) | 1,392,022 | 22.3 | 0.191 |
| naive | model | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.261 |
| naive | model | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.222 |
| naive | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.209 |
| naive | median | verify | 1/3 (33.3%) | 1,872,025 | 25.3 | 0.137 |
| naive | median | adaptive | 1/3 (33.3%) | 1,584,025 | 24.7 | 0.161 |
| naive | median | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.241 |
| naive | median | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.178 |
| control | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.170 |
| control | model | verify | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.173 |
| control | model | adaptive | 0/3 (0.0%) | 1,776,036 | 36.0 | 0.206 |
| control | model | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.281 |
| control | model | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.246 |
| control | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.150 |
| control | median | verify | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.199 |
| control | median | adaptive | 0/3 (0.0%) | 1,872,036 | 36.0 | 0.198 |
| control | median | beam | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.278 |
| control | median | full | 0/3 (0.0%) | 2,340,000 | 0.0 | 0.203 |

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

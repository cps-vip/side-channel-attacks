# V2 held-out recovery ablations

Checker: `naive`; password split: `{'train': 182, 'validation': 39, 'test': 39}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| naive | model | fixed | 24/39 (61.5%) | 9,000,001 | 1.0 | 0.235 |
| naive | model | verify | 25/39 (64.1%) | 8,100,025 | 24.9 | 0.219 |
| naive | model | adaptive | 32/39 (82.1%) | 3,951,713 | 21.0 | 0.125 |
| naive | model | beam | 0/39 (0.0%) | 9,000,000 | 0.0 | 0.266 |
| naive | model | full | 1/39 (2.6%) | 8,997,231 | 0.7 | 0.272 |
| naive | median | fixed | 3/39 (7.7%) | 9,000,001 | 1.0 | 0.234 |
| naive | median | verify | 22/39 (56.4%) | 8,100,028 | 27.7 | 0.215 |
| naive | median | adaptive | 24/39 (61.5%) | 4,970,794 | 24.8 | 0.169 |
| naive | median | beam | 0/39 (0.0%) | 9,000,000 | 0.0 | 0.256 |
| naive | median | full | 1/39 (2.6%) | 8,997,231 | 0.6 | 0.251 |
| control | model | fixed | 0/39 (0.0%) | 9,000,001 | 1.0 | 0.359 |
| control | model | verify | 0/39 (0.0%) | 8,100,036 | 36.0 | 0.316 |
| control | model | adaptive | 0/39 (0.0%) | 8,044,651 | 36.0 | 0.359 |
| control | model | beam | 0/39 (0.0%) | 9,000,000 | 0.0 | 0.383 |
| control | model | full | 0/39 (0.0%) | 7,379,077 | 0.0 | 0.327 |
| control | median | fixed | 0/39 (0.0%) | 9,000,001 | 1.0 | 0.334 |
| control | median | verify | 0/39 (0.0%) | 8,100,036 | 36.0 | 0.311 |
| control | median | adaptive | 0/39 (0.0%) | 8,072,344 | 36.0 | 0.364 |
| control | median | beam | 0/39 (0.0%) | 9,000,000 | 0.0 | 0.399 |
| control | median | full | 0/39 (0.0%) | 7,076,308 | 0.0 | 0.303 |

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

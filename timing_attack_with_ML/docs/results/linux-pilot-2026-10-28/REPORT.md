# V2 held-out recovery ablations

Backend: `linux-x86_64`; checker: `naive`; password split: `{'train': 12, 'validation': 3, 'test': 3}`.

| Checker | Method | Ablation | Recovered | Mean checker calls | Mean verification calls | Mean seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| naive | model | fixed | 3/3 (100.0%) | 2,340,001 | 1.0 | 0.030 |
| naive | median | fixed | 2/3 (66.7%) | 2,340,001 | 1.0 | 0.029 |
| control | model | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.031 |
| control | median | fixed | 0/3 (0.0%) | 2,340,001 | 1.0 | 0.030 |

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
- Linux thread_cpu_ns is thread CPU time in nanoseconds, not hardware cycles.
- Batch repetitions change the observation model; correlated calls are not independent samples.
- This small pilot verifies integration, not a reliable recovery rate or proof of constant time.

# V2 integration verification

These are development/integration checks, not a final performance study. V1 was preserved. The v2 naive pilot has only three test passwords (lengths 4–6, full 36-symbol alphabet); staged/library/trie smoke checks each have one test password and alphabet `ab01`.

## Implemented and checked

- Adaptive sampling thresholds selected using validation snapshots.
- 42-feature ranker and separately trained wrong-prefix detector.
- Beam search, a bounded deferred-prefix reserve and backtracking.
- Detector checks at partial sample checkpoints, including an early-pruning regression test.
- Final-character/component acceptance queries available to both methods, separately logged and charged.
- Identical per-password timing/warmup and verification caps across ablations.
- Optional basic18 feature ablation with the detector frozen; trained before the final pilot test was evaluated.
- Native naive, library, trie and staged SHA-256 checkers, with exact-match tests for all lengths 4–16.
- 14 passing v2 tests, including no-test-feature-read training tests, hard budgets, simulated ambiguity and backtracking.
- Exported training bundle successfully trained without the DLL/native wrapper. Notebook code cells compile; no actual Colab service run was performed.
- Independent audit of 108 current recovery runs: compressed raw checksums, actual timed/warmup/verification counts, call caps and accepted guesses match. See [audit.json](audit.json).

## Full-alphabet naive pilot: every ablation

| Checker | Ranking method | Ablation | Recovered | Mean checker calls |
| --- | --- | --- | ---: | ---: |
| naive | model | fixed | 0/3 | 2,340,001 |
| naive | model | verify | 1/3 | 1,872,030 |
| naive | model | adaptive | 3/3 | 1,392,022 |
| naive | model | beam | 0/3 | 2,340,000 |
| naive | model | full | 0/3 | 2,340,000 |
| naive | median | fixed | 0/3 | 2,340,001 |
| naive | median | verify | 1/3 | 1,872,025 |
| naive | median | adaptive | 1/3 | 1,584,025 |
| naive | median | beam | 0/3 | 2,340,000 |
| naive | median | full | 0/3 | 2,340,000 |
| control | model | fixed | 0/3 | 2,340,001 |
| control | model | verify | 0/3 | 1,872,036 |
| control | model | adaptive | 0/3 | 1,776,036 |
| control | model | beam | 0/3 | 2,340,000 |
| control | model | full | 0/3 | 2,340,000 |
| control | median | fixed | 0/3 | 2,340,001 |
| control | median | verify | 0/3 | 1,872,036 |
| control | median | adaptive | 0/3 | 1,872,036 |
| control | median | beam | 0/3 | 2,340,000 |
| control | median | full | 0/3 | 2,340,000 |

Beam/full configurations exhausted their budgets in this small naive pilot. These failures were retained; no budgets were increased to turn them into successes. More sophisticated search is not automatically better under the same cap. Recovery and sample thresholds require a larger validation study before making improvement claims.

## Checker smoke checks and provenance

- [Naive full-alphabet pilot](integration-naive-r2/REPORT.md).
- [Basic18 feature ablation, fixed search](integration-naive-r2-basic18/REPORT.md).
- [Staged SHA-256 pilot](integration-staged/REPORT.md).
- [Library comparator pilot](integration-library/REPORT.md).
- [Trie lookup pilot](integration-trie/REPORT.md).

The tiny staged-control cohort produced one successful model/full recovery using acceptance queries. Small alphabets and final-unit enumeration permit chance recovery even without a timing signal. This is not evidence that SHA-256 or the full-work control was broken. Verification-assisted success must be distinguished from timing-only success.

The first naive integration exposed late wrong-prefix rejection consuming maximum samples before pruning. Its original source, manifest and results remain under `../integration-naive-initial`. The fix moved detector checks to sampling checkpoints and added a regression test. The subsequent naive pilot used fresh excluded passwords; it was not a retuned final test. No rank weights or thresholds were chosen from its test outcomes.

Current pilot manifests, report/model fingerprints and raw data checksums are preserved. Bulk data/raw recovery files remain under `datasets/` and `research_results/` and are excluded from Git. This folder contains small review artifacts only; no data has been uploaded.

V1 source/DLL, the `cmd-run-01` model and its dataset manifest were checked against their saved fingerprints and remain unchanged.

## Next experiment

Use the commands in [the v2 README](../../README.md) for a fresh 260-password study (182/39/39 split), with separately recorded machine/load/thermal conditions. Default v2 settings use 6–24 samples, unlike the 4–12-sample integration pilot. V2 automatically excludes passwords from existing first-level v1/v2 dataset manifests. Predeclare feature/search comparisons and keep a fresh final test set.

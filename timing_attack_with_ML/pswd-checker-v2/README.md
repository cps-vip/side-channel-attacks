# Password timing research v2

V2 implements adaptive sampling, budgeted beam search and backtracking,
supervised wrong-prefix detection, richer timing features, and final-unit
verification for both model and median ranking. V1 remains frozen in
`../pswd-checker-v1`. No GPU or third-party Python packages are required.

Completed integration checks, including unsuccessful ablations and limitations,
are recorded in [experiments/integration-summary](experiments/integration-summary/README.md).
These pilots do not establish that v2 improves on v1.

## Run in Command Prompt

From the repository root, enter the version folder using the commands below.

Collection and fresh recovery require Windows 10/11 x64, RDTSCP/invariant TSC,
and the native DLL. Training uses portable Python. Run commands individually:

```cmd
cd timing_attack_with_ML\pswd-checker-v2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build_native.ps1"
python -m unittest -v
```

Small integration check, with the full 36-symbol alphabet and lengths 4–6:

```cmd
python research_pipeline.py collect --output datasets/my-pilot --passwords 18 --min-length 4 --max-length 6 --sessions 2 --min-samples 4 --max-samples 12 --cpu 0
python research_pipeline.py train --dataset datasets/my-pilot --output models/my-pilot.json --epochs 10
python research_pipeline.py evaluate --dataset datasets/my-pilot --model models/my-pilot.json --output research_results/my-pilot
notepad "research_results\my-pilot\REPORT.md"
```

This pilot has only three held-out passwords: it verifies integration, not
general recovery performance. A larger study with the exact 70/15/15 split:

```cmd
python research_pipeline.py collect --output datasets/my-v2-study --passwords 260 --sessions 2 --min-samples 6 --max-samples 24 --cpu 0 --notes "Record actual load, power plan, thermals and virtualization"
python research_pipeline.py train --dataset datasets/my-v2-study --output models/my-v2-study.json --epochs 20
python research_pipeline.py evaluate --dataset datasets/my-v2-study --model models/my-v2-study.json --output research_results/my-v2-study
notepad "research_results\my-v2-study\REPORT.md"
```

Use a fresh name per run. To resume collection, repeat its exact command with
`--resume`. `--limit-shards 2` deliberately stops after two new shards for a
resume check. Completed shards are checksum-verified. Source/DLL changes reject
resume/evaluation: freeze code and build before collecting. Omit `--cpu 0` if
that affinity is unavailable. V2 collection always records `work=0` and exposes
no artificial amplification option. Ten model/method ablations plus controls
make evaluation larger than v1; the collector prints a measured ETA.

## Features and supervised training

The ranker has **42 timing features**: q10/q50/q90, IQR, median absolute
deviation, same-round-centered median, and round-win frequency for each of
TSC ticks, QPC elapsed time, and thread cycle accounting, plus final-position
interactions. Group normalization uses no labels. Pairing subtracts a common
same-round offset; it is not an exact scheduling correction.

A separate logistic detector uses **14 group/context features** to score
prefix validity. Calibration deliberately includes wrong prefixes, labeled
`target=null`: no candidate behind such a prefix extends the matching secret.
Only correct-prefix groups train the character/component ranker; both group
types train the detector. Candidate bytes, character identities, secrets,
password IDs and target labels never enter the model inputs or blind recovery.

The model remains a small linear group-softmax ranker plus logistic detector;
this version does not add a neural network. Three L2 values are compared on
validation data. The detector threshold constrains validation valid-prefix
false rejection to at most 2%; zero disables pruning when useful separation
cannot be demonstrated. This is not a guarantee on new measurements.
The detector is checked at each partial sampling checkpoint, allowing flat
wrong-prefix groups to be rejected before they consume the maximum samples.

Adaptive thresholds are selected separately for model/median on validation
snapshots. A group can stop when its winner agrees with TSC winners in both
halves of the collected rounds and its score margin exceeds the selected
threshold. Selection seeks fewer samples while retaining character accuracy
within 0.5 percentage points of fixed-sample validation accuracy. Rank margins,
beam scores, and detector outputs are **not calibrated confidence estimates**.
The validation rule does not guarantee full-password accuracy under a hard
search budget.

## Ablations and fair budgets

Evaluation runs each row for **both** model and median ranking, on the selected
checker and its negative control:

| Ablation | Sampling | Search | Detector | Final unit |
| --- | --- | --- | --- | --- |
| `fixed` | Maximum samples | Greedy | Off | Timing prediction; one acceptance check |
| `verify` | Maximum samples | Greedy | Off | Enumerate units using acceptance |
| `adaptive` | Validation-tuned | Greedy | Off | Same enumeration |
| `beam` | Validation-tuned | Beam + reserve/backtracking | Off | Same enumeration |
| `full` | Validation-tuned | Beam + reserve/backtracking | On | Same enumeration |

Beam width defaults to 3 and the deferred-prefix reserve to 32. Rejected paths
can be abandoned for retained alternatives. Discarded alternatives are not
guaranteed recoverable. There is no secret-guided prefix correction.

Every ablation gets the same per-password timing+warmup cap: by default the
cost of a greedy full-sample run over all positions. The beam must fund extra
paths through saved samples, not silently receive triple the budget. A separate,
identical verification cap defaults to final candidate count times beam width.
Actual timed, warmup, verification and total calls are reported. Calls are
charged before invoking the oracle, including failed/excluded measurements.

Final-unit enumeration uses the boolean acceptance result and is available to
both methods. This is a **search procedure improvement**, not evidence that
the learned model improved. It cannot rescue an already wrong prefix. Report
timing-only and verification-assisted results separately.

Select a subset or budgets before seeing test results:

```cmd
python research_pipeline.py evaluate --dataset datasets/my-v2-study --model models/my-v2-study.json --output research_results/my-v2-short --ablations fixed,full --beam-width 3 --timing-budget 10000000 --verification-budget 108
```

Budgets are checker calls, not batches. Elapsed time, failures, exhaustion and
rejected branches are retained. Changing search parameters after observing
test outcomes makes that set development data; reserve a new final test set.

## Timing-feature ablation

To isolate the richer feature set, optionally fit an 18-quantile-feature ranker
on the same data **before reading test outcomes**, freezing the rich model's
prefix detector. Only the rank weights and its validation-tuned sampling policy
change; this is a feature ablation, not a different model architecture:

```cmd
python feature_ablation.py --dataset datasets/my-v2-study --base-model models/my-v2-study.json --output models/my-v2-basic18.json --epochs 20
python research_pipeline.py evaluate --dataset datasets/my-v2-study --model models/my-v2-basic18.json --output research_results/my-v2-basic18
```

Compare the rich/basic `fixed` rows to isolate ranking features without adaptive
sampling or verification. Predeclare the comparison rather than selecting a
winner and reporting that same test set as untouched.

## Native checker variants

Choose one per dataset with `collect --checker NAME`; use separate models:

| Name | Behavior | Candidate unit | Negative control |
| --- | --- | --- | --- |
| `naive` | Original byte-by-byte early return | One character | Fixed-byte XOR accumulation |
| `library` | MSVC/library `memcmp` | One character | Fixed-byte XOR accumulation |
| `trie` | Follow 36-way child pointers; reject missing paths | One character | Fixed-byte XOR accumulation |
| `staged` | SHA-256 each independent two-character component; reject first mismatch | Two characters, or one final odd byte | Hash/compare every component |

Library comparisons can work in blocks and provide little per-character
signal. Trie accesses and path failure are real lookup work, but do not
guarantee a stronger leak. Their controls are negative controls, not
matched-cost implementations. No success is assumed for a variant.

Staged verification performs real Windows BCrypt hashing without junk loops
or sleeps. It is deliberately flawed authentication architecture: independent
component hashes reduce search complexity and are **not a recommended password
storage scheme**. This studies stage-dependent work, not a break of SHA-256.
All secrets are synthetic and in the same process. The controls are experimental.
Inspect assembly before making compiler-level claims.

With all 36 symbols, a two-character component has 1,296 candidates. Staged
collection therefore defaults to batch 1, rather than 1,000. Start small:

```cmd
python research_pipeline.py collect --checker staged --alphabet ab01 --min-length 4 --max-length 6 --passwords 18 --sessions 1 --min-samples 4 --max-samples 8 --cpu 0 --output datasets/my-staged-pilot
python research_pipeline.py train --dataset datasets/my-staged-pilot --output models/my-staged-pilot.json --epochs 10
python research_pipeline.py evaluate --dataset datasets/my-staged-pilot --model models/my-staged-pilot.json --output research_results/my-staged-pilot
```

For library/trie pilots, change `--checker` and use fresh output names.

## Splits and unseen passwords

Whole unique passwords are assigned before collection. All snapshots, wrong
prefixes and sessions for each secret stay together. At 260 passwords spanning
all 13 lengths, counts are 182 train / 39 validation / 39 test. Session IDs are
split-specific collection blocks, not independent days/machines. Measure those
separately before claiming external generalization.

Previously used secrets from first-level v1/v2 dataset manifests are excluded
automatically. Add further exclusions with `--exclude-dataset PATH`. Exclusion
sources/checksums and password IDs are recorded. Exact regeneration depends on
those manifests as well as the seed; the complete sampled list is preserved.
Training opens only train/validation feature shards. Test features are read
only during evaluation.

## Saved files and provenance

- `manifest.json`: synthetic secrets, splits, settings, exclusions, source/DLL
  hashes, timestamps, machine metadata and shard checksums.
- `raw/*.csv.gz`: every timed batch, warmup and baseline, including candidate
  bytes, measured prefix, counters, ordering and migration signatures.
- `features/*.jsonl.gz`: labeled timing snapshots and retained sample counts.
- Model JSON: weights, validation choices, thresholds, schemas, training
  environment, source hashes and dataset fingerprint.
- Evaluation `REPORT.md`/`report.json`: ablation recovery, query counts, elapsed
  time, character/prefix metrics, budgets, uncertainty intervals and traces.
- `*-verification.csv.gz`: every acceptance query, separate from timed batches.
  `progress.json` preserves completed runs if an evaluation is interrupted.

Endpoint migration batches remain raw but are excluded from features. Equal
signatures do not prove there was no migration away and back. There is no
outlier trimming or baseline subtraction. Batch averages are correlated and
not independent measurements of each call. TSC ticks are reference ticks,
not actual core cycles. Query budgets include excluded readings.

Checkpoint writes retry brief Windows/OneDrive locks. Interrupted collection
resumes with unchanged settings/source. Preserve interrupted evaluations and
choose new output names; do not cherry-pick successful retries.

## Optional Colab and GitHub

```cmd
python research_pipeline.py export --dataset datasets/my-v2-study --output datasets/my-v2-colab.zip
```

Open `colab_train.ipynb`, upload the ZIP, train on a CPU runtime, and bring the
model back to the unchanged Windows source/DLL/dataset version for evaluation.
Raw measurements stay local. V1 models/features are incompatible with v2.

The root `.gitignore` excludes bulk data, raw research results, ZIPs and native
build outputs across versions. Publish selected reports and model JSONs with
metadata; large dataset archives should be versioned separately with checksums.
The root GitHub workflow runs v2 portable tests as well as the preserved versions.

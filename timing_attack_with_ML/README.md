# Password timing analysis with machine learning

This branch adds `timing_attack_with_ML/` to the team's existing side-channel research. It contains the original naive comparator, a preserved V1 timing-learning experiment, and a V2 pipeline with richer timing features and search ablations. The existing Rust and AES projects remain separate.

**Start here:** use the V2 pilot below to build, collect, train, and evaluate. No GPU, Colab account, or third-party Python package is required for the core pipeline. Native collection and fresh password recovery require supported Windows x64 hardware.

## Research question and scope

Can a learned combination of timing statistics recover synthetic passwords more effectively than choosing the candidate with the highest median timing?

An early-return comparison stops at the first mismatched byte. A guess with a longer correct prefix can execute more comparisons and take slightly longer. Repeated measurements help reveal this small signal amid noise. The attack tests candidate characters and extends its chosen prefix; the model ranks those measured candidates. It does not generate passwords without querying the checker.

The experiments assume a **known length and alphabet**, synthetic secrets of **4–16 lowercase ASCII letters/digits**, and local access to repeated checker calls. The native backend measures comparison batches, unlike the team's Rust/stdin request-timing approach. This is a different measurement boundary, not a controlled benchmark of C versus Rust or a remote-login attack.

## What this branch adds

| Location | Purpose |
| --- | --- |
| [naive-checker](naive-checker/README.md) | Original Python early-return comparator, command-line acceptance demo, and tests; no ML |
| [pswd-checker-v1](pswd-checker-v1/RESEARCH_WORKFLOW.md) | Native C Windows timing backend, collection pipeline, 18-feature linear ranker, median baseline, controls, saved models, and historical experiment records |
| [pswd-checker-v2](pswd-checker-v2/README.md) | 42-feature ranker, 14-feature prefix detector, adaptive sampling, final-unit verification, bounded beam/backtracking search, feature ablation, and checker variants |
| [docs/results](docs/results/README.md) | Selected saved report snapshots and provenance for the V1/V2 findings below |
| [notebook_media](notebook_media/fall_2026_model_entries/README.md) | Retrospective figures and recorded-trace animation for the notebook |
| [presentation-output](presentation-output/) | Presentation files and slide previews |
| [portable CI](../.github/workflows/timing-with-ml-tests.yml) | Repository-root workflow running tests in the three version folders |

The V1 and V2 source files/builds are independent. Their feature schemas and model files are incompatible. Historical documents may mention the original author's `VIP` directory or locally available datasets/DLLs. **This README's clone-relative paths and build instructions apply to a fresh checkout.**

## Prerequisites

| Task | Requirements |
| --- | --- |
| Original Python checker | Python 3.10+ |
| Native collection and fresh recovery | Windows 10/11 x64, 64-bit Python 3.10+, CPU exposing RDTSCP and invariant TSC |
| Native build | Visual Studio Build Tools with the **Desktop development with C++** workload, MSVC x64 compiler, and Windows SDK |
| Training from collected features | Python 3.10+, standard library, CPU; Windows or portable CPU training environment |
| Optional plots/media regeneration | Separate from the core pipeline; generation scripts may require NumPy, Matplotlib, and Pillow |

Git is needed to clone this repository. Python 3.14 was used in the original environment; other supported Python versions can produce environment-dependent differences. There is no core `pip install` step. The DLL is intentionally not committed and **must be built locally** for each native version used. macOS/Linux can run portable tests and training, but not this Windows measurement backend.

## Clone and select the branch

Run commands individually in **Windows Command Prompt**, starting in the directory where you want the repository:

```cmd
git clone --branch timing-with-ML https://github.com/cps-vip/side-channel-attacks.git
cd side-channel-attacks\timing_attack_with_ML
python --version
python -c "import struct; print('Python bits:', struct.calcsize('P') * 8)"
```

If already cloned, start at the repository root and run:

```cmd
git switch timing-with-ML
cd timing_attack_with_ML
```

Use `py -3` consistently instead of `python` if that is how Python is installed. Native runs require the bitness check to print `64`. The commands below assume this project directory, not the repository root. PowerShell is invoked only for the build script.

## 1. Understand and test the naive checker

```cmd
cd naive-checker
python naive_checker.py cabd
python naive_checker.py cabe
python -m unittest -v
cd ..
```

Expected: `cabd` is accepted and `cabe` is rejected. This confirms correctness, not timing recovery. The original comparison logic, with the optional work loop omitted, is:

```python
if len(candidate) != len(secret):
    return False
for actual, expected in zip(candidate, secret):
    if actual != expected:
        return False
return True
```

See [naive_checker.py](naive-checker/naive_checker.py) for the complete function. Its optional `work` parameter defaults to zero. The native V1 backend reproduces this early-return behavior for measured experiments.

## 2. Recommended first experiment: V2 pilot

From `timing_attack_with_ML`:

```cmd
cd pswd-checker-v2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build_native.ps1"
python -m unittest -v
python research_pipeline.py collect --output datasets/first-v2-pilot --passwords 18 --min-length 4 --max-length 6 --sessions 2 --min-samples 4 --max-samples 12 --cpu 0
python research_pipeline.py train --dataset datasets/first-v2-pilot --output models/first-v2-pilot.json --epochs 10
python research_pipeline.py evaluate --dataset datasets/first-v2-pilot --model models/first-v2-pilot.json --output research_results/first-v2-pilot
notepad "research_results\first-v2-pilot\REPORT.md"
```

The build should produce `native_windows.dll`. Collection creates a manifest and compressed measurement/feature shards. Training writes a JSON model. Evaluation writes `REPORT.md`, `report.json`, progress, raw recovery traces, and separate acceptance-query logs. It compares both ranking methods and all five V2 configurations against the selected checker and its negative control.

This pilot has only **three test passwords** and verifies integration, not a reliable recovery rate. A failed guess is a valid result. Tests may skip native checks when the DLL/platform is unavailable; skipped checks do not verify native functionality. If affinity to logical CPU 0 is unavailable, omit `--cpu 0` and record that change.

Use a **new output name** for each experiment. Do not run concurrent timing collection jobs. Collection prints a measured ETA; total runtime and recovery depend on CPU state, load, storage, and settings.

## 3. Larger V2 study

Remain in `pswd-checker-v2`, after building and passing the pilot:

```cmd
python research_pipeline.py collect --output datasets/study-v2-01 --passwords 260 --sessions 2 --min-samples 6 --max-samples 24 --cpu 0
python research_pipeline.py train --dataset datasets/study-v2-01 --output models/study-v2-01.json --epochs 20
python research_pipeline.py evaluate --dataset datasets/study-v2-01 --model models/study-v2-01.json --output research_results/study-v2-01
notepad "research_results\study-v2-01\REPORT.md"
```

Record actual hardware, OS/Python/compiler versions, affinity, power plan, background activity, thermal observations, and virtualization in your notebook or the collection command's `--notes` field. V2 collection always uses `work=0`, with no artificial timing amplification. Freeze source files and the DLL before collecting.

To resume interrupted **collection**, repeat its exact command with `--resume`. For interrupted evaluations, retain the partial results and choose a new evaluation output directory. Source/configuration/DLL changes reject resume or evaluation; collect a fresh dataset after changes rather than bypassing provenance checks.

### Optional feature ablation

Before reading test outcomes, compare 18 quantile features with the richer features on the same V2 data:

```cmd
python feature_ablation.py --dataset datasets/study-v2-01 --base-model models/study-v2-01.json --output models/study-v2-basic18.json --epochs 20
python research_pipeline.py evaluate --dataset datasets/study-v2-01 --model models/study-v2-basic18.json --output research_results/study-v2-basic18
```

The detector remains frozen; the ranker's other weights are zeroed and its validation policy is retuned. This is a feature ablation, not a new model architecture. Fresh blind evaluations use separate timing measurements; saved calibration groups provide the more direct shared-data feature comparison.

## 4. Run V1 separately

From `pswd-checker-v2`, switch to V1 and build its own DLL:

```cmd
cd ..\pswd-checker-v1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build_native.ps1"
python -m unittest -v
python native_attack.py --secret cabd --alphabet abcd --cpu 0 --work 0 --samples 400 --batch 1000 --output results/first-naive-run
python native_attack.py --secret cabd --alphabet abcd --cpu 0 --mode constant --work 0 --samples 400 --batch 1000 --output results/first-control-run
```

The native demo prints the final guess and verification result, and saves `measurements.csv`/`summary.json`. The small alphabet reproduces the original teaching setup. Omitting `--alphabet abcd` uses all 36 symbols. Demo output folders can be overwritten by repeated runs; choose fresh names.

For the V1 learning pipeline:

```cmd
python research_pipeline.py collect --output datasets/study-v1-01 --passwords 260 --sessions 2 --samples 40 --batch 1000 --work 0 --cpu 0
python research_pipeline.py train --dataset datasets/study-v1-01 --output models/study-v1-01.json --epochs 50
python research_pipeline.py evaluate --dataset datasets/study-v1-01 --model models/study-v1-01.json --output research_results/study-v1-01
notepad "research_results\study-v1-01\REPORT.md"
```

The V1 Python-only `timing_lab.py` demonstration has different defaults and can amplify timing with extra work. Do not confuse it with unamplified native runs. See [V1 workflow](pswd-checker-v1/RESEARCH_WORKFLOW.md) for advanced options and historical provenance.

## How the model and split work

The ranker learns a weighted sum of timing features and uses group-softmax loss to rank the next-character candidates. It is a small linear model, not a neural network or a model of likely human passwords. It can combine timing summaries beyond a single median, remains interpretable, and trains on a CPU. More features cannot create a leak where no useful signal exists.

- **V1:** q10/q50/q90 for TSC ticks, elapsed time, and thread cycle accounting, plus final-position interactions: 18 features.
- **V2:** adds interquartile range, median absolute deviation, same-round-centered medians, and round-win frequency: 42 ranking features. A separate logistic prefix-validity detector uses 14 features.
- Inputs exclude candidate character identity, password IDs, secret bytes, and target labels. Known length/position context and timing statistics are used.
- At 260 passwords across lengths 4–16, the split is **182 train / 39 validation / 39 test**. All measurements of one password remain in one split. Small pilots use rounded counts recorded in the manifest.
- Training fits weights on training data; validation selects L2 regularization and V2 policies. Test features are not read during training.
- Calibration supplies a true prefix to isolate a position's signal. Blind recovery builds its own prefix. Report character accuracy separately from complete-password recovery.
- Sequential collection blocks are not independent days/machines. V2 excludes prior secrets found in local dataset manifests, so exact regeneration depends on exclusion history as well as the seed.

See [V1 model](pswd-checker-v1/timing_model.py), [V2 model](pswd-checker-v2/timing_model.py), [split logic](pswd-checker-v2/splits.py), and [recovery implementation](pswd-checker-v2/recovery.py).

## V2 configurations and checker variants

| Configuration | What changes |
| --- | --- |
| `fixed` | Maximum samples, greedy ranking, final timing guess with one acceptance check |
| `verify` | Fixed samples, with final-unit acceptance enumeration |
| `adaptive` | Adaptive samples, greedy ranking, same final-unit enumeration |
| `beam` | Adaptive samples, bounded alternative prefixes/backtracking, verification |
| `full` | Beam configuration plus prefix detector |

All configurations receive the same per-password timing/warmup and verification caps. Actual call counts differ and include excluded readings. Both model and median methods receive final enumeration where enabled. It improves the search procedure and cannot fix an earlier wrong prefix. Beam/detector scores are not calibrated confidence probabilities.

`collect --checker` supports `naive`, `library`, `trie`, and `staged`. The staged experiment compares independently SHA-256-hashed two-character components; it is deliberately flawed authentication architecture, not secure password storage or a break of SHA-256. Full-alphabet stages have 1,296 candidate pairs, so start with the documented small pilot. Library/trie modes use a negative control, not a matched-cost comparison. See [V2 instructions](pswd-checker-v2/README.md) for commands and caveats.

## Saved findings, including failures

These are earlier measurements, not guaranteed fresh-checkout outcomes. Selected reports are included under [docs/results](docs/results/README.md); bulk raw datasets are not included.

| Study | Learned model | Median baseline |
| --- | ---: | ---: |
| V1 `cmd-run-01` blind recovery | 31/39 (79.5%) | 28/39 (71.8%) |
| V2 `v2-run-01` fixed | 24/39 (61.5%) | 3/39 (7.7%) |
| V2 adaptive + final verification | 32/39 (82.1%) | 24/39 (61.5%) |
| V2 beam | 0/39 | 0/39 |
| V2 full | 1/39 | 1/39 |

The native fixed-work controls recovered 0/39 in these studies. That observation is not a proof of security. V2 adaptive model calls averaged approximately 3.95 million versus 9.00 million for fixed timing-only recovery, 56.1% fewer. This compares complete configurations, including final verification. Against fixed sampling **with** verification, the reduction is about 51.2%.

Beam search exhausted its timing budget, and the detector's wrong-prefix detection was only about 13.6%, with about 2.8% valid-prefix false rejection. The best observed V2 configuration was adaptive greedy recovery with verification, not the full configuration. V1 and V2 use different datasets/settings, so their recovery rates are not a controlled version comparison. The older [natural-v1 reference](pswd-checker-v1/experiments/natural-v1/README.md) is a separate run with different results (28/39 model, 29/39 median).

## Outputs, data availability, and provenance

| Output | What to inspect |
| --- | --- |
| `datasets/<run>/manifest.json` | Synthetic secrets, split/settings, source/DLL hashes, machine metadata, exclusions, checksums |
| `datasets/<run>/raw/*.csv.gz` | Raw batches and counter readings |
| `datasets/<run>/features/*.jsonl.gz` | Derived timing features and labels |
| `models/<run>.json` | Weights, feature schema, validation selections, dataset fingerprint |
| `research_results/<run>/REPORT.md` / `report.json` | Recovery, budgets, failures, control outcomes, detailed runs |
| V2 verification CSVs | Acceptance queries, separate from timed measurements |

The `.gitignore` excludes datasets, raw result directories, temporary slide builds, archives, caches, and native binaries. Selected models and historical records are included; **a model JSON alone is not sufficient to rerun a historical evaluation**. It requires the matching complete dataset, code, and DLL fingerprint. Generate a new dataset and model together for a fresh experiment. This repository does not promise exact historical byte-for-byte dataset regeneration or guaranteed recovery rates. Request a checksummed dataset archive from the team if a historical audit is required; no hosted archive is currently specified.

TSC reference ticks, QPC elapsed time, and thread cycle accounting are different units. Repeated calls in one batch are correlated; do not treat them as independent samples. Affinity does not remove interrupts or SMT interference. Endpoint migration checks cannot rule out migration away and back. Changing model/search settings after viewing test outcomes turns that test set into development data; reserve new final-evaluation passwords.

## Optional Colab training

From the chosen version directory after collecting a complete dataset:

```cmd
python research_pipeline.py export --dataset datasets/study-v2-01 --output datasets/study-v2-colab.zip
```

This example is for V2. Open that version's `colab_train.ipynb`, use a CPU runtime, upload the exported bundle, train, and return the resulting model to the unchanged Windows experiment for fresh recovery. The archive packages training code/features; raw measurement CSVs remain local. Use V1 dataset names and the V1 notebook when training V1. Do not mix versions.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `python` not found | Install Python or use `py -3` consistently |
| Missing MSVC/toolchain | Install Build Tools with C++ workload and Windows SDK, then rerun the build |
| Missing DLL / `WinError 193` | Build the correct version's DLL; confirm x64 Windows, Python, and compiler |
| Native status 2 or 3 | Required CPU timing features unavailable; native experiment cannot run in this environment |
| Native status 5 | Affinity unavailable; select an allowed CPU or omit `--cpu 0` and record it |
| V2 native status 7 | Windows SHA-256 provider initialization failed |
| Output already exists | Choose a new run name; use `--resume` only for the exact interrupted collection |
| Source/DLL fingerprint mismatch | Keep historical artifacts intact; rebuild before collecting a new dataset |
| OneDrive/file lock | Close programs holding outputs, allow sync to finish, and retry collection with its exact resume command |
| Beam budget exhausted / wrong recovery | Valid experiment result; retain it and inspect budgets/traces rather than silently increasing the cap |
| No report after interruption | Inspect `progress.json`; retain it and use a fresh evaluation output directory |

Use `python research_pipeline.py collect --help`, `train --help`, and `evaluate --help` for version-specific options. Do not copy V2 sampling flags into V1.

## Tests and contribution workflow

The repository-root CI runs the original, V1, and V2 portable unittest suites on Linux. Native tests skip there; passing CI does not replace building and testing on Windows. The workflow nested inside this project folder is retained from the standalone layout; GitHub runs the workflow in the repository-root `.github/workflows` directory.

Before proposing a change, run the relevant tests, document settings and results including failures, and add a new result snapshot when appropriate. Keep code snippets and notebook links pinned to the reviewed commit when possible. From the repository root:

```cmd
git status
git add timing_attack_with_ML README.md .github/workflows/timing-with-ml-tests.yml
git --no-pager diff --cached --stat
git commit -m "Document setup, experiments, and timing research results"
git push -u origin timing-with-ML
```

Then open a pull request through the team's review process. Confirm the branch and staged files before committing. Preserve the existing team's README and work in other folders. No license is added here; follow the parent repository's licensing and course contribution policy.

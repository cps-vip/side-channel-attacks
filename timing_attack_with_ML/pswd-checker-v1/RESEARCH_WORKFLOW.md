# Timing research: collection, splitting, and model training

This repository implements a local synthetic password experiment. It learns
which tested character has a timing signature consistent with an additional
matching byte. It does not predict an untested password without queries.
The password length and alphabet remain known. Secrets use lowercase `a–z`
and digits `0–9`, with lengths 4–16.

## Model and research question

The trainable baseline is a linear classifier using group softmax loss. A group
contains one row per alphabet candidate and exactly one correct character.
It learns weights on 10th, 50th and 90th timing percentiles for TSC ticks,
QPC wall time and Windows thread cycle accounting. Each feature is centered
against its candidate group and scaled using timing spread. Separate interaction
features allow the final position to behave differently. These are **18 timing
features**, with no input character identity, candidate bytes, password ID,
ground-truth prefix, secret, or target label passed to the classifier.

The research question is whether learned timing features improve held-out
password recovery over selecting the highest median TSC measurement. A larger
or neural model is not assumed to improve a weak timing signal. The fixed-work
checker is a recovery negative control. Failures and absence of improvement are
valid results; amplification is always recorded explicitly.

## Split before collecting

Unique synthetic passwords are generated with a recorded seed and balanced
across the requested lengths. Whole passwords are assigned approximately
**70% training, 15% validation, 15% test**, stratified by length. All positions,
candidate measurements and repeated sessions for a password remain together.
Small strata require rounding; the manifest records actual counts. For 260
passwords spanning all 13 lengths, the exact counts are **182 / 39 / 39**.
For the 130-password default, the counts are **91 / 20 / 19**.

Sessions are separate sequential collection blocks, with distinct session IDs
for each split/round. Password order and candidate order are randomized. This
prevents a recorded session ID from crossing splits, but does **not** establish
independence across hardware, days, thermal conditions or power states. To study
day/machine generalization, collect additional datasets on separate occasions
and predeclare a separate external evaluation. Do not pool datasets and then
randomly split timing rows.

During calibration, the collector supplies the true prefix to isolate each
character's signal. Labels are attached after feature extraction. During blind
recovery, the model builds its own prefix, with no true-prefix correction and no
fallback character enumeration. Report calibration character accuracy separately
from complete-password recovery; one error can corrupt every later prediction.

## Windows collection

Only Python's standard library is needed. Build the native Windows x64 backend:

```powershell
.\build_native.ps1
python -m unittest -v
```

A small end-to-end check uses the full alphabet and all supported lengths:

```powershell
python research_pipeline.py collect --output datasets/pilot --passwords 39 --sessions 1 --samples 10 --batch 1000 --cpu 0 --notes "Pilot; record actual power plan/load here"
python research_pipeline.py train --dataset datasets/pilot --output models/pilot.json --epochs 30
python research_pipeline.py evaluate --dataset datasets/pilot --model models/pilot.json --output research_results/pilot
```

This minimum pilot has one password per length per split (13/13/13), so it is
an integration check, not a 70/15/15 performance study. For a larger natural
timing experiment with the exact intended split:

```powershell
python research_pipeline.py collect --output datasets/natural-v1 --passwords 260 --sessions 2 --samples 40 --batch 1000 --cpu 0 --notes "Record machine, power plan, thermal state, workload and virtualization"
python research_pipeline.py train --dataset datasets/natural-v1 --output models/natural-v1.json
python research_pipeline.py evaluate --dataset datasets/natural-v1 --model models/natural-v1.json --output research_results/natural-v1
```

This collects **7,488,000 candidate batch measurements**, representing
7,488,000,000 timed checker calls, plus warmups and separately recorded empty
checker baselines. There are 520 secret/session shards and 5,200 position
groups. Compressing and writing this data takes time; the collector prints a
measured ETA after each shard. Runtime depends on length, batch size, load,
storage and amplification. The full alphabet is 36 times the password length
in candidates per recovery attempt, not an enumeration of all possible secrets.

To demonstrate a stronger artificial signal, collect **a separate dataset**
with `--work 200 --batch 10`; never mix it silently with unamplified data.
CPU affinity is optional; omit `--cpu 0` if unavailable. Affinity does not
remove interrupts, scheduling noise or SMT interference. Avoid concurrent
collection jobs on this machine. Notes should describe the actual setup.

## Saved data and resuming

- `manifest.json`: synthetic secrets, stable IDs, splits, settings, timestamps,
  machine metadata, source/DLL SHA-256 hashes, feature schema and shard checksums.
  These secrets are deliberately generated lab values, not real credentials.
- `raw/*.csv.gz`: every candidate batch's three counter totals, candidate bytes,
  position, sample, mode, session, and endpoint migration signatures. Baseline
  batches have phase `baseline`; warmups are counted in the query budget but
  not saved as measurements. The CSV does not duplicate the target label;
  derive it by joining candidate index/position against the synthetic manifest.
- `features/*.jsonl.gz`: derived group features, correct-character index,
  split/session IDs, retained sample counts, and migration counts.

Unequal RDTSCP endpoint signatures exclude that batch from features, but retain
it in raw data. Equal signatures do not guarantee no migration away and back.
No other outlier trimming or baseline subtraction is performed. Batch totals
are normalized for features; repeated calls in a batch are not independent
samples. TSC ticks, thread cycle accounting, and elapsed time remain separate.

To stop deliberately after a few new shards, add `--limit-shards 3`. To resume,
repeat the exact collection command with `--resume`, without the limit.
Completed shards are checksum-verified and skipped. An interrupted shard is
repeated. Configuration/source/DLL changes reject resume. Fresh outputs never
overwrite an existing run. Training rejects an incomplete dataset.

Checkpoint writes retry brief Windows/OneDrive access errors for up to 3.15
seconds. If an evaluation is interrupted, preserve its output and use a new
evaluation output directory. For a reviewed orchestration-only code update,
`evaluate --allow-driver-change` allows **only** the driver file hash to differ
and records both source versions in the report. The native C/DLL, wrapper,
password configuration and feature/model module must still match exactly.
This flag does not automatically prove that a driver edit is harmless: review
the source diff, preserve the original driver, and do not use it to hide changes
to candidate collection or feature construction. Use a new dataset for changed
measurement or feature semantics.

## Training and evaluation

Training reads only training and validation feature shards. It tries L2 values
0, 0.001 and 0.01, chooses by validation password-macro character accuracy, then
cross-entropy, and writes a JSON model. The manifest contains synthetic secrets
for orchestration and auditing; that is not a security isolation boundary.
Neither secret fields nor labels are model inputs. Features and selected
hyperparameters are fixed before test evaluation.

Evaluation reads the untouched test feature shards, then performs **fresh blind
recovery measurements** for every test password using both model and median
ranking, on both vulnerable and fixed-work checkers. Each receives the same
sample/batch budget, with independently randomized measurement orders. Adaptive
candidate sets can differ after mistakes, so this is a recovery comparison,
not a matched fixed-candidate detector benchmark. The model is not fitted to
control data. Control recovery success is not a false-positive detection rate.

Reports include overall/per-length/final-position calibration accuracy, complete
password recovery, macro password character accuracy, checker-call budgets,
and 95% Wilson intervals across unique held-out passwords for recovery. The
intervals assume passwords are independent trials conditional on this setup;
they do not capture shared machine/session drift. Softmax values are scores,
not calibrated probabilities of password recovery. Query budgets include timed,
warmup and verification calls separately. Final verification never corrects a
guess. `REPORT.md`, `report.json`, progress and compressed raw recovery CSVs
are written to the evaluation directory.

Treat test results as final. Repeatedly changing the model after seeing test
results turns that set into another validation set; reserve new passwords and
sessions for a new final evaluation. Preserve unsuccessful runs.

## Train in Colab

Native collection and fresh blind evaluation stay on Windows. Training can run
in a standard CPU Colab runtime; a GPU and PACE/ICE are unnecessary for this
baseline. Export a portable bundle:

```powershell
python research_pipeline.py export --dataset datasets/natural-v1 --output datasets/natural-v1-colab.zip
```

Open `colab_train.ipynb` in Colab, upload that ZIP, run the cells, and download
`model.json`. The ZIP contains the training code, original manifest and all
feature shards. Large raw CSVs remain local. Bring the model back to Windows
and evaluate against the original dataset. The model's manifest fingerprint
is checked before evaluation. Colab training does not load the DLL.

## GitHub publication

Commit the Python/C sources, tests, build script, notebook, documentation and
selected JSON model/report artifacts. `.gitignore` excludes DLL/build products,
environment files, compressed exports, bulk datasets and raw research results.
Professors can rebuild the DLL from source; Linux CI skips native tests and
runs portable model/split tests. No third-party Python packages are required.

Keep large datasets outside ordinary Git history. Publish versioned archives
through a GitHub Release or a research data host; record their download links
and SHA-256 checksums in your experiment writeup. Preserve the source revision,
manifest, exact commands and raw data together. Copy a selected `REPORT.md`
and `report.json` into a committed experiment folder when ready to present.
Only publish synthetic lab datasets. This folder is not currently a Git
repository; no remote repository or publication is created by these commands.

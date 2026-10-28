# Linux timing + ML pilot

This port measures the inherited early-exit comparator on Linux x86-64. It uses
synthetic secrets, known length/alphabet, and local calls in the same process.
There are **no sleeps, busy loops, or extra per-character work** in the Linux
checker. Each observation times a batch of unchanged comparisons. This is not
an external-process or network attack, and batch calls are not independent samples.

The initial experiment compares fixed-sample ML ranking with median ranking.
Adaptive sampling, beam search, library/trie checks, and staged hashing are outside
this Linux milestone. The original Windows C backend and historical records remain.

## 1. Connect and check the machine

On your Mac:

```bash
ssh vip
```

On the server, run commands individually:

```bash
hostname
uname -srmo
lscpu
python3 --version
cc --version
taskset -pc $$
uptime
```

The October 27, 2026 preflight found `cidu-10114.ctisl.gtri.org`, Linux x86-64,
an Intel i7-14700, RDTSCP/constant TSC, Python 3.12.3, GCC 13.3, and CPUs 0–27
allowed. The native initializer also checks CPUID's invariant-TSC bit. Stop and
return the error if hardware requirements fail; do not substitute made-up counters.
No perf permissions, root access, power-plan changes, or scheduler privileges are required.

The prepared server copy for this review is:

```bash
cd /home/cgossmann3/timing-ml-linux-pilot.Xa3ai86N/pswd-checker-v2
```

This is a separate source snapshot, not an update to an existing server checkout.
If using a repository that already contains this port, instead enter its
`timing_attack_with_ML/pswd-checker-v2` directory. A new clone must select a branch
that contains `native_linux.c`; the prepared folder and GitHub checkout are
independent copies.

**Learn:** TSC reference ticks, actual core cycles, elapsed time, and scheduled
thread CPU time are different quantities. A machine can have a high-resolution
timer and still have noisy measurements.

## 2. Build and verify before collecting

For a new source copy, run:

```bash
sh build_native.sh
sh setup_linux_env.sh
. .venv/bin/activate
python3 -m unittest -v
```

The prepared server copy is already built and has its plotting environment.
For that copy, activate the environment and run the tests without rebuilding:

```bash
. .venv/bin/activate
python3 -m unittest -v
```

Expected: `native_linux.so` and `native_linux.build.json` exist. Three
`NativeLinuxTests` must actually execute and pass. The Windows native test is
expected to skip here. Passing only portable or skipped tests is insufficient.
The build records compiler arguments and source/library hashes.

`setup_linux_env.sh` installs Matplotlib only inside `.venv`. This server omits
`ensurepip`, so the script creates a venv with `--without-pip` and bootstraps pip
inside it using the maintainers' [documented get-pip method](https://pip.pypa.io/en/stable/installation/).
Dependency versions are saved in `.venv/installed-packages.txt`. Collection,
training, and evaluation themselves still use Python's standard library.

Select an allowed CPU and a fresh experiment identifier in this shell:

```bash
TIMING_CPU=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
TIMING_RUN=$(date -u +%Y%m%dT%H%M%SZ)
```

Keep the printed run identifier in your notes, or inspect the directories if you
reconnect. To read an existing run, set `TIMING_RUN` to its original identifier
rather than generating a new one. To start another experiment, generate a new one.

The same affinity is used for collection and fresh recovery. Pinning reduces
migration; it does not isolate a core from interrupts, other users, or SMT siblings.
Do not run concurrent timing jobs. Keep the same source and native build after
starting a dataset. Editing or rebuilding requires a new dataset and model.

## 3. Check natural leakage first — stop here to review

```bash
python3 diagnose_linux.py --output "diagnostics/$TIMING_RUN-a" --rounds 100 --batch 1000 --cpu "$TIMING_CPU" --seed 20261027
python3 diagnose_linux.py --output "diagnostics/$TIMING_RUN-b" --rounds 100 --batch 1000 --cpu "$TIMING_CPU" --seed 20261028
cat "diagnostics/$TIMING_RUN-a/REPORT.md"
cat "diagnostics/$TIMING_RUN-b/REPORT.md"
```

The diagnostic randomizes modes and prefix lengths, uses eight-byte guesses,
and measures the naive checker, fixed-work control, and empty-call baseline.
Each run saves `raw.csv`, `config.json`, `report.json`, `REPORT.md`, distribution
plots in SVG/PNG, and disassembly when `objdump` is available. Warmups, baseline
calls, acceptance checks, and migrated measurements are counted. Raw data keeps
migrations; only features/plots exclude them. Baseline readings are not subtracted.

Send both `REPORT.md` files, both `report.json` files, the PNGs, and output paths.
Look for repeatable prefix-dependent changes in the naive checker relative to
the control and baseline. Adjacent prefix lengths need not be distinguishable;
the last-byte mismatch and full match perform nearly the same comparisons.
Weak or inconsistent separation is a reason to inspect noise and overhead before
training, not to introduce delay or keep retrying until an attractive plot appears.

Review the exact compiled build, not only source:

```bash
objdump -d --no-show-raw-insn --disassemble=vulnerable native_linux.so
objdump -d --no-show-raw-insn --disassemble=fixed_work native_linux.so
objdump -d --no-show-raw-insn --disassemble=lab_measure native_linux.so
```

**Learn:** connect a mismatch branch to extra comparisons, then compare a
distribution of repeated timings rather than trusting a single fast/slow result.
Volatile secret reads retain the inherited laboratory comparison behavior. They
do not establish the behavior of ordinary optimized production comparisons.

## 4. After reviewing diagnostics, collect and train

Keep the same shell variables from above. If reconnecting, set `TIMING_CPU` and
use a new `TIMING_RUN` before starting a new dataset.

```bash
python3 research_pipeline.py collect --checker naive --output "datasets/$TIMING_RUN-pilot" --passwords 18 --min-length 4 --max-length 6 --sessions 2 --min-samples 4 --max-samples 12 --batch 1000 --cpu "$TIMING_CPU" --notes "Linux integration pilot; record current load and observations"
python3 research_pipeline.py train --dataset "datasets/$TIMING_RUN-pilot" --output "models/$TIMING_RUN-pilot.json" --epochs 10
```

Expected: 36 completed shards and password split **12 train / 3 validation /
3 test**. The collector prints a measured ETA. All observations, prefix groups,
and sessions for one secret stay in the same split.

**Learn during collection:** quantiles summarize a timing distribution; IQR and
MAD describe variation. Same-round features compare candidates observed near
each other. Features contain timing statistics and public position context,
not secret bytes, labels, or character identities.

**Learn during training:** the linear ranker learns weights for those features.
Training uses labeled calibration groups with known prefixes. Validation picks
regularization. Test features are not opened during training. V2 also fits a
prefix detector and sampling thresholds; neither is used in the fixed-sample
evaluation below. Calibration accuracy does not mean a blind attack can maintain
a correct prefix all the way through a password.

Linux datasets/models use schema and feature version **3** with `thread_cpu_ns`.
Windows schema **2** retains `thread_cycles`; portable training can read either
schema based on dataset metadata. Fresh native evaluation must match the dataset
backend, source fingerprints, build, and model. Do not rename Windows counters
or reuse historical Windows models for Linux measurements.

Interrupted collection can resume by repeating its **exact** command with
`--resume`. Hash/configuration/checksum mismatches require a fresh experiment;
do not bypass them. Retain partial data and failed outcomes.
Use `--resume` only for interrupted collection: invoking it on a completed dataset
updates the manifest timestamp and changes its fingerprint, invalidating models
that were trained against the earlier manifest.

## 5. Blind recovery: compare ML and median fairly

```bash
python3 research_pipeline.py evaluate --dataset "datasets/$TIMING_RUN-pilot" --model "models/$TIMING_RUN-pilot.json" --output "research_results/$TIMING_RUN-pilot" --ablations fixed --methods model,median --beam-width 1 --verification-budget 1
cat "research_results/$TIMING_RUN-pilot/REPORT.md"
```

Expected: 12 blind recovery runs: three test passwords × two ranking methods ×
two checker modes. Both methods get the same per-password timed/warmup cap and
one final acceptance check. Every batched call is charged, including warmups
and excluded endpoint migrations. Collection totals also include empty baselines.
Recovery uses its own predicted prefix; ground truth scores the result afterward.

Failures, budget exhaustion, character accuracy, complete-password recovery,
elapsed time, and query counts are retained in `report.json`, raw compressed
CSVs, verification logs, and `progress.json`. An interrupted evaluation remains
partial; choose a new output directory and retain the old one rather than
overwriting failures.

Send `REPORT.md`, `report.json`, and the dataset's `manifest.json`. Keep all raw
data, model JSON, build metadata, and source snapshot. Three held-out passwords
verify integration only. A failed attack does not prove the control is secure,
and an ML win on this tiny pilot does not establish a general improvement.
Do not tune settings against these test outcomes and then call them untouched
test data. Later studies need fresh secrets, more held-out passwords, independent
sessions, and an explicitly chosen time/query budget.

**Learn:** per-character errors compound; a wrong earlier prefix can make every
later guess uninformative. The final character may be especially difficult
because early-exit work can be identical on a mismatch and a full match.

## Optional portable training export

```bash
python3 research_pipeline.py export --dataset "datasets/$TIMING_RUN-pilot" --output "datasets/$TIMING_RUN-training.zip"
```

The archive includes portable code, manifest, and checksummed feature shards,
not native binaries or raw timing CSVs. Unzip it elsewhere and train using
`--dataset dataset`. Bring the model back to the unchanged server source/build
for fresh evaluation.

## Read the completed October 28 run

The user-run experiment is `20261028T180716Z`, separate from the earlier
`server-validation-pilot`. From the prepared server directory:

```bash
cat research_results/20261028T180716Z-pilot/REPORT.md
cat diagnostics/20261028T180716Z-a/REPORT.md
cat diagnostics/20261028T180716Z-b/REPORT.md
```

Its collection finished all 36 shards. Fixed-sample results were ML **3/3**,
median **2/3**, and control **0/3** for both methods. The median failure was the
last character of the six-character secret. Each method received the same
per-password timing/warmup cap and one final acceptance check. The raw-call audit
counted 152,352,000 collection calls and 28,080,012 evaluation calls. Both diagnostic
runs used 100 rounds, batch 1,000, CPU 0, and `work=0`; each counted 2,727,022 calls,
passed functional checks, restored affinity, and recorded zero endpoint migrations.

The [selected report and plots](../docs/results/linux-pilot-2026-10-28/README.md)
are stored in the repository's `timing_attack_with_ML/docs/results/` directory.
The prepared server snapshot only contains the V2 folder, so read its direct
report paths above there. Complete raw data, feature shards, model, build
metadata, and source remain on the server. The new pilot's secrets are disjoint
from the earlier pilot; reproduce an existing dataset from its retained files,
not just its seed, because previous-manifest exclusions affect secret selection.

Keep these runs unchanged. For the next study, predeclare a larger held-out set
and independent measurement sessions before looking at outcomes. Do not tune
against these three test passwords or add artificial work to improve recovery.

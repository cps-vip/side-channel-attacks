# Password timing analysis with machine learning

Can a model make better use of noisy timing measurements than simply choosing
the candidate with the largest median? This project tests that question using
synthetic passwords and an early-exit checker.

The model helps choose the next character from measured candidates. It learns
from timing patterns rather than password spelling. The experiments assume the
password length and alphabet are known and measure batches of local checker calls.

## Start here

- [Architecture guide](ARCHITECTURE_GUIDE.md): how the experiment, files, and models fit together.
- [Linux runbook](pswd-checker-v2/LINUX_RUNBOOK.md): staged server commands and expected outputs.
- [V2 instructions](pswd-checker-v2/README.md): Windows setup and additional experiment options.
- [Saved results](docs/results/README.md): reports, plots, and limitations.

## Project layout

| Folder | Purpose |
| --- | --- |
| `naive-checker/` | A small Python checker to understand early-exit behavior |
| `pswd-checker-v1/` | The preserved Windows experiment with an 18-feature model |
| `pswd-checker-v2/` | The current pipeline, richer model, and Linux backend |
| `docs/results/` | Selected experiment reports and plots |
| `notebook_media/`, `presentation-output/` | Figures and presentation material |

## Running it

Native measurements require Linux or Windows x86-64 with RDTSCP and invariant
TSC support, Python 3.10+, and a C compiler. Windows uses MSVC Build Tools;
Linux uses GCC or Clang. Training runs on a CPU using Python's standard library.
Linux diagnostic plots use Matplotlib, installed in a project virtual environment.

From the repository root on Linux:

```bash
cd timing_attack_with_ML/pswd-checker-v2
sh build_native.sh
sh setup_linux_env.sh
. .venv/bin/activate
python3 -m unittest -v
```

Continue with the [runbook](pswd-checker-v2/LINUX_RUNBOOK.md). It covers the two
prefix diagnostics, data collection, training, and a fair ML-versus-median test.
The Linux pilot uses the naive checker and its control, with no artificial work.

For Windows, start from the repository root in Command Prompt:

```cmd
cd timing_attack_with_ML\pswd-checker-v2
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build_native.ps1"
python -m unittest -v
```

Then use the [Windows pilot commands](pswd-checker-v2/README.md#run-in-command-prompt).
Use a branch containing this port when following the Linux instructions.

## What we have observed

In the [October 28 Linux pilot](docs/results/linux-pilot-2026-10-28/README.md),
18 passwords were split into 12 training, 3 validation, and 3 test passwords.

| Checker | ML recovered | Median recovered |
| --- | ---: | ---: |
| Early-exit checker | 3/3 | 2/3 |
| Fixed-work control | 0/3 | 0/3 |

Both methods received the same query budget and one final acceptance check.
Three test passwords are enough to check the workflow, but not to establish
that ML is generally better. The saved reports also retain unsuccessful runs.

## Keeping runs reproducible

Use a fresh output name for each experiment and keep its raw data, manifest,
model, and build metadata together. Changes to measured code or the native
library require a new dataset. Linux and Windows use different timing features,
so their models are not interchangeable.

Bulk datasets and native binaries are excluded from Git. The reports in this
repository are selected snapshots; complete raw data remains in the original
experiment directories. See the runbook for resuming interrupted collection
and the [V1 workflow](pswd-checker-v1/RESEARCH_WORKFLOW.md) for older experiments.

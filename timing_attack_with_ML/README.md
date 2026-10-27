# Password timing research

The project is separated into an original checker, a frozen v1 experiment,
and the v2 research implementation.

| Folder | Contents |
| --- | --- |
| [naive-checker](naive-checker/README.md) | Original Python early-return password comparator, extracted without changing its function body; no trained model. |
| [pswd-checker-v1](pswd-checker-v1/README.md) | Current Windows native checker, collection pipeline, timing model, Colab notebook, tests, all existing datasets and experiment results. |
| [pswd-checker-v2](pswd-checker-v2/README.md) | Adaptive sampling, budgeted beam/backtracking search, wrong-prefix detection, richer features, verification ablations, and native checker variants. |

## Run v1 in Command Prompt

```cmd
cd /d "C:\Users\alyaa\OneDrive\Desktop\Comp Sci\VIP\pswd-checker-v1"
python -m unittest -v
```

Run all previous collection, training, evaluation and build commands from this
v1 directory. Their relative dataset/model paths stay the same. Python source,
DLL bytes, trained weights, and dataset manifests were preserved during the move.
Historical metadata may mention the old absolute location.

Your most recent results are [cmd-run-01/REPORT.md](pswd-checker-v1/research_results/cmd-run-01/REPORT.md).
The full instructions are in [RESEARCH_WORKFLOW.md](pswd-checker-v1/RESEARCH_WORKFLOW.md).

## Run the original checker

```cmd
cd /d "C:\Users\alyaa\OneDrive\Desktop\Comp Sci\VIP\naive-checker"
python naive_checker.py cabd
python naive_checker.py cabe
python -m unittest -v
```

The first example accepts the synthetic secret `cabd`; the second rejects an
incorrect candidate. The checker uses no amplification by default.

Root `.gitignore` rules exclude large generated datasets, native build products,
raw research results and environment files across the version folders. GitHub
CI runs portable tests for the original checker, v1 and v2. No repository has been
published by this reorganization.

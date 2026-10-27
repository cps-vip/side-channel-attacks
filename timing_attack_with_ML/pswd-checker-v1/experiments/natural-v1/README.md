# Natural timing experiment, 2026-10-21

This is a completed local experiment using the author's Windows C password checker. It uses synthetic lowercase/digit passwords, known lengths 4–16, all 36 candidate symbols, and **no artificial amplification**.

- Unique passwords: 260, balanced at 20 per length.
- Split by whole password: **182 train / 39 validation / 39 test**.
- Collection rounds: 2; all repeats of a password stay in one split.
- Candidate batch measurements: 7,488,000; 1,000 checker calls per batch.
- Additional empty-check baseline batches: 10,400; warmup calls are separate.
- Derived position groups: 5,200; candidate feature rows: 187,200; timing features per candidate: 18.
- Collection elapsed wall time, including the resume gap: 214.9 seconds.
- Source/DLL hashes, seeds, complete settings and per-shard timestamps/checksums: [manifest.json](manifest.json).
- Selected linear group-softmax model: [../../models/natural-v1.json](../../models/natural-v1.json), L2=0.0, 50 epochs, training seed 7.

## Results

| Measure | Learned model | Median TSC baseline |
| --- | ---: | ---: |
| Held-out calibration character accuracy | 97.4% | 96.2% |
| Fresh vulnerable checker password recovery | 28/39 (71.8%) | 29/39 (74.4%) |
| Fresh fixed-work checker password recovery | 0/39 | 0/39 |

The learned model improved calibration character accuracy in this dataset but did **not** improve complete-password recovery in the fresh test. Calibration receives correct prefixes; recovery predicts its own prefixes. This single-machine result does not establish that either method is generally better or that the control is secure. See [REPORT.md](REPORT.md) for per-length/final-position metrics and recovery uncertainty, and [report.json](report.json) for every final recovery trace and query budget.

## Reproduce

From the project root, rebuild the DLL as described in the main README. To collect a new experiment rather than overwrite this one:

```powershell
python research_pipeline.py collect --output datasets/natural-replication --passwords 260 --sessions 2 --samples 40 --batch 1000 --cpu 0 --seed 20261021 --notes "Record actual machine/load/power/thermal conditions"
python research_pipeline.py train --dataset datasets/natural-replication --output models/natural-replication.json --epochs 50 --seed 7
python research_pipeline.py evaluate --dataset datasets/natural-replication --model models/natural-replication.json --output research_results/natural-replication --seed 101
```

To evaluate the existing historical dataset using the current driver, use a new output directory and append `--allow-driver-change`, for the provenance reason below. That explicit acknowledgement is unnecessary for a newly collected matching version.

## Provenance and interrupted writes

Collection initially stopped at a Windows checkpoint replacement access error and resumed from its verified checkpoint. The first full evaluation also stopped at a progress-file replacement access error. Its partial progress files are preserved here and all partial raw files remain in `research_results/natural-v1`. Those incomplete observations are not combined with the final complete evaluation.

After that failure, the driver was changed only to retry brief Windows access errors, acknowledge a reviewed driver-only revision, and report both source hashes. The original driver is preserved in [collection_driver.py](collection_driver.py), matching its manifest SHA-256. An AST comparison confirmed that only `save_json`, `evaluate`, and `main` changed; collection, timing measurement, feature loading, training, and blind recovery functions did not change. The C source, DLL, native wrapper, password configuration, and feature/model module hashes remained identical. The model and hyperparameters were **not** changed after viewing test outcomes. A fresh complete evaluation was then run with the acknowledged driver-only change; `report.json` records both source versions. This is maintenance recovery, not an untouched first execution of the test cohort.

## Dataset availability

Full raw/feature datasets are stored locally under `datasets/natural-v1` and excluded from Git. Raw compressed measurements occupy approximately 48.4 MiB. The Colab feature bundle is approximately 6.6 MiB. The ZIP bundles and local raw recovery files have not been uploaded or published. Publish a versioned dataset archive and add its URL/checksum here before claiming that a public repository contains the raw data.

The manifest and reports in this folder are small review artifacts suitable for GitHub. Synthetic secrets are deliberately recorded for auditing, and are not model inputs. No real credentials are part of the experiment.

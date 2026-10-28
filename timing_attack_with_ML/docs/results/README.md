# Saved result snapshots

The Windows entries below are unchanged copies of earlier local reports. The
Linux entries record the initial port validation and the user's subsequent run.

- [Linux V2 user-run pilot / October 28, 2026](linux-pilot-2026-10-28/README.md):
  two diagnostic runs, a complete 36-shard dataset, and held-out ML/median results;
  [generated report](linux-pilot-2026-10-28/REPORT.md),
  [machine-readable report](linux-pilot-2026-10-28/report.json).

- [Linux V2 pilot / October 27, 2026](linux-pilot-2026-10-27/README.md): native test status,
  known-prefix plots, [generated report](linux-pilot-2026-10-27/REPORT.md), and
  [machine-readable report](linux-pilot-2026-10-27/report.json).

- [pswd-checker-v1 / cmd-run-01](pswd-checker-v1-cmd-run-01/REPORT.md): [machine-readable report](pswd-checker-v1-cmd-run-01/report.json), [provenance](pswd-checker-v1-cmd-run-01/provenance.json).
- [pswd-checker-v2 / v2-run-01](pswd-checker-v2-v2-run-01/REPORT.md): [machine-readable report](pswd-checker-v2-v2-run-01/report.json), [provenance](pswd-checker-v2-v2-run-01/provenance.json).
- [pswd-checker-v2 / v2-run-01-basic18](pswd-checker-v2-v2-run-01-basic18/REPORT.md): [machine-readable report](pswd-checker-v2-v2-run-01-basic18/report.json), [provenance](pswd-checker-v2-v2-run-01-basic18/provenance.json).

The provenance files identify original run paths and SHA-256 hashes of reports, models, and dataset manifests. report.json files preserve original timestamps, environments, budgets, traces, and limitations. Raw measurements/feature shards and native binaries are not included; these summaries are not a complete historical reproduction bundle. Models alone cannot reproduce historical evaluation without matching datasets and source/DLL hashes.

The existing natural-v1 reference and V2 integration pilots are separate experiments with their own outcomes; do not substitute them for these runs.

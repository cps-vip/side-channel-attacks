# Linux known-prefix diagnostic

Host: `cidu-10114.ctisl.gtri.org`; CPU: `0`; batch: `1000`; rounds: `100`.
Functional checks passed. Original affinity restored: **True**.
Total checker calls: **2,727,022**, including warmup, empty baseline and checks.
Endpoint-migration calls retained in raw data but excluded from features: **0**.

![Known-prefix distributions](distributions.svg)

## Read before training

- Every guess has eight bytes. Prefix 8 is the complete correct guess; prefix 7 mismatches at the last byte.
- Each plotted point summarizes one batch, not 1,000 independent observations.
- Compare repeated prefix-dependent changes in the naive checker against the control and empty baseline.
- TSC reference ticks, wall time and thread CPU time measure different intervals and include different overhead.
- Volatile secret reads preserve the inherited lab comparator; this is not a claim about ordinary production comparisons.
- Equal endpoint signatures cannot exclude migration away and back. Affinity does not eliminate interrupts or SMT interference.
- Repeat with a fresh directory and seed. Weak or inconsistent separation is a result to investigate, not a reason to add delay.
- Review compiled `vulnerable`, `fixed_work`, and `lab_measure`: early exit, fixed loop, repeated native calls, and no added workload.
- Proceed to the integration pilot only after reviewing both diagnostic runs.

Assembly: `disassembly.txt`.
Return `REPORT.md`, `report.json`, `distributions.png`, and both runs’ output paths. Keep `raw.csv` and `config.json`.

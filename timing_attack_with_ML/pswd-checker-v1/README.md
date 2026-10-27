# Password timing side-channel lab

**Dataset collection, train/validation/test splits, a trainable timing model,
and Colab training are now available.** Start with
[RESEARCH_WORKFLOW.md](RESEARCH_WORKFLOW.md). The model learns to rank queried
characters from local timing measurements; it does not predict passwords
without querying the checker.

A completed unamplified reference experiment collected 7,488,000 candidate
batch measurements with a 182/39/39 password split. The model recovered 28/39
held-out passwords versus 29/39 for median ranking, and both recovered 0/39
against the fixed-work control. See the [experiment record](experiments/natural-v1/README.md)
for data provenance, limitations, reports and the saved model.

**For the native Windows counter implementation, start with [NATIVE_MEASUREMENTS.md](NATIVE_MEASUREMENTS.md).** It records TSC ticks, Windows thread cycle accounting, and QPC elapsed time in compiled C. The Python-only implementation below remains a portable baseline.

This local class experiment deliberately compares a synthetic password one byte at a time and returns at the first mismatch. Longer correct prefixes execute more work. The attacker receives only a callable checker, the alphabet, and the password length. It tests candidate characters in randomized order, collects repeated timing distributions, and extends the prefix with the largest median time. The final guess is verified through the checker.

## Run

From this folder, with Python 3.10 or newer:

```powershell
python -m unittest -v
python timing_lab.py --output results/demo
python timing_lab.py --mode constant --output results/control
python timing_lab.py --work 0 --samples 1000 --batch 100 --output results/natural
```

The default password is the **synthetic** value `cabd`. Passwords must have **4–16 characters**, each a lowercase ASCII letter (`a–z`) or digit (`0–9`). Both runners default to all 36 characters as the search alphabet. Use `--alphabet abcd` to reproduce older four-symbol experiments. A custom alphabet must contain 2–36 unique supported characters and include every character in the secret.

Default `--work 2000` explicitly amplifies the per-character leak for teaching; there are no sleeps. `--work 0` removes this amplification. Recovery is not guaranteed, particularly with no amplification. Failed guesses are experiment results, not evidence of a secure implementation. A greedy wrong choice propagates to later positions. The attack assumes a known length and alphabet, so this is a constrained proof of concept.

For an expanded-alphabet native demo, after rebuilding the DLL:

```powershell
python native_attack.py --secret a0z9b1y8c2x7d3w6 --cpu 0 --work 200 --samples 100 --batch 10 --output results/expanded-demo
```

See [ALPHANUMERIC_VERIFICATION.md](ALPHANUMERIC_VERIFICATION.md) for observed results, including unsuccessful unamplified runs.

Each output directory receives raw `measurements.csv` and `summary.json`. Reusing a directory overwrites those files. Use distinct directories for each run. Timing fields are **nanoseconds per call**, not CPU cycle counts. Batch samples are correlated measurements and must not be treated as independent individual calls.

The control hashes each input and uses `hmac.compare_digest` on fixed-length digests. This removes the explicit prefix-dependent comparison loop; it does not make the entire Python runtime or hashing constant-time for arbitrary input lengths. This is a comparison experiment, not a production authentication design. Real authentication also needs a dedicated password hashing scheme.

## Research plan

1. Establish correctness and amplified recovery. Repeat with multiple random synthetic secrets and ordering seeds. Report success rate and total queries, not just one successful run.
2. Compare vulnerable and control distributions for **the same fixed candidate set**, including known correct-prefix lengths. The adaptive attack chooses different candidates after mistakes, so its CSV alone is not a matched detector benchmark.
3. Remove amplification. Vary batch size and sample count independently. Save every run, including failures. Plot distributions and uncertainty, not just averages. More samples do not remove systematic bias.
4. Record hardware, OS, power settings, thermal conditions, load, core placement, and virtualization configuration. Randomize candidate order to reduce drift bias. Warm up before collecting data.
5. On supported Linux systems, `--cpu N` requests logical CPU affinity. Identify the core's type independently before selecting it. This option does not identify performance/efficiency cores, and guest CPU affinity does not establish physical host-core placement. No macOS core-type control is implemented here.
6. Both elapsed and thread CPU time are recorded. Their difference can flag scheduling interference but is **not** a context-switch count or exact correction. Use OS profiling/counters in a later native measurement backend to observe switches and migration. Record unavailable counters as unavailable.
7. If the assignment requires mperf/hardware cycles, retain this lab as a baseline and replace the timing backend with a validated native implementation. WSL2/VM counter availability needs testing on the actual setup. Hayden's WSL2 advice is a starting hypothesis, not a result measured here.

## Where machine learning fits

Distribution ranking is the baseline, not a trained ML model. A timing leak reveals information about tested candidates; it does not directly reveal an untested password or eliminate search assumptions.

`research_pipeline.py` now collects labeled calibration groups from known synthetic secrets and trains a timing classifier using `timing_model.py`. The label is the correct next-character index within each candidate group. Whole passwords and their collection blocks stay in one split; no random-row split is used. The model is selected on validation data and evaluated using held-out calibration accuracy and fresh blind password recovery against median ranking and the fixed-work control. See [RESEARCH_WORKFLOW.md](RESEARCH_WORKFLOW.md) for the split policy, limitations and Colab workflow. A beam search could retain multiple likely prefixes in a future experiment.

The project provides the vulnerable checker, statistical baseline, mitigation comparison, raw collection, and a trainable timing model. It does not provide mperf integration, automatic core-type selection, context-switch counters, calibrated model confidence, or a matched fixed-candidate detection benchmark.

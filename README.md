# Side-Channel Attack Research — VIP Device Security Team

**Authors:** Estelle Jung, Carter Pattison, Aly Aadil Salewala, Piper Wright 
**Program:** Cyber-Physical Systems VIP, Georgia Tech  
**Focus:** Side-channel attack vectors targeting cryptographic implementations

---

## Current Status

**Timing Attack on Password Authentication** — *Implemented in Rust (`main.rs`)*  
A vulnerable password checker with an early-exit comparison is exploited by measuring per-character execution time to recover the secret. This is a demo for side-channel attacks.

**Correlation Power Analysis (CPA) on AES-128** - *Implemented in Python (AES-128-CPA.py)*
Software simulation of CPA targeting AES-128 using Hamming weight power models with Gaussian noise. Demonstrates key recovery through statistical correlation analysis of simulated power traces.

---

## Next Steps

### 1. Refine the Password Timing Attack (TOP PRIORITY)

- Get the timing attack compiling to a standalone binary
- Write an external harness script that runs the binary repeatedly and collects timing data
  - Could be a shell script, Python script, or Perl script
  - Main tradeoff: a compiled binary must be reverse-engineered to inspect, whereas a Python file is human-readable
- Improve statistical robustness (multiple samples per candidate, median filtering, etc.)

### 2. Timing Attack on AES-128

- Add visualizations for AES-128 CPA (Carter Pattison)
- Develop timing-attack vulnerable AES-128 implementation (Aly Aadil)
- Implement a timing side-channel attack against an AES-128 implementation
- Attack should use only command-line observable timing (no API-level access)
- Language: prefer a compiled language (Rust** or C++) for tighter timing control
  - Python is an option, but be aware of garbage collector interference with measurements
- Demonstrate key (or partial key) recovery from timing leakage

### 3. Physical Power Analysis — Hardware Selection

Evaluate hardware platforms for performing physical power analysis:

- **ChipWhisperer** - more handholding
- **Raspberry Pi**
- **STM32**
- Investigate whether ChipWhisperer can handle RF signal capture/analysis

### 4. CPA DPA Trajectory (Long-Term Roadmap)

- Start with **CPA** on real hardware (extending the Python simulation already in progress)
- Iterate: crack a target → add countermeasures → crack again
- Progress to **DPA** when CPA is no longer sufficient - this is the multi-semester stretch goal


---

## Tools & Stack

- **Rust** — timing attack implementation
- **Python** — CPA simulation, power trace analysis
- **NumPy, Matplotlib** — statistical analysis & visualization
- Hardware TBD (ChipWhisperer / RPi / STM32)

## Password timing analysis with machine learning

The `timing-with-ML` branch adds a separate C/Python research pipeline under
[`timing_attack_with_ML`](timing_attack_with_ML/README.md). Start with that README
for Windows and Linux prerequisites, native builds, naive/V1/V2 experiments, CPU model
training, saved results, limitations, and troubleshooting. Existing Rust and
AES projects above remain separate.

### Linux: start here

The Linux V2 pilot measures a native C early-exit checker with **no sleeps or
deliberate per-character workload**. It compares a learned timing ranker with
median timing and a fixed-work control. Measurements are batches of local,
same-process calls; this does not establish an external-process or network attack.

Requirements: Linux x86-64, RDTSCP/invariant TSC, Python 3.10+, a C compiler,
and `curl`/network access to install diagnostic plotting dependencies in a local
virtual environment. No GPU, root privileges, or `perf` access is needed.

From the repository root, run commands individually and stop if a command fails:

```bash
cd timing_attack_with_ML/pswd-checker-v2
sh build_native.sh
sh setup_linux_env.sh
. .venv/bin/activate
python3 -m unittest -v
TIMING_CPU=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
TIMING_RUN=$(date -u +%Y%m%dT%H%M%SZ)
python3 diagnose_linux.py --output "diagnostics/$TIMING_RUN-a" --cpu "$TIMING_CPU" --seed 20261027
python3 diagnose_linux.py --output "diagnostics/$TIMING_RUN-b" --cpu "$TIMING_CPU" --seed 20261028
```

Defaults are 100 diagnostic rounds and 1,000 unchanged comparisons per batch.
Confirm that all three Linux native tests execute; the Windows-native test skips
on Linux. Review both diagnostic plots before collecting a dataset. Follow the
[Linux runbook](timing_attack_with_ML/pswd-checker-v2/LINUX_RUNBOOK.md) for server
paths, the collect/train/evaluate commands, expected outputs, and recovery from
interruption. A prepared server copy already exists; use the runbook's activation
instructions there rather than rebuilding an experiment that has collected data.

The [October 28 user-run pilot](timing_attack_with_ML/docs/results/linux-pilot-2026-10-28/README.md)
completed 36 shards with 12 training, 3 validation, and 3 test passwords. Fixed-sample
ML recovered 3/3 test secrets, median ranking recovered 2/3, and each method
recovered 0/3 on the control. These are integration results on three held-out
secrets, not a reliable recovery-rate estimate or proof of constant-time execution.
Source, dataset, and native-library fingerprints must match; train new Linux
models rather than reusing Windows models or changing counter units.

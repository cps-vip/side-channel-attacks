# Side-Channel Attack Research — VIP Device Security Team

**Program:** Cyber-Physical Systems VIP, Georgia Tech  
**Original authors:** Estelle Jung, Carter Pattison, Aly Aadil Salewala, Piper Wright

We study how implementation details can reveal secrets through timing and other
side channels. The current ML experiment compares a learned timing model with
median timing to recover synthetic passwords from an early-exit checker.

## Where to start

| Project | What it contains |
| --- | --- |
| [Timing with ML](timing_attack_with_ML/README.md) | The Windows/Linux password experiment, training pipeline, and results |
| [Rust timing example](timing_attack_rust2/) | Earlier password timing work using a separate process |
| [AES examples](AES-128-CPA-Attack/) | Simulated correlation power analysis and AES timing experiments |

For an explanation of the ML experiment, read the
[architecture guide](timing_attack_with_ML/ARCHITECTURE_GUIDE.md).
For server commands, use the [Linux runbook](timing_attack_with_ML/pswd-checker-v2/LINUX_RUNBOOK.md).

## Linux setup

From the repository root on a supported Linux x86-64 machine:

```bash
cd timing_attack_with_ML/pswd-checker-v2
sh build_native.sh
sh setup_linux_env.sh
. .venv/bin/activate
python3 -m unittest -v
```

Then follow the runbook to check timing distributions, collect data, train, and
evaluate. If using the prepared server copy, follow its activation instructions
before rebuilding anything. Windows setup is in the [V2 instructions](timing_attack_with_ML/pswd-checker-v2/README.md).

## Latest Linux pilot

The [October 28 run](timing_attack_with_ML/docs/results/linux-pilot-2026-10-28/README.md)
used no deliberately added per-character work. ML recovered 3/3 test passwords,
median timing recovered 2/3, and both recovered 0/3 against the fixed-work control.
This small pilot shows the pipeline works; a larger study is needed to compare
recovery rates reliably. Measurements used batches of local function calls.

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
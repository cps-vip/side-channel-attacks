# Run the password timing lab on Windows

## 1. Open the project

Open PowerShell and run:

```powershell
Set-Location -LiteralPath 'C:\Users\alyaa\OneDrive\Desktop\Comp Sci\VIP\pswd-checker-v1'
python --version
```

The native DLL is already compiled in this folder. Python 3.14 and MSVC x64 Build Tools were available when the project was tested. Use Windows x64 with a processor exposing RDTSCP and invariant TSC. This DLL is not a Mac executable.

## 2. Run the vulnerable checker attack

```powershell
python native_attack.py --cpu 0 --samples 400 --batch 1000 --output results/my-vulnerable-run
```

This uses the synthetic password `cabd` and the default 36-symbol alphabet `abcdefghijklmnopqrstuvwxyz0123456789`. Passwords may contain 4–16 lowercase letters or digits. Add `--alphabet abcd` to reproduce the original smaller search space. With the new default, it tests 400 timing batches for each of 36 candidates at each position; every batch contains 1,000 calls. No artificial amplification is enabled. The attacker selects the largest median TSC measurement at each position and verifies the final guess.

The earlier saved run printed:

```text
Position 0: 'c'; median 11.51 tsc_ticks/call
Position 1: 'a'; median 16.33 tsc_ticks/call
Position 2: 'b'; median 18.85 tsc_ticks/call
Position 3: 'd'; median 18.73 tsc_ticks/call
Guess: cabd; verified: True
```

Your timings and guesses can differ because the attack is statistical. `Position 0` is the first character. `verified: True` means the guessed password was accepted; `False` means the attempt failed.

## 3. Run the fixed-work comparison

```powershell
python native_attack.py --cpu 0 --mode constant --samples 400 --batch 1000 --output results/my-control-run
```

This removes the explicit early-return behavior for equal-length candidates. The earlier run guessed `adcc` and failed verification. A failed recovery is expected to be more likely on this comparison, but one failure does not prove security.

## 4. Inspect output

Each output directory contains:

- `measurements.csv`: raw batch totals for elapsed nanoseconds, TSC ticks, thread cycle accounting, and endpoint migration signatures.
- `summary.json`: configuration, ranked medians, final guess, verification result, and empty-check baseline samples.

Use a fresh output name for every run; reusing the name overwrites that run's files. Output paths must remain inside `VIP`. To compare elapsed-time rankings, add `--metric wall_ns`. To compare Windows thread cycle accounting, use `--metric thread_cycles`. Keep the units separate.

## 5. Check correctness or rebuild

```powershell
python -m unittest -v
```

To rebuild after changing `native_windows.c`:

```powershell
.\build_native.ps1
```

If PowerShell blocks the script under a local execution policy, and your computer's policy permits it, invoke a process-scoped build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build_native.ps1
```

If `python` is not found, try `py -3` in place of `python`. Initialization status 5 means the selected affinity was unavailable: try another allowed CPU, or omit `--cpu 0` and record that affinity was uncontrolled. Status 2 or 3 means the required CPU counter capabilities were unavailable; do not interpret that as an attack failure. The portable `python timing_lab.py` demo remains available, but measures time rather than native counter data.

## Notebook submission

`NOTEBOOK.md` has four entries and four attached PNGs in `notebook_media`. Confirm the actual class week and any dates before submitting. For a GitHub wiki, upload or commit the PNGs somewhere the wiki can access, then replace the four relative image paths with those hosted image URLs. Merely pasting the text will not upload the images. Code and result links likewise need repository URLs if these files are not alongside the published notebook. Keep the exact semester/week/entry heading structure required by the class.

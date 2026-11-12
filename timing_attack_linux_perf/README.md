# Linux password checker with perf

The original [natural Rust checker](../timing_attack_natural_rust/password_checker.rs) returns as soon as a byte differs. The C version follows the same rule. Its fixed-work control compares every byte of an equal-length guess and checks for a mismatch at the end.

`perf_cycles.c` opens Linux's hardware CPU-cycle event for the current thread and enables it around a batch of checker calls. It uses the same user-space event as `perf stat -e cycles:u`. Startup, Python, and file output are outside the measured region. The region includes the calls and batch loop. Each call counts toward the query budget, and there are no delays inside either checker. [Linux perf event reference](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)

`experiment.py` shuffles guesses each round and saves one CSV row per batch. It checks that the counter ran for the full batch using perf's enabled and running fields. The ranking uses only cycle counts. Running on one CPU helps keep the comparisons consistent across batches. Hardware cycle counts can still vary with frequency and other activity on the machine.

## Run on the VIP Linux server

From the repository root on the server, run these commands. You need `cc`, `make`, Python 3, and access to the hardware cycle counter.

```bash
cd timing_attack_linux_perf
perf stat -e cycles:u -- true
make
python3 experiment.py diagnose --output diagnose-a.csv
python3 experiment.py diagnose --seed 43 --output diagnose-b.csv
```

Look for a numeric cycle count from `perf stat`. On the VIP server it lists separate `cpu_core` and `cpu_atom` events, and one numeric count is enough for this check. If the event is denied or unsupported, send back that output before interpreting any measurements. Each diagnostic prints the median batch cycles by known prefix length and the median change from a zero-byte match within the same round. Look for a repeatable prefix pattern in the early-exit checker and compare it with the fixed-work control. Keep both CSVs and the terminal summaries.

If the early-exit signal repeats, try the small recovery demo with a synthetic password.

```bash
python3 experiment.py recover --secret a7b2 --output recover-a.csv
```

Both checkers get the same budget. The demo assumes the password length is known and the characters are lowercase letters or digits. For each byte except the last, the script keeps the character with the highest median cycle count. It tries every possible final byte with the checker's yes/no result because a match and a mismatch at that byte both reach the final comparison. The terminal output includes the lead over the runner-up, whether a guess verified, and the total checker calls. With the defaults and a four-byte password, that's `10,800,036` calls per checker, including the 36 final guesses. Omit `--secret` for a fresh four-byte lab password. Use a new output filename for each run.

## First VIP server run

On November 11, 2026, both diagnostic runs on CPU 0 showed increasing median cycles as more bytes matched in the early-exit checker. From zero to five matching bytes the increase was about 13,000 cycles per 1,000 checks in each run. The fixed-work medians stayed within three cycles per batch within each run. In one recovery demo, the early-exit checker returned a verified `a7b2` and the fixed-work guess failed verification at the same query budget. These measurements show what happened in this run. More secrets and independent runs would be needed to estimate a recovery rate.

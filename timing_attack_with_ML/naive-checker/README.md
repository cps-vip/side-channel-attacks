# Original naive checker

`naive_checker.py` contains the original `vulnerable_check` function extracted
from v1's `timing_lab.py`. Its body is preserved: it checks length, compares
bytes in order, and returns at the first mismatch. A longer correct prefix can
therefore execute more work.

The original optional `work` argument is retained, with its default of zero.
The command-line examples use zero work; they add no artificial amplification.
This is the original low-level byte comparator. The 4–16 lowercase/digit
restrictions belong to the v1 experiment harness, not this extracted primitive.

From this directory:

```cmd
python naive_checker.py cabd
python naive_checker.py cabe
python naive_checker.py a0z9 --secret a0z9
python -m unittest -v
```

The first and third examples print `Accepted: True`; the second prints
`Accepted: False`. There is no model, dataset collection, or native DLL
dependency in this folder. The full original portable experiment remains in
`../pswd-checker-v1/timing_lab.py`.

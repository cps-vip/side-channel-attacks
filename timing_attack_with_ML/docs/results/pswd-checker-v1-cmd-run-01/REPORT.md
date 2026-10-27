# Held-out timing model evaluation

Dataset password split counts: `{'train': 182, 'validation': 39, 'test': 39}`.

| Checker | Method | Recovered | Rate | 95% Wilson interval |
| --- | --- | ---: | ---: | --- |
| vulnerable | model | 31/39 | 79.5% | 64.5%–89.2% |
| vulnerable | median | 28/39 | 71.8% | 56.2%–83.5% |
| constant | model | 0/39 | 0.0% | 0.0%–9.0% |
| constant | median | 0/39 | 0.0% | 0.0%–9.0% |

## Calibration with known correct prefixes

| Positions | Groups | Model accuracy | Median accuracy |
| --- | ---: | ---: | ---: |
| all | 780 | 98.6% | 97.1% |
| length_12 | 72 | 98.6% | 98.6% |
| earlier_positions | 702 | 99.9% | 99.9% |
| last_position | 78 | 87.2% | 71.8% |
| length_10 | 60 | 98.3% | 93.3% |
| length_15 | 90 | 98.9% | 98.9% |
| length_16 | 96 | 99.0% | 99.0% |
| length_13 | 78 | 97.4% | 100.0% |
| length_7 | 42 | 97.6% | 100.0% |
| length_5 | 30 | 96.7% | 90.0% |
| length_4 | 24 | 100.0% | 100.0% |
| length_14 | 84 | 97.6% | 100.0% |
| length_8 | 48 | 97.9% | 89.6% |
| length_6 | 36 | 100.0% | 86.1% |
| length_9 | 54 | 100.0% | 98.1% |
| length_11 | 66 | 100.0% | 97.0% |

## Interpretation

- Calibration supplies true prefixes; blind recovery supplies predicted prefixes.
- Control uses the same candidate alphabet and budget, on independently measured adaptive paths.
- The control here is a recovery negative control, not a matched fixed-candidate detector benchmark.
- Model softmax scores are not calibrated confidence estimates.
- One machine and collection blocks do not establish cross-machine/session generalization.
- TSC ticks are reference ticks, not actual core execution cycles.

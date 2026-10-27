# Held-out timing model evaluation

Dataset password split counts: `{'train': 182, 'validation': 39, 'test': 39}`.

| Checker | Method | Recovered | Rate | 95% Wilson interval |
| --- | --- | ---: | ---: | --- |
| vulnerable | model | 28/39 | 71.8% | 56.2%–83.5% |
| vulnerable | median | 29/39 | 74.4% | 58.9%–85.4% |
| constant | model | 0/39 | 0.0% | 0.0%–9.0% |
| constant | median | 0/39 | 0.0% | 0.0%–9.0% |

## Calibration with known correct prefixes

| Positions | Groups | Model accuracy | Median accuracy |
| --- | ---: | ---: | ---: |
| all | 780 | 97.4% | 96.2% |
| length_11 | 66 | 100.0% | 90.9% |
| earlier_positions | 702 | 100.0% | 99.6% |
| last_position | 78 | 74.4% | 65.4% |
| length_14 | 84 | 95.2% | 100.0% |
| length_6 | 36 | 97.2% | 91.7% |
| length_13 | 78 | 96.2% | 100.0% |
| length_7 | 42 | 100.0% | 100.0% |
| length_16 | 96 | 99.0% | 100.0% |
| length_9 | 54 | 92.6% | 92.6% |
| length_12 | 72 | 100.0% | 98.6% |
| length_5 | 30 | 90.0% | 96.7% |
| length_8 | 48 | 100.0% | 87.5% |
| length_15 | 90 | 97.8% | 98.9% |
| length_4 | 24 | 95.8% | 91.7% |
| length_10 | 60 | 98.3% | 90.0% |

## Interpretation

- Calibration supplies true prefixes; blind recovery supplies predicted prefixes.
- Control uses the same candidate alphabet and budget, on independently measured adaptive paths.
- The control here is a recovery negative control, not a matched fixed-candidate detector benchmark.
- Model softmax scores are not calibrated confidence estimates.
- One machine and collection blocks do not establish cross-machine/session generalization.
- TSC ticks are reference ticks, not actual core execution cycles.

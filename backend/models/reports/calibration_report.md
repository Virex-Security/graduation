# Probability Calibration Report

Isotonic Regression was tested natively via `CalibratedClassifierCV`.

## Brier Scores (MSE of Probabilities)
| Class | Brier Score |
|---|---|
| command_injection | 0.000830 |
| log4shell | 0.000037 |
| normal | 0.037501 |
| path_traversal | 0.000629 |
| sqli | 0.038636 |
| ssrf | 0.000442 |
| ssti | 0.001006 |
| xss | 0.001632 |
| xxe | 0.000697 |

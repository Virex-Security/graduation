# VIREX Model Evaluation Report

## Overall Metrics on Untouched Test Set
- **Macro ROC-AUC:** 0.9959

## Per-Class Metrics
| Class | Precision | Recall | F1-Score |
|---|---|---|---|
| command_injection | 0.9907 | 0.9900 | 0.9903 |
| log4shell | 0.9987 | 0.9987 | 0.9987 |
| normal | 0.8754 | 0.9953 | 0.9315 |
| path_traversal | 0.9982 | 0.9983 | 0.9982 |
| sqli | 0.9813 | 0.6522 | 0.7836 |
| ssrf | 0.9946 | 0.9867 | 0.9906 |
| ssti | 0.9571 | 0.9827 | 0.9697 |
| xss | 0.9696 | 0.9819 | 0.9757 |
| xxe | 0.9852 | 0.9747 | 0.9799 |

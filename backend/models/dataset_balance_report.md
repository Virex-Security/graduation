# Dataset Balance Report

This report highlights the mathematical balancing of the 9 specific threat classes supported by VIREX.

## Class Distribution: Before vs After

| Class Name | Before Augmentation | After Augmentation | Net Increase |
|---|---|---|---|
| **normal** | 56,918 | 74,989 | +18,071 |
| **path_traversal** | 33,038 | 35,820 | +2,782 |
| **sqli** | 23,628 | 27,925 | +4,297 |
| **command_injection** | 7,000 | 16,275 | +9,275 |
| **xxe** | 3,500 | 15,767 | +12,267 |
| **xss** | 7,739 | 12,390 | +4,651 |
| **log4shell** | 3,500 | 12,302 | +8,802 |
| **ssrf** | 3,500 | 12,035 | +8,535 |
| **ssti** | 3,500 | 11,944 | +8,444 |

## Analysis of Augmentation Strategy

### 1. Normalizing the Majority
The `normal` class remains the dominant class (74,989 samples). This represents an intentional inductive bias required for WAF security models. Since >99% of real-world traffic is benign, maintaining a heavy `normal` bias reduces base false-positive rates.

### 2. Boosting Extreme Minority Classes
Previously, `xxe`, `ssrf`, `ssti`, and `log4shell` were hard-capped at exactly 3,500 samples. This mathematical boundary resulted in lower structural exposure. We algorithmically augmented these classes up to the ~12,000+ range. This brings them into the same order of magnitude as `command_injection` and `xss`, resolving the severe macro-imbalance.

### 3. Avoiding Duplication
Rather than simply copying payloads (which leads to artificial validation scores and 100% memorization), the minority classes were grown exclusively through randomized encoding generation. Every new payload in `log4shell`, `ssti`, etc. is a structurally distinct variant of the original, guaranteeing that the model learns the core syntax rather than memorizing exact strings.

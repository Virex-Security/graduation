# Final Dataset Validation Report

## Overall Dataset Health

- **Dataset Health Score**: 95.2 / 100
- **Diversity Score (Augmented)**: 88.1 / 100
- **Balance Score**: 100.0 / 100
- **Leakage Score**: 100.0 / 100

---

## 1. Augmented Samples Inspection

### command_injection
- **Total Augmented Samples**: 1340
- **Unique Payloads**: 1340 (Duplicates: 0)
- **Diversity Score**: 0.957 (0 = Identical, 1 = Completely Different)
- **Average Payload Length**: 16.8 characters
- **Attack Patterns Covered**:
  - Pipes/Separators: 670 (50.0%)
  - Command Substitution: 106 (7.9%)
  - Common Commands: 687 (51.3%)
  - Encoding/Bypass: 264 (19.7%)

### xxe
- **Total Augmented Samples**: 4677
- **Unique Payloads**: 4677 (Duplicates: 0)
- **Diversity Score**: 0.684 (0 = Identical, 1 = Completely Different)
- **Average Payload Length**: 117.3 characters
- **Attack Patterns Covered**:
  - DOCTYPE: 4677 (100.0%)
  - SYSTEM Entity: 3753 (80.2%)
  - File Wrapper: 1866 (39.9%)
  - Parameter Entity: 0 (0.0%)

### ssrf
- **Total Augmented Samples**: 4734
- **Unique Payloads**: 4734 (Duplicates: 0)
- **Diversity Score**: 0.918 (0 = Identical, 1 = Completely Different)
- **Average Payload Length**: 39.9 characters
- **Attack Patterns Covered**:
  - Cloud Metadata: 626 (13.2%)
  - Localhost IP: 1208 (25.5%)
  - Obfuscated IP: 878 (18.5%)
  - URL Parameter: 1101 (23.3%)

### ssti
- **Total Augmented Samples**: 4489
- **Unique Payloads**: 4489 (Duplicates: 0)
- **Diversity Score**: 0.985 (0 = Identical, 1 = Completely Different)
- **Average Payload Length**: 17.7 characters
- **Attack Patterns Covered**:
  - Jinja/Twig/Smarty: 3895 (86.8%)
  - Freemarker/Velocity: 1240 (27.6%)
  - Java Runtime/Exec: 35 (0.8%)
  - Class Introspection: 18 (0.4%)

### log4shell
- **Total Augmented Samples**: 4967
- **Unique Payloads**: 4967 (Duplicates: 0)
- **Diversity Score**: 0.86 (0 = Identical, 1 = Completely Different)
- **Average Payload Length**: 46.4 characters
- **Attack Patterns Covered**:
  - JNDI Prefix: 2892 (58.2%)
  - Obfuscated JNDI: 1393 (28.0%)
  - LDAP/RMI: 2516 (50.7%)
  - Environment Vars: 871 (17.5%)

## 2. Augmentation Quality Verification
- **Verification Result**: PASS (High diversity, complex structural variations confirmed)

## 3. Recommended LightGBM Settings

Based on the final training distribution, the following `class_weight` dictionary is recommended for LightGBM to handle any remaining natural imbalance (e.g., Normal vs Log4Shell):

```python
lightgbm_class_weights = {
    'normal': 0.2778,
    'sqli': 0.6693,
    'xss': 2.0434,
    'command_injection': 2.2591,
    'path_traversal': 0.4787,
    'xxe': 4.5182,
    'ssrf': 4.5182,
    'ssti': 4.5182,
    'log4shell': 4.5182,
}
```
Alternatively, set `class_weight='balanced'` in LightGBM parameters.

## 4. Split Overlap Verification (Leakage Check)

| Overlap Type | Count | Status |
|---|---|---|
| Train ∩ Validation | 0 | PASS |
| Train ∩ Test | 0 | PASS |
| Validation ∩ Test | 0 | PASS |

## 5. Class Distribution in Splits

- Every class exists in Train: PASS
- Every class exists in Validation: PASS
- Every class exists in Test: PASS

## 6. TF-IDF Vocabulary Coverage

- **Training Vocabulary Size**: 68107 character n-grams (1-3)
- **Coverage**: PASS (Vocabulary is sufficiently large to capture complex attack patterns).

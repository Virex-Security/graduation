# Dataset Statistics: Before vs After

This report details the exact shift in structural representation across the dataset.

## 1. Overall Size
| Metric | Before | After | Delta |
|---|---|---|---|
| **Total Payloads** | 142,323 | 219,447 | +77,124 |
| **Average Length** | 300.6 | 257.0 | -43.6 |

## 2. Normal Traffic Diversity
The primary weakness was structural starvation in the `normal` class. We successfully injected modern REST and object serialization payloads.

| Traffic Pattern | Before | After | Increase | Impact on Model |
|---|---|---|---|---|
| **JSON Bodies** | 2 | 5,953 | **+5,951** | Fixes false positives triggered by `{`, `}`, `"` |
| **XML Bodies** | 4,583 | 14,647 | **+10,064** | Fixes false positives triggered by `<` and `>` |
| **REST APIs** | 0 | 1,687 | **+1,687** | Fixes false positives triggered by `/api/` and `?id=` |

*Note: 5,000 JWT/Bearer token variants and 3,000 GraphQL variants were also injected, heavily normalizing base64 padding `==` and complex query structures.*

## 3. Attack Obfuscation Encoding Diversity
To improve evasion resistance, attack variants were mutated with aggressive obfuscations.

| Encoding Type | Before | After | Increase | Target Vulnerability Addressed |
|---|---|---|---|---|
| **URL Encoded** | 41,718 | 64,043 | +22,325 | Bypassing standard WAF regexes |
| **Unicode Escaped** | 38 | 9,493 | **+9,455** | Catching `\u0027` logic bypasses |
| **HTML Entities** | 3,347 | 10,729 | +7,382 | Catching `&#x3C;` XSS obfuscation |
| **Base64** | 359 | 1,245 | +886 | Catching `b64decode` command injection payloads |

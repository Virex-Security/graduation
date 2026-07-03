# WAF External Dataset Report
Generated: 2026-07-01 02:33:35

---

## 1. Downloaded Datasets

| Dataset | Repository | Files | On-Disk Size | Status |
|---------|------------|-------|--------------|--------|
| CSIC 2010 HTTP Dataset | Monkey-D-Groot/Machine-Learning-on-CSIC-2010 | 3 | 54.67 MB | ✅ OK |
| PayloadsAllTheThings | swisskyrepo/PayloadsAllTheThings | 204 | 19.83 MB | ✅ OK |
| SecLists (sparse) | danielmiessler/SecLists | 62 | 671.76 MB | ✅ OK |

> All original downloaded files are **untouched** in their respective directories.

---

## 2. Attack Category Breakdown

| Category | Payloads Extracted | CSV Size |
|----------|--------------------|----------|
| `normal` | 81,310 | 40329.2 KB |
| `sqli` | 33,926 | 15442.9 KB |
| `xss` | 11,662 | 1216.5 KB |
| `cmdi` | 8,689 | 1135.5 KB |
| `path_traversal` | 47,258 | 4659.2 KB |
| `xxe` | 331 | 31.3 KB |
| `ssrf` | 279 | 23.5 KB |
| `ssti` | 529 | 44.4 KB |
| `log4shell` | 42 | 4.0 KB |
| **TOTAL** | **184,026** | **122.83 MB** |

Duplicates skipped (cross-source deduplication): **35,179**

---

## 3. Source Contributions

| Source | Files Processed | Raw Payloads |
|--------|----------------|--------------|
| csic_2010 | 3 | 123,042 |
| payloads_all_the_things | 67 | 30,022 |
| seclists | 62 | 66,157 |

---

## 4. Output Files

```
backend/data/external/
├── csic_2010/                    ← Raw CSIC 2010 files (untouched)
├── payloads_all_the_things/      ← Cloned repo (untouched)
├── seclists/                     ← Sparse clone, Fuzzing/ only (untouched)
├── extracted/
│   ├── normal.csv                ← Normal HTTP requests
│   ├── sqli.csv                  ← SQL Injection
│   ├── xss.csv                   ← Cross-Site Scripting
│   ├── cmdi.csv                  ← Command Injection
│   ├── path_traversal.csv        ← Path/Directory Traversal
│   ├── xxe.csv                   ← XML External Entity
│   ├── ssrf.csv                  ← Server-Side Request Forgery
│   ├── ssti.csv                  ← Server-Side Template Injection
│   ├── log4shell.csv             ← Log4Shell / Log4j RCE
│   └── combined_external.csv     ← All categories merged (184,026 rows)
├── extract_payloads.py           ← This extraction script
├── dataset_report.md             ← This report
└── dataset_report.json           ← Machine-readable summary
```

---

## 5. Notes

- **CSIC 2010**: Real HTTP traffic from an eCommerce application. Normal files provide authentic request structure.
  Anomalous traffic is heuristically categorized (XSS / path traversal / command injection / SQL injection).
- **PayloadsAllTheThings**: Expert-curated payloads from .md and .txt files. Includes context-aware examples.
- **SecLists**: Penetration testing wordlists. Only `Fuzzing/` attack subdirectories were cloned (no password/username lists).
- **Deduplication**: Cross-source MD5 deduplication ensures each unique payload appears only once in `combined_external.csv`.

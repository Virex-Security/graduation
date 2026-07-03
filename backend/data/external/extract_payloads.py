#!/usr/bin/env python3
"""
WAF Training Dataset Extractor
================================
Sources:
  - CSIC 2010 HTTP Dataset (downloaded raw files)
  - PayloadsAllTheThings (git cloned)
  - SecLists (sparse git clone, Fuzzing dirs only)

Outputs per-category CSVs and combined_external.csv
inside extracted/ folder, plus dataset_report.md
"""

import os
import re
import csv
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ─── PATHS ───────────────────────────────────────────────
SCRIPT_DIR    = Path(__file__).parent
CSIC_DIR      = SCRIPT_DIR / "csic_2010"
PATT_DIR      = SCRIPT_DIR / "payloads_all_the_things"
SECLISTS_DIR  = SCRIPT_DIR / "seclists"
EXTRACTED     = SCRIPT_DIR / "extracted"
EXTRACTED.mkdir(exist_ok=True)

# ─── CATEGORIES ──────────────────────────────────────────
CATEGORIES = [
    "normal", "sqli", "xss", "cmdi",
    "path_traversal", "xxe", "ssrf", "ssti", "log4shell",
]

# PayloadsAllTheThings folder name -> category
PATT_DIR_MAP = {
    "SQL Injection"                   : "sqli",
    "XSS Injection"                   : "xss",
    "Command Injection"               : "cmdi",
    "Directory Traversal"             : "path_traversal",
    "Client Side Path Traversal"      : "path_traversal",
    "XXE Injection"                   : "xxe",
    "Server Side Request Forgery"   : "ssrf",
    "Server Side Template Injection"  : "ssti",
    "Log4Shell"                       : "log4shell",
}

# SecLists Fuzzing actual directory mappings (matched to real repo structure)
# Dirs: Fuzzing/Databases/SQLi/, Fuzzing/XSS/, Fuzzing/LFI/
# Files: Fuzzing/XXE-Fuzzing.txt, Fuzzing/command-injection-commix.txt
SECLISTS_DIRS = {
    "Databases/SQLi" : "sqli",
    "XSS"            : "xss",
    "LFI"            : "path_traversal",
}
SECLISTS_FILES = {
    "XXE-Fuzzing.txt"             : "xxe",
    "command-injection-commix.txt": "cmdi",
}

# ─── DEDUP ───────────────────────────────────────────────
_seen: set = set()

def is_dup(payload: str) -> bool:
    h = hashlib.md5(payload.encode("utf-8", errors="ignore")).hexdigest()
    if h in _seen:
        return True
    _seen.add(h)
    return False

# ─── STATS ───────────────────────────────────────────────
stats = {
    "datasets": {},
    "categories": defaultdict(int),
    "total": 0,
    "duplicates_skipped": 0,
}

# ─── WRITERS ─────────────────────────────────────────────
_writers: dict = {}
_files:   dict = {}

def open_writers():
    for cat in CATEGORIES:
        fp = EXTRACTED / f"{cat}.csv"
        fh = open(fp, "w", newline="", encoding="utf-8")
        w  = csv.writer(fh)
        w.writerow(["payload", "label", "source"])
        _writers[cat] = w
        _files[cat]   = fh

def close_writers():
    for fh in _files.values():
        fh.close()

def emit(payload: str, category: str, source: str):
    payload = payload.strip()
    if not payload or len(payload) < 2:
        return
    if is_dup(payload):
        stats["duplicates_skipped"] += 1
        return
    if category not in _writers:
        return
    _writers[category].writerow([payload, category, source])
    stats["categories"][category] += 1
    stats["total"] += 1

# ─── HELPERS ─────────────────────────────────────────────

# Markdown TOC link: [Some Text](#some-anchor) or [text](url)
_MD_LINK_RE     = re.compile(r"^\[[^\]]+\]\([^)]*\)$")
# Markdown heading  (# Title, ## Subtitle, etc.)
_MD_HEADING_RE  = re.compile(r"^#{1,6}\s+")
# Pure prose: more than 6 whitespace-separated words with no special chars
_PROSE_RE       = re.compile(r"^(?:[A-Za-z]+ ){6,}[A-Za-z]+$")
# At least one 'attack' character / pattern for attack payloads
_ATTACK_CHARS   = re.compile(
    r"[<>'\"`;|&${}\[\]()=\\/%+#@!*^~?]|\.\.|"
    r"(?i)(select|union|insert|drop|exec|system|eval|alert|script|"
    r"jndi|ldap|etc/passwd|localhost|127\.0\.0|doctype|entity|"
    r"template|render|cmd|bash|python|wget|curl|nc\b|chmod)"
)

def _is_noise(line: str) -> bool:
    """Return True if the line is clearly navigation/prose, not a payload."""
    if _MD_LINK_RE.match(line):
        return True
    if _MD_HEADING_RE.match(line):
        return True
    if _PROSE_RE.match(line):
        return True
    # Very short words-only lines (e.g. 'Basic Injection', 'Command Execution')
    if re.match(r'^[A-Za-z][A-Za-z\s\-]{3,50}$', line) and ' ' in line and len(line.split()) <= 5:
        # Allow only if it has attack signal
        if not _ATTACK_CHARS.search(line):
            return True
    return False


def read_txt_payloads(fpath: Path):
    """Read a plain .txt payload file — one payload per line."""
    try:
        text = fpath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('|'):
            continue
        if _MD_LINK_RE.match(line):
            continue
        line = re.sub(r'^[\*\-\+]\s+', '', line).strip()
        if line and len(line) >= 2 and not _is_noise(line):
            result.append(line)
    return result


def read_md_payloads(fpath: Path):
    """
    Extract payloads from Markdown files.
    Strategy:
      - Code blocks (``` fences): capture every non-empty line as a payload.
      - Inline code (`snippet`): capture as payload.
      - List items (* / - / +): capture ONLY if they contain attack signal.
      - Everything else (headings, TOC links, prose): discard.
    """
    try:
        text = fpath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    result = []
    in_code = False
    for line in text.splitlines():
        stripped = line.strip()
        # Toggle code fence
        if stripped.startswith('```'):
            in_code = not in_code
            continue
        if in_code:
            # Inside a fenced code block — accept as raw payload
            if stripped and len(stripped) >= 2:
                result.append(stripped)
            continue
        # Skip headings and TOC links
        if _MD_HEADING_RE.match(stripped) or _MD_LINK_RE.match(stripped):
            continue
        # Inline code `...`
        for ic in re.findall(r'`([^`]{2,})`', stripped):
            if _ATTACK_CHARS.search(ic) and not _is_noise(ic):
                result.append(ic)
        # List items — only keep if they have attack signal
        m = re.match(r'^[\*\-\+]\s+(.+)', stripped)
        if m:
            val = m.group(1).strip()
            # Strip nested inline links like [label](#ref)
            val = re.sub(r'\[[^\]]+\]\([^)]*\)', '', val).strip()
            if val and len(val) >= 4 and _ATTACK_CHARS.search(val) and not _is_noise(val):
                result.append(val)
    return result

def parse_csic_requests(fpath: Path):
    """Parse CSIC HTTP log format into single-line request strings."""
    try:
        text = fpath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    requests = []
    block = []
    for line in text.splitlines():
        if not line.strip():
            if block:
                requests.append(" ".join(block[:12]))
                block = []
        else:
            block.append(line.strip())
    if block:
        requests.append(" ".join(block[:12]))
    return requests

# ─── PROCESSORS ──────────────────────────────────────────

SQLI_RE = re.compile(
    r"(select\s|union\s|insert\s|drop\s|delete\s|update\s|"
    r"or\s+1\s*=\s*1|'|--|%27|%3D|and\s+1\s*=|sleep\s*\(|benchmark\s*\(|"
    r"waitfor\s+delay|xp_cmdshell|information_schema|char\s*\(|concat\s*\()",
    re.I)
XSS_RE  = re.compile(
    r"(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|"
    r"document\.cookie|<\s*img|<\s*svg|%3Cscript|eval\s*\(|expression\s*\()",
    re.I)
TRAV_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|"
    r"%252e%252e|\.\.%2f|%c0%ae)",
    re.I)
CMDI_RE = re.compile(
    r"(;\s*(ls|cat|id|whoami|curl|wget|bash|sh|nc|python|perl|ruby)\b|"
    r"\|\s*(ls|cat|id|whoami|bash|sh)|%7C|`[^`]+`|\$\(|cmd\.exe|/bin/sh)",
    re.I)

def process_csic():
    print("\n[CSIC 2010] Processing ...")
    ds = {"files": 0, "payloads": 0}

    for fname in ["normalTrafficTraining.txt", "normalTrafficTest.txt"]:
        fp = CSIC_DIR / fname
        if not fp.exists():
            print(f"  [SKIP] {fname}")
            continue
        reqs = parse_csic_requests(fp)
        for r in reqs:
            emit(r, "normal", "csic_2010")
        ds["files"] += 1
        ds["payloads"] += len(reqs)
        print(f"  [OK] {fname}: {len(reqs):,} normal requests")

    fp = CSIC_DIR / "anomalousTrafficTest.txt"
    if fp.exists():
        reqs = parse_csic_requests(fp)
        counts = defaultdict(int)
        for r in reqs:
            if XSS_RE.search(r):
                emit(r, "xss", "csic_2010"); counts["xss"] += 1
            elif TRAV_RE.search(r):
                emit(r, "path_traversal", "csic_2010"); counts["path_traversal"] += 1
            elif CMDI_RE.search(r):
                emit(r, "cmdi", "csic_2010"); counts["cmdi"] += 1
            else:
                emit(r, "sqli", "csic_2010"); counts["sqli"] += 1
        total_a = sum(counts.values())
        ds["files"] += 1
        ds["payloads"] += total_a
        print(f"  [OK] anomalousTrafficTest.txt: {total_a:,} -> {dict(counts)}")
    else:
        print("  [SKIP] anomalousTrafficTest.txt")

    stats["datasets"]["csic_2010"] = ds
    print(f"  CSIC total: {ds['payloads']:,} from {ds['files']} files")


def process_patt():
    print("\n[PayloadsAllTheThings] Processing ...")
    ds = {"files": 0, "payloads": 0}
    if not PATT_DIR.exists():
        print("  [SKIP] Not cloned")
        stats["datasets"]["payloads_all_the_things"] = ds
        return
    for folder, cat in PATT_DIR_MAP.items():
        d = PATT_DIR / folder
        if not d.exists():
            print(f"  [SKIP] {folder}")
            continue
        fc = 0
        for fp in d.rglob("*"):
            if not fp.is_file():
                continue
            suf = fp.suffix.lower()
            if suf == ".md":
                pls = read_md_payloads(fp)
            elif suf == ".txt":
                pls = read_txt_payloads(fp)
            else:
                continue
            for p in pls:
                emit(p, cat, "payloads_all_the_things")
            ds["files"] += 1
            fc += len(pls)
            ds["payloads"] += len(pls)
        print(f"  [OK] {folder} -> {cat}: {fc:,} payloads")
    # Log4Shell is inside CVE Exploits/Log4Shell.md (no top-level dir)
    log4shell_file = PATT_DIR / "CVE Exploits" / "Log4Shell.md"
    if log4shell_file.exists():
        pls = read_md_payloads(log4shell_file)
        for p in pls:
            emit(p, "log4shell", "payloads_all_the_things")
        ds["files"] += 1
        ds["payloads"] += len(pls)
        print(f"  [OK] CVE Exploits/Log4Shell.md -> log4shell: {len(pls):,} payloads")
    else:
        print("  [SKIP] CVE Exploits/Log4Shell.md not found")

    stats["datasets"]["payloads_all_the_things"] = ds
    print(f"  PATT total: {ds['payloads']:,} from {ds['files']} files")


def process_seclists():
    print("\n[SecLists] Processing ...")
    ds = {"files": 0, "payloads": 0}
    fuzz = SECLISTS_DIR / "Fuzzing"
    if not fuzz.exists():
        print("  [SKIP] Fuzzing/ not found")
        stats["datasets"]["seclists"] = ds
        return

    # Process directory-based sources
    for folder, cat in SECLISTS_DIRS.items():
        d = fuzz / folder
        if not d.exists():
            print(f"  [SKIP] Fuzzing/{folder}")
            continue
        fc = 0
        for fp in d.rglob("*.txt"):
            pls = read_txt_payloads(fp)
            for p in pls:
                emit(p, cat, "seclists")
            ds["files"] += 1
            fc += len(pls)
            ds["payloads"] += len(pls)
        print(f"  [OK] Fuzzing/{folder} -> {cat}: {fc:,} payloads")

    # Process standalone file-based sources
    for fname, cat in SECLISTS_FILES.items():
        fp = fuzz / fname
        if not fp.exists():
            print(f"  [SKIP] Fuzzing/{fname}")
            continue
        pls = read_txt_payloads(fp)
        for p in pls:
            emit(p, cat, "seclists")
        ds["files"] += 1
        ds["payloads"] += len(pls)
        print(f"  [OK] Fuzzing/{fname} -> {cat}: {len(pls):,} payloads")

    stats["datasets"]["seclists"] = ds
    print(f"  SecLists total: {ds['payloads']:,} from {ds['files']} files")


def write_combined():
    print("\n[Combined] Merging CSVs ...")
    out_path = EXTRACTED / "combined_external.csv"
    total = 0
    with open(out_path, "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["payload", "label", "source"])
        for cat in CATEGORIES:
            fp = EXTRACTED / f"{cat}.csv"
            if not fp.exists():
                continue
            with open(fp, newline="", encoding="utf-8") as f:
                r = csv.reader(f)
                next(r)
                for row in r:
                    w.writerow(row)
                    total += 1
    print(f"  [OK] combined_external.csv: {total:,} rows")
    return total


def dir_size_mb(path: Path) -> float:
    if not path.exists():
        return 0.0
    return round(sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) / 1048576, 2)

def count_files(path: Path, exts=(".txt",".md")) -> int:
    if not path.exists():
        return 0
    return sum(1 for f in path.rglob("*") if f.is_file() and f.suffix.lower() in exts)


def write_report(combined_total: int):
    print("\n[Report] Writing dataset_report.md ...")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    csic_files   = count_files(CSIC_DIR, (".txt",))
    patt_files   = count_files(PATT_DIR, (".txt",".md"))
    sl_files     = count_files(SECLISTS_DIR / "Fuzzing", (".txt",))

    csic_mb  = dir_size_mb(CSIC_DIR)
    patt_mb  = dir_size_mb(PATT_DIR)
    sl_mb    = dir_size_mb(SECLISTS_DIR)
    ext_mb   = dir_size_mb(EXTRACTED)

    cat_rows = ""
    for cat in CATEGORIES:
        n  = stats["categories"].get(cat, 0)
        fp = EXTRACTED / f"{cat}.csv"
        kb = round(fp.stat().st_size / 1024, 1) if fp.exists() else 0
        cat_rows += f"| `{cat}` | {n:,} | {kb} KB |\n"

    def ok(n):
        return "✅ OK" if n > 0 else "⚠️ Not available"

    report = f"""# WAF External Dataset Report
Generated: {now}

---

## 1. Downloaded Datasets

| Dataset | Repository | Files | On-Disk Size | Status |
|---------|------------|-------|--------------|--------|
| CSIC 2010 HTTP Dataset | Monkey-D-Groot/Machine-Learning-on-CSIC-2010 | {csic_files} | {csic_mb} MB | {ok(csic_files)} |
| PayloadsAllTheThings | swisskyrepo/PayloadsAllTheThings | {patt_files} | {patt_mb} MB | {ok(patt_files)} |
| SecLists (sparse) | danielmiessler/SecLists | {sl_files} | {sl_mb} MB | {ok(sl_files)} |

> All original downloaded files are **untouched** in their respective directories.

---

## 2. Attack Category Breakdown

| Category | Payloads Extracted | CSV Size |
|----------|--------------------|----------|
{cat_rows}| **TOTAL** | **{stats['total']:,}** | **{ext_mb} MB** |

Duplicates skipped (cross-source deduplication): **{stats['duplicates_skipped']:,}**

---

## 3. Source Contributions

| Source | Files Processed | Raw Payloads |
|--------|----------------|--------------|
| csic_2010 | {stats['datasets'].get('csic_2010',{}).get('files',0)} | {stats['datasets'].get('csic_2010',{}).get('payloads',0):,} |
| payloads_all_the_things | {stats['datasets'].get('payloads_all_the_things',{}).get('files',0)} | {stats['datasets'].get('payloads_all_the_things',{}).get('payloads',0):,} |
| seclists | {stats['datasets'].get('seclists',{}).get('files',0)} | {stats['datasets'].get('seclists',{}).get('payloads',0):,} |

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
│   └── combined_external.csv     ← All categories merged ({combined_total:,} rows)
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
"""

    rp = SCRIPT_DIR / "dataset_report.md"
    rp.write_text(report, encoding="utf-8")
    print(f"  [OK] dataset_report.md ({rp.stat().st_size:,} bytes)")

    jp = SCRIPT_DIR / "dataset_report.json"
    jp.write_text(json.dumps({
        "generated_at":        now,
        "total_payloads":      stats["total"],
        "duplicates_skipped":  stats["duplicates_skipped"],
        "categories":          dict(stats["categories"]),
        "datasets":            stats["datasets"],
        "combined_csv_rows":   combined_total,
    }, indent=2), encoding="utf-8")
    print(f"  [OK] dataset_report.json")


def main():
    print("=" * 62)
    print("  Virex WAF — External Dataset Extractor")
    print(f"  Script dir : {SCRIPT_DIR}")
    print(f"  Output dir : {EXTRACTED}")
    print("=" * 62)

    open_writers()
    process_csic()
    process_patt()
    process_seclists()
    close_writers()

    combined_total = write_combined()
    write_report(combined_total)

    print("\n" + "=" * 62)
    print(f"  DONE  |  Unique payloads : {stats['total']:,}")
    print(f"        |  Duplicates skip : {stats['duplicates_skipped']:,}")
    print(f"        |  Report          : dataset_report.md")
    print("=" * 62)


if __name__ == "__main__":
    main()



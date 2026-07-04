# VIREX Security — Complete Project Reference Document

This document provides a comprehensive technical overview of **VIREX Security**, an AI-powered Web Application Firewall (WAF) and MLOps Security Information and Event Management (SIEM) platform. 

Graphic designers can use this reference to extract headlines, diagrams, feature lists, and technical details to build the roll-up banner.

---

## 🛡️ 1. Project Overview & Mission
VIREX is designed to protect web applications from sophisticated Layer 7 (application layer) attacks and zero-day vulnerabilities. Modern WAFs rely on static rules (signatures) which can be bypassed. VIREX solves this by implementing a **hybrid detection engine** that combines fast-path regex rules with high-speed machine learning inference. It integrates a **continuous learning MLOps pipeline** and a **local NLP security chatbot** to assist security analysts.

---

## ⚙️ 2. Core System Architecture & Traffic Flow
The system operates as an inline reverse proxy gateway, ensuring that all traffic is inspected before reaching target applications.

```
[ Client Request ]
       │
       ▼
[ Nginx Gateway (Port 8060) ]
       │
       ├─► (Subrequest /waf-inspect) ──► [ Flask WAF Engine (Port 5000) ]
       │                                           │
       │                                  [ Step 1: Sliding Window Rate Limiting ]
       │                                           │
       │                                  [ Step 2: Deterministic Regex Check ]
       │                                  (SQLi, XSS, Path Traversal, SSRF, Cmd Injection)
       │                                           │
       │                                  [ Step 3: ML Feature Extraction ]
       │                                  (3000 TF-IDF + 52 Security Heuristics)
       │                                           │
       │                                  [ Step 4: LightGBM ONNX Inference ]
       │                                           │
       │                                           ▼
       │                                    [ Decision Block ]
       │                                   /                \
       │                       (If Malicious)              (If Clean)
       │                             /                        \
       ▼                            ▼                          ▼
[ Nginx Proxy ] ◄────── [ HTTP 403 Forbidden ]          [ Proxy to Backend App ]
       │
       ▼
[ Logs Written to PostgreSQL DB ] ──► [ SIEM Dashboard (Port 8070) ]
```

---

## 🧠 3. Advanced WAF Threat Detection Engine

### Layer 1: Deterministic Rules (Regex Engine)
* **Purpose:** Instant inspection of obvious and known attack signatures.
* **Covered Attack Vectors:**
  * **SQL Injection (SQLi):** e.g., `' OR '1'='1` or Union-based selections.
  * **Cross-Site Scripting (XSS):** e.g., `<script>` tags, inline handlers (`onerror`, `onload`).
  * **Path Traversal:** e.g., `../../etc/passwd` directory exploration.
  * **Command Injection:** e.g., system command execution (`cat /etc/passwd`, `rm -rf`).
  * **Server-Side Request Forgery (SSRF):** e.g., fetching `http://169.254.169.254`.
  * **XML External Entity (XXE), Server-Side Template Injection (SSTI), & Log4Shell.**

### Layer 2: Machine Learning Inference (LightGBM on ONNX)
* **Feature Extraction:**
  * **TF-IDF Vectorization:** Extracts **3,000 sub-word n-gram combinations** from request payloads.
  * **Security Heuristic Features:** Derives **52 numeric features** including Shannon entropy variance, special character ratios, SQL/HTML keyword densities, and script tag occurrences.
* **High-Speed Inference:** Features are consolidated into a **3,052-dimension vector** fed to a **LightGBM Classifier** compiled to **ONNX Runtime**, executing in **sub-millisecond (< 1ms)** latency.

---

## 🔄 4. Autonomous MLOps & Continuous Learning Pipeline
VIREX implements an active continuous learning framework to ensure the ML model updates and adapts to new attack trends.

### Concept Drift Detection
Monitors live production traffic distributions against the training baseline to detect shifts:
* **Population Stability Index (PSI):** Measures label and prediction drift over a sliding time-window.
* **Kullback-Leibler (KL) Divergence:** Information-theoretic metric identifying distribution divergence.
* **Feature Distribution Comparison:** Z-score tracking on numerical heuristics.

### Automated Retraining & Champion-Challenger Evaluation
* **Feedback Merger:** Aggregates production threat logs corrected/verified by security analysts.
* **Isolated Subprocess Retraining:** Runs in a separate background thread to keep WAF inspection latency unaffected.
* **Champion-Challenger Evaluator:** Benchmarks the new candidate model against the current production model (champion) on **7 key metrics** (Accuracy, Precision, Recall, F1-Score, ROC-AUC, FPR, FNR) with thresholds preventing performance regression (e.g., F1-macro must not drop).
* **Rollback Guarantees:** Instant rollback to the previous model version if promotion validation fails.

---

## 💬 5. Dobby: Smart NLP Security Analyst Assistant
A fully local assistant built directly into the SIEM dashboard to interact with security metrics.

* **Privacy-First Design:** Runs 100% locally with zero internet dependencies or third-party API connections, ensuring no telemetry or request data leaves the secure environment.
* **Explainable AI (XAI) Parser:** Dissects raw malicious payloads (like complex nested SQLi or obfuscated XSS scripts) and translates them into plain-English explanation reports showing why it was flagged and what it attempts to exploit.
* **Dynamic Querying:** Understands analyst intents (via keyword mapping and fuzzy string similarity) to report live stats, system health, and active incident lists.

---

## 📊 6. SIEM Monitoring Dashboard
* **Real-time Visualization:** Telemetry timeline, attack classifications, top attacker IPs, and ML confidence levels using dynamic Chart.js dashboards.
* **Incident Management:** Groups related logs into unique incidents. Security analysts can investigate details, mark false positives, or enforce IP blocks and temporary rate limits.
* **Role-Based Access Control (RBAC):** Restricts administrative functions using secure, state-managed JWT authentication with role divisions (Admin, Analyst, Manager).

---

## 🛠️ 7. Full Technology Stack
* **Proxy & Gateway:** `Nginx` (Reverse Proxy & auth_request subrequest router)
* **Application Framework:** `Flask (Python 3)` · `Gunicorn (WSGI Server)`
* **Data Storage:** `PostgreSQL` (Supabase/Neon) · `Redis` (Session Caching)
* **Machine Learning & MLOps:** `LightGBM` · `ONNX Runtime` · `scikit-learn` · `Pandas` · `NumPy`
* **SIEM Frontend:** `React` · `Chart.js` · `Tailwind CSS`
* **Containerization:** `Docker` · `Docker Compose`

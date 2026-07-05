# VIREX Security — Roll-up Banner Design Blueprint

This document contains the exact design guidelines, copywriting, and layout structure for the **VIREX Security** roll-up banner (**85cm x 200cm**). It is written entirely in English for direct delivery to graphic designers.

---

## 🎨 Design System & Color Palette
* **Theme:** Sleek Cyberpunk / Dark Mode.
* **Background Color:** Dark Deep Slate/Black (`#04020a` / `#08041a`) with a subtle overlay of futuristic digital grid or cyber-mesh lines.
* **Primary Brand Color:** Neon Purple (`#9507c1` - used for primary highlights, borders, and main title glow).
* **Accent Color:** Neon Blue (`#00d4ff` - used for status indicators, subheadings, and icons).
* **Alert Color:** Neon Red (`#ff2d55` - used for blocked attack statistics/severity indicators).
* **Fonts:** Montserrat or Orbitron (for headers/titles) and Inter or Roboto (for body texts/lists).

---

## 📐 Layout Blueprint & Copy (Top to Bottom)

### 1. Header Section
* **Visuals:** 
  * Left side: [University Logo Placeholder]
  * Right side: [Faculty/Department Logo Placeholder]
  * Center: Glowing **VIREX** wordmark (using a metallic purple/blue gradient font) with a glowing shield icon `🛡️`.
* **Main Title:** 
  > **VIREX: An Autonomous AI-Powered 7-Layer WAF & MLOps SIEM Platform**
* **Subtitle:** 
  > *Graduation Project — Faculty of Computers and Artificial Intelligence*

---

### 2. Core Vision Statement
* **Visuals:** High-contrast text placed inside a glassmorphic container with a neon purple border.
* **Copy:**
  > **"Securing Web Infrastructures Against Zero-Day Exploits using Inline Sub-Millisecond ML Inference and Autonomous Continuous Learning."**

---

### 3. Layered WAF Detection Pipeline
* **Visuals:** A two-column grid explaining the hybrid inspection engine.
* **Column 1: Layer 1 — Deterministic Rules (Regex Engine)**
  * *Fast-Path Signature Checks:* Performs instant pattern matching to stop known attack signatures.
  * *Vulnerability Coverage:* SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, SSRF, XXE, SSTI, and Log4Shell.
* **Column 2: Layer 2 — AI Anomaly Inference Engine (ONNX)**
  * *Feature Extraction:* Parses **3,000 TF-IDF sub-word n-gram features** and extracts **52 heuristic security metrics** (entropy, symbol density, tag ratio).
  * *High-Performance Inference:* Unified LightGBM classifier compiled to **ONNX Runtime** for sub-millisecond execution times.

---

### 4. Autonomous MLOps & Continuous Learning
* **Visuals:** A step-by-step workflow loop layout.
* **Concept Drift Detection:** Active traffic analysis monitoring distribution shifts using **Population Stability Index (PSI)**, **Kullback-Leibler (KL) Divergence**, and Z-score calculations.
* **Continuous Self-Training:** Automatically aggregates verified analyst feedback to retrain the model in an isolated background thread, preventing server performance degradation.
* **Champion-Challenger Evaluation:** Automatically benchmark new models against current production instances across 7 key metrics (Accuracy, F1-macro, ROC AUC, FPR, FNR) with automated fallback guarantees.

---

### 5. Dobby: Local NLP Security Assistant
* **Visuals:** A mock chatbot window overlay or clean feature card.
* **Privacy-First Architecture:** 100% local Natural Language Processing (NLP) chatbot with zero external API dependencies or cloud connections to prevent data leak risks.
* **Explainable AI (XAI):** Built-in rule-based explainability parser that translates malicious payloads into natural, actionable descriptions.
* **Live System Telemetry:** Allows security analysts to query live metrics, active incident queues, and system health via simple chat commands.

---

### 6. Technology Stack Badges
* **Visuals:** Clean, uniform flat icons or tech badges.
* **Core Tech:** `Python` · `Flask` · `PostgreSQL` · `Redis` · `Nginx` · `Docker`
* **AI & MLOps:** `LightGBM` · `ONNX Runtime` · `scikit-learn` · `Pandas` · `Chart.js`

---

### 7. Footer Section
* **Left:** **Supervised By:**
  * Dr. [Supervisor Name]
  * Eng. [TA Name]
* **Center:** **Project Team:**
  * [Student Name 1]
  * [Student Name 2]
  * [Student Name 3
  * [Student Name 4]
* **Right:** 
  * [QR Code Placeholder]
  * **"Scan to View Live Demo & Repository"**

---

## 💡 Printing & Export Guidelines for the Designer
1. **Dimensions:** Set canvas size to **85 cm width x 200 cm height**.
2. **Resolution:** Design at **300 DPI** using **CMYK Color Profile** for printing.
3. **Margins:** Keep all text and critical logos at least **5 cm away from the top and bottom borders** (safety area for the rollup mechanism).
4. **Contrast:** Dark backgrounds require high-contrast neon glows (`#9507c1` and `#00d4ff`) to make text readable in bright exhibition halls.

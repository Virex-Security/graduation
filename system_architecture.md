# Virex Security: System Architecture

## Overview
Virex Security is an advanced, AI-powered Web Application Firewall (WAF) and SIEM visualization platform. The system operates on a hybrid detection logic model, leveraging fast-path rule-based checking for obvious threats, and a robust LightGBM inference pipeline via ONNX Runtime for complex zero-day anomaly detection.

## Request Lifecycle
1. **Client Request**: An incoming HTTP payload is ingested by the Flask API Gateway.
2. **Pre-Flight Validation**: Standard sanitation checks process the payload structure.
3. **Regex Fast-Path**: Known, deterministic attack strings are instantly blocked via optimized regular expressions, bypassing machine learning entirely.
4. **Machine Learning Pre-Processing**: If the string falls outside determinism, it passes to the ML engine:
    - **TF-IDF Vectorization**: Parses 3,000 sub-word n-gram combinations (n=1 to 3).
    - **SecurityFeatureExtractor**: Derives 52 critical text heuristics such as punctuation ratios, entropy variance, and specific malicious keywords.
5. **ONNX Inference**: The 3,052-dimension unified feature vector is fed to a highly optimized LightGBM inference graph executing in sub-millisecond timeframes via the `onnxruntime` backend.
6. **Decision & Caching Engine**: The probability dict outputs a unified severity (`low`, `medium`, `high`, `critical`) and maps it to specific mitigations (`allow`, `monitor`, `block`). This outcome is written to a fast-tier LRU dictionary or Redis memory cache to prevent re-evaluation of exact duplicates.
7. **Database Persistence**: The telemetric data is asynchronously saved to SQLite (development) or PostgreSQL (production) schemas.
8. **Real-time Dashboarding**: Security operators utilize a localized React + Chart.js dashboard running on port `8070` to query the anomalies, drill into IP frequency, and observe real-time attack traffic.

## Infrastructure Stack
- **Web Servers**: Flask / Gunicorn
- **Data Persistence**: SQLite3, PostgreSQL (Supabase/Neon), Redis
- **Machine Learning**: LightGBM, ONNX Runtime, scikit-learn
- **Frontend**: Vanilla Javascript, Chart.js, HTML5/CSS3
- **Containerization**: Docker, Docker Compose

## Security Protocols
- Completely modular and sandboxed inference boundaries.
- No dynamic `eval` or `exec` execution states on user payload data.
- Absolute separation of Model Training pathways from Production Inference instances.

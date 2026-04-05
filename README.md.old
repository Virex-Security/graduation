# Virex Security System (Graduation Project)

A lightweight **API Security + SIEM Dashboard** demo built with **Flask**.
It detects common web attacks (SQL Injection, XSS, brute force, scanner behavior, rate limiting) and visualizes events and incidents in a dashboard.

## Tech Stack
- Backend: Python + Flask
- Dashboard: Flask templates + HTML/CSS/JavaScript
- ML: TF‑IDF + RandomForest (scikit-learn)
- (Optional later) Database: SQL Server

## Services & Ports (Local)
- **API Service:** `http://127.0.0.1:5000`
- **Dashboard:** `http://127.0.0.1:8070/` (Landing page: `/`)

## Project Structure (high level)
- `simple_app.py` — API + security pipeline + ML detection (demo)
- `dashboard.py` — dashboard web app + incidents + reports
- `templates/` — HTML templates (landing/login/signup/dashboard/etc.)
- `static/` — CSS/JS assets
- `ml_training_data.csv` — training dataset (text,label)
- `requirements.txt` — Python dependencies

## Setup (Windows)
### 1) Create venv (recommended)
```bash
python -m venv .venv
.venv\Scripts\activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

## Run Locally
### 1) Start the API (Terminal 1)
```bash
python simple_app.py
```

### 2) Start the Dashboard (Terminal 2)
```bash
python dashboard.py
```

Open the dashboard in your browser:
- `http://127.0.0.1:8070/`

API health check:
- `http://127.0.0.1:5000/api/health`

## Demo / Attack Simulation
Run the demo script to generate attacks and see detections in real time:
```bash
python attack_simulator.py
```

Expected:
- Some attacks should be **blocked** (e.g., 400 / 429)
- Dashboard should show events, blocked requests, and incidents

## Environment Variables
Create a `.env` file (or update your environment) based on `.env.example`.

Example:
- `SECRET_KEY` — Flask/JWT secret key

## Notes
- This is a graduation demo project: some endpoints use in-memory fake data for users/orders/products.
- ML model files may be generated locally: `model.pkl` and `vectorizer.pkl`.

## Roadmap (Next Improvements)
- Move audit logs to **SQL Server** instead of local JSON
- Add ML metrics reporting & threshold tuning
- Improve access control (roles) and security hardening (CSRF, secure cookies)
- Add automated tests (pytest)
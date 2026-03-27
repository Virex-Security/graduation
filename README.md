# Virex Security System (Graduation Project)

A lightweight **API Security + SIEM Dashboard** demo built with **Flask**.
It detects common web attacks (SQL Injection, XSS, brute force, scanner behavior, rate limiting) and visualizes events and incidents in a dashboard.

## 🆕 **Refactored Structure** (March 2026)

The project has been refactored into a clean, modular structure for better maintainability and scalability.

## Tech Stack

- **Backend:** Python + Flask
- **Dashboard:** Flask templates + HTML/CSS/JavaScript
- **ML:** TF‑IDF + RandomForest (scikit-learn)
- **Security:** Rule-based + ML-based threat detection

## Services & Ports (Local)

- **API Service:** `http://127.0.0.1:5000`
- **Dashboard:** `http://127.0.0.1:8070/`

---

## 🚀 Quick Start

### 1) Setup Environment

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Configure `.env` File

```env
SECRET_KEY=your-secret-key-here
API_PORT=5000
DASHBOARD_PORT=8070
API_URL=http://127.0.0.1:5000
DASHBOARD_URL=http://127.0.0.1:8070
```

### 3) Run Services

**Terminal 1 - API:**

```bash
python run_api.py
```

**Terminal 2 - Dashboard:**

```bash
python run_dashboard.py
```

### 4) Run Attack Simulator (Optional)

```bash
python scripts/attack_simulator.py
```

---
---

## 📊 Key Features

1. **Multi-Layer Threat Detection**
   - Regex patterns (SQL Injection, XSS)
   - Rate limiting & scanner detection
   - ML-based anomaly detection

2. **SIEM Dashboard**
   - Real-time threat visualization
   - Incident management
   - Security score calculation
   - ML performance metrics

3. **Role-Based Access Control**
   - Admin and User roles
   - Protected endpoints
   - Audit logging

4. **ML Integration**
   - TF-IDF + Random Forest
   - Auto-retraining every hour
   - Live detection statistics

---

## 🛠️ Development

### Train ML Model

```bash
python scripts/train_model_enhanced.py
```

### Run Tests

```bash
pytest tests/
```

---

## 📝 API Endpoints

### Essential

- `GET /api/health` - Health check
- `POST /api/login` - User login (with brute force protection)
- `GET /api/security/stats` - Security statistics
- `GET /api/users` - Get users (demo data)
- `GET /api/orders` - Get orders (demo data)
- `GET /api/products` - Get products (demo data)

### Dashboard Pages

- `/` - Landing page
- `/dashboard` - Main dashboard
- `/incidents` - Incident management
- `/ml-detections` - ML performance
- `/profile` - User profile

---

## 🐛 Troubleshooting

**Import errors:** Ensure virtual environment is activated and run from project root.

**Dashboard shows zeros:** Check API is running and `data/siem_audit.json` exists.

**Templates not found:** Use `run_dashboard.py` (not `dashboard.py` directly).

---

## 📖 Module Guide

- **app/api/** - API routes, security manager, business logic
- **app/dashboard/** - Dashboard routes, services, incident management
- **app/auth/** - Authentication, decorators, user management
- **app/ml/** - ML model loading and threat detection
- **app/security/** - Request filtering and event utilities
- **app/chatbot/** - NLP-based security assistant

---

## 🚧 Future Roadmap

- SQL Server integration
- WebSocket real-time updates
- Custom ML training UI
- Docker deployment
- Enhanced role system

---

**Built with ❤️ for cybersecurity education**

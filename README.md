# 🛡️ Virex Security System

A full-stack SIEM (Security Information and Event Management) platform with:
- **WAF** — Web Application Firewall (signature + ML-based detection)
- **SIEM Dashboard** — Real-time threat monitoring and incident management
- **ML Engine** — Anomaly detection using scikit-learn
- **Chatbot** — Bilingual (EN/AR) security assistant
- **Attack Simulator** — For testing and demos

---

## 🚀 Quick Start

### Prerequisites
| Tool | Minimum Version |
|------|----------------|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |

### 1. Clone & configure

```bash
git clone https://github.com/Virex-Security/graduation.git
cd graduation

<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
# Copy and edit the environment file
cp .env.example .env
# Edit .env — set SECRET_KEY, INTERNAL_API_SECRET, and optionally SMTP_*
```

Generate secure keys:
```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('INTERNAL_API_SECRET=' + secrets.token_hex(32))"
<<<<<<< HEAD
=======
=======
# ⚠️ Setup environment variables
cp .env.example .env
# Edit .env — set SECRET_KEY, INTERNAL_API_SECRET, and SMTP_*
```

Generate secure keys (DO NOT use defaults!):
```bash
python3 -c "import secrets; print('SECRET_KEY=\"' + secrets.token_hex(64) + '\"')"
python3 -c "import secrets; print('INTERNAL_API_SECRET=\"' + secrets.token_urlsafe(48) + '\"')"
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the ML model (first time only)

```bash
python3 scripts/train_model_enhanced.py
```

### 4. Start the servers

**Linux / macOS:**
```bash
bash start.sh all
```

**Windows:**
```cmd
start.bat all
```

**Manual:**
```bash
# Terminal 1 — API server (port 5000)
python run_api.py

# Terminal 2 — Dashboard (port 8070)
python run_dashboard.py
```

### 5. Open the dashboard

```
http://localhost:8070
```

Default credentials (change after first login!):
| Username | Password | Role |
|----------|----------|------|
| admin | Admin@123 | Admin |

---

## 🐳 Docker (Recommended)

```bash
cp .env.example .env   # fill in values
docker-compose up -d
```

Services:
- Dashboard: http://localhost:8070
- API: http://localhost:5000

---

## 🏗️ Architecture

```
graduation/
├── app/
│   ├── api/            # WAF + REST API (port 5000)
│   │   ├── routes.py   # API route handlers
│   │   ├── security.py # WAF / threat detection manager
│   │   ├── services.py # Business logic
│   │   ├── responses.py# Standardized API responses (NEW)
│   │   └── persistence.py
│   ├── auth/           # Authentication & authorization
│   │   ├── auth.py     # Login / logout / token minting
│   │   ├── decorators.py # @token_required, @admin_required
│   │   ├── models.py   # UserManager (DB-backed)
│   │   └── roles.py
│   ├── chatbot/        # Dobby — bilingual security chatbot
│   ├── dashboard/      # SIEM Dashboard (port 8070)
│   │   ├── routes.py   # Dashboard route handlers
│   │   ├── services.py # Dashboard data service
│   │   └── metrics.py
│   ├── ml/             # ML inference engine
│   ├── security/       # Event processing utilities
│   ├── config.py       # Centralized config + startup validator (NEW)
│   ├── database.py     # SQLite data access layer
│   └── static/         # CSS, JS, images
├── detections/         # CSRF / SSRF rule modules
├── frontend/           # React dashboard (Vite + Tailwind)
├── scripts/            # ML training, attack simulator
├── db/                 # SQLite database (gitignored)
├── data/               # ML data, model files (gitignored)
├── .env.example        # Environment template
├── Dockerfile
├── docker-compose.yml
└── start.sh / start.bat
```

---

## 🔐 Security Configuration

| Setting | Dev | Production |
|---------|-----|------------|
| `FLASK_DEBUG` | true | **false** |
| `COOKIE_SECURE` | false | **true** (requires HTTPS) |
<<<<<<< HEAD
| `SECRET_KEY` | any | **random 32+ byte hex** |
| HTTPS | optional | **required** |

=======
<<<<<<< HEAD
| `SECRET_KEY` | any | **random 32+ byte hex** |
| HTTPS | optional | **required** |

=======
| `SECRET_KEY` | any | **random 64+ byte hex** |
| HTTPS | optional | **required** |

### ⚠️ Secret Rotation
If your `.env` file is accidentally committed or shared, you **MUST** rotate all secrets immediately. 
1. Generate new `SECRET_KEY` and `INTERNAL_API_SECRET`.
2. Update the `SMTP_PASSWORD`.
3. Restart all services.

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🔒 Security Notes

- Passwords are hashed with Werkzeug's `generate_password_hash` (PBKDF2-SHA256)
- JWT tokens stored in `httpOnly` cookies (not localStorage)
- Token revocation via `jti` + `user_sessions` table
- Rate limiting: 10 req/10s global + 5 login attempts/60s per IP
- WAF: signature rules (SQL injection, XSS, command injection, path traversal) + ML model
- CSRF and SSRF detection modules active on all state-changing requests
- All sensitive paths return 404 (scanner honeypot)

---

<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
## 💾 Database Concurrency

> [!IMPORTANT]
> This project uses **SQLite** for simplicity and zero-configuration setup. SQLite supports multiple simultaneous readers but only **one simultaneous writer**. 
> 
> To ensure stability under load, we have implemented:
> - **WAL Mode**: Write-Ahead Logging for better concurrency.
> - **Extended Timeouts**: Connection busy timeouts set to 30 seconds.
> - **Worker Strategy**: Gunicorn workers are limited to **1 per service** in `docker-compose.yml` to prevent internal write contention.
> 
> **Production Recommendation:**
> For high-concurrency environments or large-scale deployments, we recommend migrating to **PostgreSQL**.

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
## 📜 License

Educational project — Virex Security Team

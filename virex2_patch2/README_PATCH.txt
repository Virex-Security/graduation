=====================================
  VIREX2 Patch v2 — What's New
=====================================

NEW FILES:
  app/api/persistence.py      ← Data persistence (stats, blocked IPs, attacks, ML log)

UPDATED FILES:
  app/api/routes.py           ← /api/my-attacks + /api/clear-attacks + persistent blocked IPs
  app/api/security.py         ← Saves attacks to user_attacks.json + logs ML detections
  app/ml/inference.py         ← ML thresholds from .env (ML_THRESHOLD_BLOCK/MONITOR)
  app/auth/models.py          ← threading.Lock + atomic write
  app/auth/decorators.py      ← JWT ExpiredSignatureError explicit check
  app/templates/attack_history.html   ← NEW page: Attack History dashboard
  app/templates/sidebar_component.html ← Added "Attack History" link in sidebar
  simple_app.py               ← Thin wrapper only

NEW DATA FILES (auto-created on first run):
  data/stats.json             ← total_requests, blocked_requests (survives restart)
  data/blocked_ips.json       ← blocked IPs (survives restart)
  data/user_attacks.json      ← attack history per user/IP
  data/ml_detections.jsonl    ← ML detection log (JSONL format)

NEW ENV VARS (add to your .env):
  ML_THRESHOLD_BLOCK=0.90
  ML_THRESHOLD_MONITOR=0.70
  MAX_CONTENT_LENGTH=1048576

NEW API ENDPOINTS:
  GET  /api/my-attacks?user=<username>   ← Get attack history
  DELETE /api/clear-attacks?all=true     ← Clear all history
  DELETE /api/clear-attacks?user=<name>  ← Clear one user

NEW DASHBOARD PAGE:
  http://localhost:8070/attack-history   ← Visual attack history table

HOW TO APPLY:
  Windows: double-click APPLY_PATCH.bat  (run from inside virex_patch2 folder)
  Mac/Linux: bash apply_patch.sh
=====================================

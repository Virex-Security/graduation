# ============================================================
#  Virex Security System — Multi-stage Dockerfile
# ============================================================

# ── Stage 1: Build React frontend ─────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --silent

COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python application ───────────────────────────
FROM python:3.11-slim

LABEL maintainer="Virex Security Team"
LABEL description="Virex SIEM Security System"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd --create-home --shell /bin/bash virex
WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=virex:virex . .

# Copy built frontend into static folder
COPY --from=frontend-builder /build/frontend/dist /app/app/static/react

# Create necessary directories
RUN mkdir -p db data app/static/uploads/avatars \
    && chown -R virex:virex /app

# Switch to non-root user
USER virex

# Expose ports
EXPOSE 5000 8070

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Default: run dashboard (override in docker-compose)
CMD ["gunicorn", "--bind", "0.0.0.0:8070", "--workers", "2", \
     "--timeout", "60", "--access-logfile", "-", "run_dashboard:app"]

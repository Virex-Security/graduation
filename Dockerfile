FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# ── Security: run as a dedicated non-root user ──────────────
# Create a system user with no login shell and no home directory.
RUN groupadd --system nonrootuser && \
    useradd  --system --no-create-home --shell /sbin/nologin \
             --gid nonrootuser nonrootuser && \
    chown -R nonrootuser:nonrootuser /app

USER nonrootuser

EXPOSE 5000
CMD ["gunicorn", "run_api:app", "--bind", "0.0.0.0:5000", "--workers", "2"]

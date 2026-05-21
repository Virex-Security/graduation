FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . /app

# Switch to non-root user
USER appuser

EXPOSE 5000
CMD ["gunicorn", "run_api:app", "--bind", "0.0.0.0:5000", "--workers", "2"]

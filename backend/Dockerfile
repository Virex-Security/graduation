FROM python:3.11-slim

# Prevent writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install libgomp1 (OpenMP) required by XGBoost and LightGBM models
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend source files
COPY . /app

# Expose WAF API (5000) and Dashboard Server (8070)
EXPOSE 5000
EXPOSE 8070

# Default command starts the WAF API server
CMD ["python", "run_api.py"]

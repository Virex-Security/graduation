FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt


COPY . /app

EXPOSE 5000
CMD gunicorn "run_api:app" --bind 0.0.0.0:5000 --workers 2

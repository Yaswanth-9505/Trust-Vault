# For Fly.io / Render / Railway / any container host. Mount a persistent
# volume at /data so the database survives restarts.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TV_ENV=production TV_DATABASE_PATH=/data/trustvault.db \
    TV_SECURE_COOKIES=1 TV_TRUSTED_PROXIES=1 TV_SQLITE_JOURNAL=WAL

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
COPY wsgi.py .

RUN useradd --create-home --uid 10001 tv && mkdir -p /data && chown tv /data
USER tv

EXPOSE 8000
# 2 workers: SQLite serialises writes; more workers only add lock contention.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "60", "wsgi:app"]

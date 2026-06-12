FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=lxml -r requirements.txt

COPY . .
RUN chmod +x docker/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["docker/entrypoint.sh"]
# Worker count is configurable via WEB_CONCURRENCY (default 2). A single worker
# serializes all requests on one event loop, so a burst of concurrent fetches
# queues head-of-line; multiple workers absorb bursts. `exec` keeps uvicorn as
# PID 1 of the command so it receives stop signals for graceful shutdown.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY:-2}"]

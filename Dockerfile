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
# Worker count is configurable via WEB_CONCURRENCY (default 4). A single worker
# serializes all requests on one event loop, so a burst of concurrent fetches
# queues head-of-line; multiple workers absorb bursts. Gunicorn (pre-fork) is the
# process manager instead of uvicorn's own `--workers` supervisor, whose spawn
# path crash-loops its child workers on some hosts; gunicorn forks reliably and
# gives graceful restarts. `exec` keeps gunicorn as PID 1 so it receives stop
# signals. Workers run the uvicorn ASGI worker class from the uvicorn-worker
# package (uvicorn.workers is deprecated in modern uvicorn).
CMD ["sh", "-c", "exec gunicorn app.main:app -k uvicorn_worker.UvicornWorker --workers ${WEB_CONCURRENCY:-4} --bind 0.0.0.0:8000 --timeout 120 --graceful-timeout 30 --access-logfile -"]

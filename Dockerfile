FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=lxml -r requirements.txt

COPY . .
RUN chmod +x docker/entrypoint.sh
# Pre-compile to bytecode at build time so each container boot reuses cached
# .pyc instead of recompiling all source in memory (see PYTHONDONTWRITEBYTECODE
# removal above). Baked into the read-only image layer.
RUN python -m compileall -q app

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
#
# `--preload` imports the app ONCE in the master before forking; workers then
# fork copy-on-write instead of each re-importing the full dependency tree.
# This eliminates the ~90s boot gap on small VPSes where N workers importing in
# parallel thrash CPU/RAM (swap). Safe here because the DB engine/pool is built
# lazily inside the lifespan (per-worker, post-fork) — no connection crosses the
# fork. `--max-requests` recycles workers to bound any slow memory growth.
CMD ["sh", "-c", "exec gunicorn app.main:app -k uvicorn_worker.UvicornWorker --workers ${WEB_CONCURRENCY:-4} --preload --bind 0.0.0.0:8000 --timeout 120 --graceful-timeout 30 --max-requests 1000 --max-requests-jitter 100 --access-logfile -"]

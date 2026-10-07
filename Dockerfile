# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

# Build-time only: the running container makes no outbound calls.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Application code, owned by root and not writable by the runtime user.
COPY app.py /app/app.py
COPY templates /app/templates

# Unprivileged runtime account with no shell and no home directory.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vault \
    && chown -R root:root /app \
    && chmod -R a-w,a+rX /app

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else sys.exit(1)"]

# 2 workers x 4 threads is plenty for a room of players and stays well inside
# the memory cap. --worker-tmp-dir points at the tmpfs so a read-only root
# filesystem is not a problem.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--threads", "4", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "20", \
     "--graceful-timeout", "10", \
     "--keep-alive", "2", \
     "--max-requests", "2000", \
     "--max-requests-jitter", "200", \
     "--limit-request-line", "4094", \
     "--limit-request-fields", "40", \
     "--limit-request-field_size", "4094", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]

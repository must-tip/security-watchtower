FROM python:3.11.16-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY watchers/requirements.lock ./requirements.lock
RUN python -m pip install --prefix=/install --require-hashes --requirement requirements.lock

FROM python:3.11.16-slim-bookworm@sha256:2e32f7d302adc1c37428355c1e646897c0c53f4fd60b6a551245fb90ee129f91 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN groupadd --system --gid 1001 watchtower \
    && useradd --system --uid 1001 --gid watchtower --no-create-home watchtower

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=1001:1001 watchers/ /app/watchers/

USER 1001:1001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
    CMD ["python", "-c", "import os, redis; redis.Redis(host=os.environ['REDIS_HOST'], port=int(os.getenv('REDIS_PORT', '6379')), password=os.environ['REDIS_PASSWORD'], socket_connect_timeout=5).ping()"]

CMD ["python", "-m", "watchers.main"]

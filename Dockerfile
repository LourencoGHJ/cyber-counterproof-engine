# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m pip install --no-cache-dir . \
    && groupadd --system --gid 10001 cce \
    && useradd --system --uid 10001 --gid cce \
        --home-dir /nonexistent --shell /usr/sbin/nologin cce \
    && mkdir -p /reports \
    && chown 10001:10001 /reports

USER 10001:10001

ENTRYPOINT ["cce"]
CMD ["--help"]

# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic.ini compose.yaml ./
COPY migrations ./migrations
COPY docs ./docs
COPY examples ./examples

RUN python -m venv /opt/securescan \
    && /opt/securescan/bin/pip install ".[postgres]"


FROM python:3.12-slim-bookworm AS runtime

ARG SECURESCAN_RUNTIME_UID=1000
ARG SECURESCAN_RUNTIME_GID=1000

ENV HOME=/home/securescan \
    PATH=/opt/securescan/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN test "${SECURESCAN_RUNTIME_UID}" -gt 0 \
    && test "${SECURESCAN_RUNTIME_GID}" -gt 0 \
    && groupadd --gid "${SECURESCAN_RUNTIME_GID}" securescan \
    && useradd --create-home --uid "${SECURESCAN_RUNTIME_UID}" \
        --gid securescan --shell /usr/sbin/nologin securescan \
    && install -d -o securescan -g securescan /app /var/lib/securescan

COPY --from=builder /opt/securescan /opt/securescan
COPY --chown=securescan:securescan src /app/src
COPY --chown=securescan:securescan migrations /app/migrations
COPY --chown=securescan:securescan alembic.ini /app/alembic.ini

WORKDIR /app
USER securescan:securescan

EXPOSE 8000

CMD ["uvicorn", "securescan.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

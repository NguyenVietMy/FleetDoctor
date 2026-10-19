FROM ghcr.io/astral-sh/uv:0.11.4 AS uv
FROM python:3.12-slim AS base
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --locked --extra collector --no-dev
RUN useradd --uid 10001 --create-home fleetdoctor
USER fleetdoctor
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "fleetdoctor.collector:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers", "--no-access-log"]

FROM base AS test
USER root
COPY tests ./tests
COPY scripts ./scripts
COPY deploy ./deploy
COPY monitoring ./monitoring
COPY compose.yaml Dockerfile ./
RUN uv sync --locked --all-extras
CMD ["/app/.venv/bin/python", "-m", "pytest", "-q"]


FROM test AS disk-test
USER root
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs util-linux mount && rm -rf /var/lib/apt/lists/*
CMD ["/app/.venv/bin/python", "scripts/disk_helper_probe.py"]

FROM base AS production

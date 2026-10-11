FROM ghcr.io/astral-sh/uv:0.11.4 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --locked --extra collector --no-dev
RUN useradd --uid 10001 --create-home fleetdoctor
USER fleetdoctor
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "fleetdoctor.collector:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers", "--no-access-log"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY infra_mcp ./infra_mcp

# Nicht als root laufen. Der Container braucht keinen Docker-Socket - er
# spricht nur mit der Portainer-API und der NPM-API.
RUN useradd --system --no-create-home --uid 10001 mcp \
    && mkdir -p /data && chown mcp /data
USER mcp

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    METRICS_FILE=/data/host-metrics.jsonl \
    PYTHONUNBUFFERED=1

# Version aus dem Git-Tag, Commit und Build-Zeit (von GitHub Actions gesetzt) -
# infra_version gibt alles zurück, damit nach einem Redeploy prüfbar ist, welcher
# Stand wirklich läuft. Ohne APP_VERSION meldet der Server "dev-<kurzer Commit>".
ARG GIT_SHA=unbekannt
ARG APP_VERSION=
ARG BUILD_TIME=
ENV GIT_SHA=$GIT_SHA \
    APP_VERSION=$APP_VERSION \
    BUILD_TIME=$BUILD_TIME

EXPOSE 8000

# /healthz liegt hinter der Bearer-Prüfung; der Check nutzt das eigene MCP_API_KEY.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-m", "infra_mcp.healthcheck"]

CMD ["python", "-m", "infra_mcp"]

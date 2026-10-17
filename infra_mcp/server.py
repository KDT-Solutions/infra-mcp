"""HTTP-Transport (Streamable HTTP) mit Bearer-Auth - gleiches Muster wie
plesk-mcp, also-mcp und dr-mcp.

Läuft ausschliesslich als Docker-Container hinter einem Reverse-Proxy und wird
als Custom Connector in Claude genutzt. Ohne MCP_API_KEY startet der Server
nicht; jeder Request ohne gültiges "Authorization: Bearer <MCP_API_KEY>"
bekommt 401 (auch /healthz).
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import sys

# Registrierung der Tools passiert beim Import der Module.
from . import tools_npm, tools_portainer, tools_workflow  # noqa: F401
from . import metrics
from .app import mcp
from .config import settings
from .version import __version__

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
# httpx loggt sonst jede URL auf INFO.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("infra_mcp")


class _BearerAuthMiddleware:
    """Minimalistische ASGI-Middleware: prüft 'Authorization: Bearer <token>'."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode("latin-1")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"")
        # Konstantzeit-Vergleich, damit das Token nicht über Antwortzeiten erratbar ist.
        if not hmac.compare_digest(auth_header, self.expected):
            from starlette.responses import JSONResponse

            response = JSONResponse({"error": "unauthorized"}, status_code=401)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _with_healthz(app):
    """/healthz für den Docker-Healthcheck (liegt hinter der Bearer-Prüfung)."""
    from starlette.responses import JSONResponse

    async def router(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/healthz":
            await JSONResponse({"status": "ok", "version": __version__})(scope, receive, send)
            return
        await app(scope, receive, send)

    return router


def _build_http_app(api_key: str, host: str = "0.0.0.0"):
    if not api_key:
        raise RuntimeError(
            "MCP_API_KEY (statisches Bearer-Token) fehlt - aus Sicherheitsgründen kein Start ohne Token."
        )
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.middleware.cors import CORSMiddleware

    # transport_security: DNS-Rebinding-Schutz deaktiviert, analog zu
    # plesk-mcp/dr-mcp - sonst blockt das SDK jeden Request mit einem
    # Host-Header, der nicht "localhost"/eine IP ist (421 "Invalid Host
    # header"), obwohl der Server bewusst unter einer echten Domain erreichbar
    # ist. Die eigentliche Absicherung übernimmt MCP_API_KEY/_BearerAuthMiddleware.
    # json_response=True: einfache application/json-Antworten statt SSE-
    # Stream - robuster hinter Reverse-Proxies.
    starlette_app = mcp.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host=host,
    )
    secured_app = _BearerAuthMiddleware(_with_healthz(starlette_app), api_key)
    # CORS aussen um die Auth-Middleware: Browser-basierte MCP-Clients (z.B.
    # Claude.ai) rufen den Endpoint per Cross-Origin-Fetch auf. Preflight-
    # OPTIONS-Requests (ohne Authorization-Header) beantwortet CORSMiddleware
    # direkt, bevor sie die Bearer-Prüfung erreichen.
    return CORSMiddleware(
        secured_app,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id"],
    )


async def _run_http_server(api_key: str, host: str, port: int) -> None:
    import uvicorn

    app = _build_http_app(api_key, host)
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    srv = uvicorn.Server(config)
    logger.info("infra-mcp %s HTTP server running on %s:%s", __version__, host, port)
    sampler = None
    if settings().node_exporter_url:
        # 24-h-Verlauf von Host-CPU/RAM (infra_host_history)
        sampler = asyncio.create_task(metrics.sampler_loop())
    try:
        await srv.serve()
    finally:
        if sampler:
            sampler.cancel()


def main() -> None:
    api_key = os.environ.get("MCP_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "MCP_API_KEY (statisches Bearer-Token) fehlt - aus Sicherheitsgründen kein Start ohne Token."
        )
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8000"))
    asyncio.run(_run_http_server(api_key, host, port))


if __name__ == "__main__":
    main()

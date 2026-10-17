"""MCPServer-Instanz, Tool-Registrierung mit Audit-Log und Client-Singletons."""

from __future__ import annotations

import functools
import inspect
import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import audit, guard
from .config import settings
from .errors import InfraError
from .npm_client import NpmClient
from .portainer_client import PortainerClient
from .version import __version__

logger = logging.getLogger("infra_mcp")

INSTRUCTIONS = (
    "infra-mcp verwaltet Container und Stacks über die Portainer-API sowie Proxy-Hosts und Zertifikate "
    "im Nginx Proxy Manager. Schreibende Tools führen nur mit confirm=true aus; ohne confirm liefern sie "
    "eine Vorschau. Geschützte Container, Stacks und Domains werden blockiert. Es wird nichts gelöscht."
)

mcp = MCPServer("infra-mcp", version=__version__, instructions=INSTRUCTIONS)


def tool(*dargs: Any, **dkwargs: Any):
    """Wie mcp.tool(), zusätzlich:
    - jeder Aufruf wird als JSON-Zeile geloggt (Parameter ohne Secrets),
    - erwartete Fehler (InfraError) werden als ToolError mit Klartext gemeldet,
    - unerwartete Fehler nur mit Typ, ohne Details (könnten Secrets enthalten).
    Registriert wird der Wrapper; das Modul behält die Originalfunktion (Tests)."""
    register = mcp.tool(*dargs, **dkwargs)

    def decorator(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                params = dict(sig.bind_partial(*args, **kwargs).arguments)
            except TypeError:
                params = dict(kwargs)
            started = time.monotonic()
            fields: dict[str, Any] = {"tool": fn.__name__, "params": guard.redact_params(params)}
            try:
                result = fn(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
            except ToolError as exc:
                msg = guard.redact_text(str(exc))
                audit.log_event("tool_call", **fields, status="error", error=msg, duration_ms=_ms(started))
                raise ToolError(msg) from None
            except InfraError as exc:
                msg = guard.redact_text(str(exc))
                audit.log_event(
                    "tool_call", **fields, status="error", error_type=type(exc).__name__, error=msg,
                    duration_ms=_ms(started),
                )
                raise ToolError(msg) from None
            except Exception as exc:  # noqa: BLE001 - bewusst: keine Details nach aussen
                audit.log_event(
                    "tool_call", **fields, status="error", error_type=type(exc).__name__, duration_ms=_ms(started)
                )
                logger.exception("Unerwarteter Fehler in %s", fn.__name__)
                raise ToolError(f"Interner Fehler ({type(exc).__name__}). Details im Container-Log.") from None
            status = "preview" if isinstance(result, dict) and result.get("preview") is True else "ok"
            audit.log_event(
                "tool_call", **fields, status=status, result=audit.summarize_result(result), duration_ms=_ms(started)
            )
            return result

        register(wrapper)
        return fn

    return decorator


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

_portainer: PortainerClient | None = None
_npm: NpmClient | None = None


def portainer() -> PortainerClient:
    global _portainer
    if _portainer is None:
        cfg = settings()
        missing = [n for n, v in (("PORTAINER_URL", cfg.portainer_url), ("PORTAINER_API_KEY", cfg.portainer_api_key)) if not v]
        if missing:
            raise InfraError(f"Konfiguration unvollständig, fehlende Umgebungsvariablen: {', '.join(missing)}")
        _portainer = PortainerClient(cfg.portainer_url, cfg.portainer_api_key, verify=cfg.portainer_tls_verify)
    return _portainer


def npm() -> NpmClient:
    global _npm
    if _npm is None:
        cfg = settings()
        missing = [
            n for n, v in (("NPM_URL", cfg.npm_url), ("NPM_USER", cfg.npm_user), ("NPM_PASSWORD", cfg.npm_password)) if not v
        ]
        if missing:
            raise InfraError(f"Konfiguration unvollständig, fehlende Umgebungsvariablen: {', '.join(missing)}")
        _npm = NpmClient(cfg.npm_url, cfg.npm_user, cfg.npm_password)
    return _npm


def set_clients(portainer_client: PortainerClient | None = None, npm_client: NpmClient | None = None) -> None:
    """Nur für Tests: Clients ersetzen bzw. zurücksetzen."""
    global _portainer, _npm
    _portainer = portainer_client
    _npm = npm_client

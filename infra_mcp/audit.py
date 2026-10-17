"""Audit-Log: jeder Tool-Aufruf als eine JSON-Zeile auf stdout
(Toolname, Parameter ohne Secrets, Resultat, Dauer)."""

from __future__ import annotations

import datetime
import json
import sys
from typing import Any


def log_event(event: str, **fields: Any) -> None:
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        **fields,
    }
    # Direkt auf stdout (eine Zeile pro Aufruf); die übrigen Logs gehen nach stderr.
    print(json.dumps(record, ensure_ascii=False, default=str), file=sys.stdout, flush=True)


def summarize_result(result: Any) -> Any:
    """Kurzfassung des Resultats fürs Log - keine Inhalte wie Logs oder Compose-Dateien."""
    if isinstance(result, dict):
        summary: dict[str, Any] = {"keys": sorted(result.keys())[:20]}
        for k in ("executed", "preview", "action", "ok", "status", "id", "stack_id", "proxy_host_id"):
            if k in result and isinstance(result[k], (str, int, bool, type(None))):
                summary[k] = result[k]
        return summary
    if isinstance(result, list):
        return {"items": len(result)}
    if isinstance(result, str):
        return {"chars": len(result)}
    return {"type": type(result).__name__}

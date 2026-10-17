"""Async-Client für die Portainer-API (Access Token im Header X-API-Key).

Geprüft gegen den Portainer-Quellcode 2.45.2 (api/http/handler/stacks):
- GET  /api/system/version, GET /api/endpoints
- Docker-Proxy unter /api/endpoints/{id}/docker/...
- GET  /api/stacks, /api/stacks/{id}, /api/stacks/{id}/file
- PUT  /api/stacks/{id}?endpointId=..            (Compose-Stack aktualisieren)
- PUT  /api/stacks/{id}/git/redeploy?endpointId=..  (Git-Stack)
- POST /api/stacks/{id}/start|stop?endpointId=..
- POST /api/stacks/create/standalone/string?endpointId=..
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .errors import PortainerError, UnclearStateError

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
DEPLOY_TIMEOUT = 300.0
CONTAINER_ACTION_TIMEOUT = 60.0

STACK_TYPES = {1: "swarm", 2: "compose", 3: "kubernetes"}
STACK_STATUS = {1: "active", 2: "inactive", 3: "deploying", 4: "error"}
STACK_STATUS_DEPLOYING = 3
STACK_STATUS_ERROR = 4


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    msg = ""
    if isinstance(body, dict):
        parts = [str(body.get(k)) for k in ("message", "details") if body.get(k)]
        msg = " - ".join(parts)
    if not msg:
        msg = (resp.text or "").strip()
    return msg[:500]


def demux_docker_stream(data: bytes) -> str:
    """Docker-Log-Stream ohne TTY demultiplexen.

    Jeder Frame hat einen 8-Byte-Header: Byte 0 = Stream (0 stdin, 1 stdout,
    2 stderr), Bytes 1-3 = 0, Bytes 4-7 = Länge (big endian). Erkennt das
    Format nicht (z.B. TTY-Container), wird der Rest unverändert übernommen.
    """
    chunks: list[bytes] = []
    i, n = 0, len(data)
    while i + 8 <= n:
        header = data[i : i + 8]
        if header[0] not in (0, 1, 2) or header[1:4] != b"\x00\x00\x00":
            break
        size = int.from_bytes(header[4:8], "big")
        chunks.append(data[i + 8 : i + 8 + size])
        i += 8 + size
    if i < n:
        chunks.append(data[i:])
    return b"".join(chunks).decode("utf-8", errors="replace")


def summarize_stats(raw: dict[str, Any]) -> dict[str, Any]:
    """CPU-% wie `docker stats`, RAM ohne Page-Cache, Netzwerk-Summen."""
    cpu = raw.get("cpu_stats") or {}
    pre = raw.get("precpu_stats") or {}
    cpu_delta = (cpu.get("cpu_usage", {}).get("total_usage") or 0) - (pre.get("cpu_usage", {}).get("total_usage") or 0)
    sys_delta = (cpu.get("system_cpu_usage") or 0) - (pre.get("system_cpu_usage") or 0)
    online = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    cpu_pct = round(cpu_delta / sys_delta * online * 100.0, 2) if cpu_delta > 0 and sys_delta > 0 else 0.0

    mem = raw.get("memory_stats") or {}
    stats = mem.get("stats") or {}
    usage = mem.get("usage") or 0
    # cgroup v2: inactive_file, cgroup v1: total_inactive_file (gleiche Rechnung wie docker CLI)
    cache = stats.get("inactive_file", stats.get("total_inactive_file", 0)) or 0
    used = max(usage - cache, 0) if usage else 0
    limit = mem.get("limit") or 0

    rx = tx = 0
    for net in (raw.get("networks") or {}).values():
        rx += net.get("rx_bytes") or 0
        tx += net.get("tx_bytes") or 0

    return {
        "cpu_percent": cpu_pct,
        "online_cpus": online,
        "memory_used_bytes": used,
        "memory_limit_bytes": limit,
        "memory_percent": round(used / limit * 100.0, 2) if limit else None,
        "memory_used_mib": round(used / 1048576, 1),
        "memory_limit_mib": round(limit / 1048576, 1) if limit else None,
        "network_rx_bytes": rx,
        "network_tx_bytes": tx,
        "pids": (raw.get("pids_stats") or {}).get("current"),
    }


class PortainerClient:
    def __init__(self, base_url: str, api_key: str, verify: bool = True, transport: httpx.AsyncBaseTransport | None = None):
        base = base_url.rstrip("/")
        if not base.endswith("/api"):
            base += "/api"
        self._client = httpx.AsyncClient(
            base_url=base,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            verify=verify,
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        timeout: float | None = None,
        write: bool = False,
        raw: bool = False,
    ) -> Any:
        t = httpx.Timeout(timeout or READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        label = f"{method} {path}"
        try:
            resp = await self._client.request(method, path, params=params, json=json_body, timeout=t)
        except (httpx.ConnectTimeout, httpx.ConnectError):
            # Verbindung kam nicht zustande - auch bei Schreibvorgängen wurde nichts gesendet.
            raise PortainerError(f"Portainer nicht erreichbar ({label}): Verbindungsaufbau fehlgeschlagen.") from None
        except httpx.TimeoutException:
            if write:
                raise UnclearStateError(
                    f"Portainer: Timeout bei {label}. Der Zustand ist unklar - die Aktion wurde evtl. "
                    "ausgeführt. Bitte zuerst den Ist-Zustand prüfen (z.B. portainer_stack_list / "
                    "portainer_container_list). Es wird nicht automatisch wiederholt."
                ) from None
            raise PortainerError(f"Portainer: Timeout bei {label}.") from None
        except httpx.HTTPError as exc:
            raise PortainerError(f"Portainer: Netzwerkfehler bei {label} ({type(exc).__name__}).") from None

        if resp.status_code == 304:
            return {"not_modified": True}
        if resp.status_code >= 400:
            raise PortainerError(f"Portainer: HTTP {resp.status_code} bei {label}: {_error_message(resp)}")
        if raw:
            return resp.content
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- System -----------------------------------------------------------

    async def version(self) -> Any:
        return await self._request("GET", "/system/version")

    async def endpoints(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/endpoints") or []

    # -- Docker-Proxy -----------------------------------------------------

    def _docker(self, endpoint_id: int, path: str) -> str:
        return f"/endpoints/{int(endpoint_id)}/docker{path}"

    async def containers(self, endpoint_id: int, all_: bool = True, filters: dict[str, list[str]] | None = None) -> list[dict]:
        params: dict[str, Any] = {"all": "1" if all_ else "0"}
        if filters:
            params["filters"] = json.dumps(filters)
        return await self._request("GET", self._docker(endpoint_id, "/containers/json"), params=params) or []

    async def container_inspect(self, endpoint_id: int, container: str) -> dict[str, Any]:
        return await self._request("GET", self._docker(endpoint_id, f"/containers/{container}/json"))

    async def container_logs(self, endpoint_id: int, container: str, tail: int, since: int | None = None) -> bytes:
        params: dict[str, Any] = {"stdout": "1", "stderr": "1", "tail": str(tail), "timestamps": "1"}
        if since:
            params["since"] = str(since)
        return await self._request("GET", self._docker(endpoint_id, f"/containers/{container}/logs"), params=params, raw=True)

    async def container_stats(self, endpoint_id: int, container: str) -> dict[str, Any]:
        return await self._request(
            "GET", self._docker(endpoint_id, f"/containers/{container}/stats"), params={"stream": "false"}
        )

    async def container_action(self, endpoint_id: int, container: str, action: str) -> Any:
        if action not in ("start", "stop", "restart"):
            raise PortainerError(f"Unbekannte Container-Aktion: {action}")
        return await self._request(
            "POST",
            self._docker(endpoint_id, f"/containers/{container}/{action}"),
            timeout=CONTAINER_ACTION_TIMEOUT,
            write=True,
        )

    async def images(self, endpoint_id: int) -> list[dict]:
        return await self._request("GET", self._docker(endpoint_id, "/images/json")) or []

    async def volumes(self, endpoint_id: int) -> dict[str, Any]:
        return await self._request("GET", self._docker(endpoint_id, "/volumes")) or {}

    async def networks(self, endpoint_id: int) -> list[dict]:
        return await self._request("GET", self._docker(endpoint_id, "/networks")) or []

    # -- Stacks -----------------------------------------------------------

    async def stacks(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/stacks") or []

    async def stack(self, stack_id: int) -> dict[str, Any]:
        return await self._request("GET", f"/stacks/{int(stack_id)}")

    async def stack_file(self, stack_id: int) -> str:
        data = await self._request("GET", f"/stacks/{int(stack_id)}/file")
        return (data or {}).get("StackFileContent", "") if isinstance(data, dict) else ""

    async def stack_update_compose(self, stack_id: int, endpoint_id: int, payload: dict[str, Any]) -> Any:
        return await self._request(
            "PUT",
            f"/stacks/{int(stack_id)}",
            params={"endpointId": int(endpoint_id)},
            json_body=payload,
            timeout=DEPLOY_TIMEOUT,
            write=True,
        )

    async def stack_git_redeploy(self, stack_id: int, endpoint_id: int, payload: dict[str, Any]) -> Any:
        return await self._request(
            "PUT",
            f"/stacks/{int(stack_id)}/git/redeploy",
            params={"endpointId": int(endpoint_id)},
            json_body=payload,
            timeout=DEPLOY_TIMEOUT,
            write=True,
        )

    async def stack_start(self, stack_id: int, endpoint_id: int) -> Any:
        return await self._request(
            "POST", f"/stacks/{int(stack_id)}/start", params={"endpointId": int(endpoint_id)},
            timeout=DEPLOY_TIMEOUT, write=True,
        )

    async def stack_stop(self, stack_id: int, endpoint_id: int) -> Any:
        return await self._request(
            "POST", f"/stacks/{int(stack_id)}/stop", params={"endpointId": int(endpoint_id)},
            timeout=DEPLOY_TIMEOUT, write=True,
        )

    async def stack_create_git(self, endpoint_id: int, payload: dict[str, Any]) -> Any:
        return await self._request(
            "POST",
            "/stacks/create/standalone/repository",
            params={"endpointId": int(endpoint_id)},
            json_body=payload,
            timeout=DEPLOY_TIMEOUT,
            write=True,
        )

    async def stack_create_compose(self, endpoint_id: int, name: str, content: str, env: list[dict[str, str]]) -> Any:
        return await self._request(
            "POST",
            "/stacks/create/standalone/string",
            params={"endpointId": int(endpoint_id)},
            json_body={"Name": name, "StackFileContent": content, "Env": env},
            timeout=DEPLOY_TIMEOUT,
            write=True,
        )

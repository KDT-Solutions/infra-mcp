"""Async-Client für die Nginx-Proxy-Manager-API.

Login per POST /api/tokens {"identity", "secret"} liefert {"token", "expires"}
(JWT, standardmässig 1 Tag gültig). Das Token wird im Speicher gehalten, vor
Ablauf per GET /api/tokens erneuert und bei HTTP 401 genau einmal per neuem
Login ersetzt, danach wird der Request einmal wiederholt.

Payloads geprüft gegen den NPM-Quellcode (backend/schema, backend/routes,
backend/internal) der Versionen v2.12.6 und v2.16.0:
- Bis v2.12.x verlangt ein Let's-Encrypt-Zertifikat meta.letsencrypt_email und
  meta.letsencrypt_agree. Ab v2.13.0 sind diese Felder im Schema nicht mehr
  erlaubt (additionalProperties: false); NPM nimmt die E-Mail-Adresse des
  angemeldeten NPM-Benutzers.
- Beim Anlegen mit certificate_id="new" legt NPM erst den Proxy-Host an
  (ssl_forced/http2/hsts werden dabei mangels Zertifikat auf false gesetzt)
  und hängt danach das Zertifikat an. ssl_forced muss deshalb anschliessend
  per PUT gesetzt werden.
"""

from __future__ import annotations

import datetime
import json
import time
from typing import Any, Callable

import httpx

from .errors import NpmError, UnclearStateError

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
CERT_TIMEOUT = 180.0
REFRESH_MARGIN_SECONDS = 3600


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    msg = ""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = str(err.get("message") or "")
        elif err:
            msg = str(err)
    if not msg:
        msg = (resp.text or "").strip()
    return msg[:500]


def _parse_expires(value: Any) -> float:
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


class NpmClient:
    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._user = user
        self._password = password
        self._clock = clock
        self._token: str | None = None
        self._expires: float = 0.0
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Accept": "application/json"},
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- Token ------------------------------------------------------------

    def _store_token(self, data: Any) -> None:
        if not isinstance(data, dict) or not data.get("token"):
            if isinstance(data, dict) and data.get("requires_2fa"):
                raise NpmError(
                    "NPM-Login verlangt 2FA. Für den MCP-Benutzer muss die Zwei-Faktor-Anmeldung deaktiviert sein."
                )
            raise NpmError("NPM-Login: Antwort enthält kein Token.")
        self._token = data["token"]
        self._expires = _parse_expires(data.get("expires")) or (self._clock() + 23 * 3600)

    async def _login(self) -> None:
        try:
            resp = await self._client.post("/tokens", json={"identity": self._user, "secret": self._password})
        except httpx.TimeoutException:
            raise NpmError("NPM-Login: Timeout.") from None
        except httpx.HTTPError as exc:
            raise NpmError(f"NPM nicht erreichbar (Login, {type(exc).__name__}).") from None
        if resp.status_code >= 400:
            # Keine Details zurückgeben - die Antwort könnte den Benutzernamen enthalten.
            raise NpmError(f"NPM-Login fehlgeschlagen (HTTP {resp.status_code}). NPM_USER/NPM_PASSWORD prüfen.")
        self._store_token(resp.json())

    async def _refresh(self) -> None:
        try:
            resp = await self._client.get("/tokens", headers={"Authorization": f"Bearer {self._token}"})
        except httpx.HTTPError:
            resp = None
        if resp is not None and resp.status_code < 400:
            try:
                self._store_token(resp.json())
                return
            except (NpmError, ValueError):
                pass
        await self._login()

    async def _ensure_token(self) -> None:
        if not self._token:
            await self._login()
        elif self._expires - self._clock() < REFRESH_MARGIN_SECONDS:
            await self._refresh()

    # -- Requests ---------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        timeout: float | None = None,
        write: bool = False,
        _retried: bool = False,
    ) -> Any:
        await self._ensure_token()
        t = httpx.Timeout(timeout or READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        label = f"{method} {path}"
        try:
            resp = await self._client.request(
                method, path, params=params, json=json_body, timeout=t,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except (httpx.ConnectTimeout, httpx.ConnectError):
            raise NpmError(f"NPM nicht erreichbar ({label}): Verbindungsaufbau fehlgeschlagen.") from None
        except httpx.TimeoutException:
            if write:
                raise UnclearStateError(
                    f"NPM: Timeout bei {label}. Der Zustand ist unklar - die Aktion (z.B. Zertifikatsanforderung) "
                    "wurde evtl. ausgeführt. Bitte zuerst den Ist-Zustand prüfen (npm_proxy_host_get / "
                    "npm_certificate_list). Es wird nicht automatisch wiederholt."
                ) from None
            raise NpmError(f"NPM: Timeout bei {label}.") from None
        except httpx.HTTPError as exc:
            raise NpmError(f"NPM: Netzwerkfehler bei {label} ({type(exc).__name__}).") from None

        if resp.status_code == 401 and not _retried:
            # Token abgelaufen/ungültig: einmal neu einloggen und wiederholen.
            # 401 heisst, NPM hat den Request nicht ausgeführt - Wiederholen ist auch bei Schreibvorgängen sicher.
            self._token = None
            await self._login()
            return await self._request(
                method, path, params=params, json_body=json_body, timeout=timeout, write=write, _retried=True
            )
        if resp.status_code >= 400:
            raise NpmError(f"NPM: HTTP {resp.status_code} bei {label}: {_error_message(resp)}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -- Lesen ------------------------------------------------------------

    async def version(self) -> Any:
        """GET /api/ liefert status, setup und version {major, minor, revision}."""
        return await self._request("GET", "/")

    async def legacy_letsencrypt_meta(self) -> bool:
        """True, wenn die installierte NPM-Version meta.letsencrypt_email/agree erwartet (bis v2.12).
        Erkannt am API-Schema (GET /api/schema), nicht an der Versionsnummer. Bewusst bei
        jedem Aufruf neu, damit ein NPM-Update ohne Neustart von infra-mcp greift."""
        schema = await self._request("GET", "/schema")
        text = schema if isinstance(schema, str) else json.dumps(schema)
        return "letsencrypt_email" in text

    async def proxy_hosts(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/proxy-hosts", params={"expand": "certificate,access_list"}) or []

    async def proxy_host(self, host_id: int) -> dict[str, Any]:
        return await self._request(
            "GET", f"/nginx/proxy-hosts/{int(host_id)}", params={"expand": "certificate,access_list"}
        )

    async def certificates(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/certificates") or []

    async def redirection_hosts(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/redirection-hosts", params={"expand": "certificate"}) or []

    async def streams(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/streams") or []

    async def access_lists(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/nginx/access-lists", params={"expand": "items,clients"}) or []

    async def host_report(self) -> Any:
        return await self._request("GET", "/reports/hosts")

    # -- Schreiben --------------------------------------------------------

    async def create_proxy_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        timeout = CERT_TIMEOUT if payload.get("certificate_id") == "new" else READ_TIMEOUT
        return await self._request("POST", "/nginx/proxy-hosts", json_body=payload, timeout=timeout, write=True)

    async def update_proxy_host(self, host_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        timeout = CERT_TIMEOUT if payload.get("certificate_id") == "new" else READ_TIMEOUT
        return await self._request(
            "PUT", f"/nginx/proxy-hosts/{int(host_id)}", json_body=payload, timeout=timeout, write=True
        )

    async def enable_proxy_host(self, host_id: int) -> Any:
        return await self._request("POST", f"/nginx/proxy-hosts/{int(host_id)}/enable", write=True, timeout=60)

    async def disable_proxy_host(self, host_id: int) -> Any:
        return await self._request("POST", f"/nginx/proxy-hosts/{int(host_id)}/disable", write=True, timeout=60)

    async def renew_certificate(self, cert_id: int) -> Any:
        return await self._request(
            "POST", f"/nginx/certificates/{int(cert_id)}/renew", write=True, timeout=CERT_TIMEOUT
        )

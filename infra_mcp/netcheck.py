"""DNS-Vorabprüfung und HTTPS-Test.

Aufgelöst wird über den Resolver des Containers (Docker-DNS, der an den
Resolver des Hosts weiterleitet). infra-mcp legt keine DNS-Einträge an;
fehlt ein Eintrag, wird gemeldet, welcher A-Record nötig ist.
"""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from typing import Any

import httpx

DNS_TIMEOUT = 10.0
HTTPS_TIMEOUT = 15.0


async def resolve_ipv4(domain: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM), DNS_TIMEOUT
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return []
    return sorted({info[4][0] for info in infos})


async def check_dns(domains: list[str], public_ip: str) -> dict[str, Any]:
    """Prüft, ob jede Domain (A-Record) auf PUBLIC_IP zeigt."""
    results: dict[str, Any] = {}
    ok = True
    for d in domains:
        ips = await resolve_ipv4(d)
        good = bool(public_ip) and public_ip in ips
        entry: dict[str, Any] = {"resolved": ips, "ok": good}
        if not good:
            ok = False
            entry["required_record"] = f"{d}. IN A {public_ip}" if public_ip else "PUBLIC_IP ist nicht gesetzt"
            entry["hint"] = (
                f"A-Record für {d} auf {public_ip} anlegen (infra-mcp setzt keine DNS-Einträge)."
                if not ips
                else f"{d} zeigt auf {', '.join(ips)}, erwartet {public_ip}. A-Record korrigieren."
            )
        results[d] = entry
    return {"ok": ok, "public_ip": public_ip or None, "domains": results}


def _fetch_cert(domain: str) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=HTTPS_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            cert = tls.getpeercert() or {}
    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        dt = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=datetime.timezone.utc)
        expires = dt.isoformat()
        days_left = (dt - datetime.datetime.now(datetime.timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    return {"cert_valid": True, "cert_expires": expires, "cert_days_left": days_left, "cert_issuer": issuer.get("organizationName")}


async def https_check(domain: str) -> dict[str, Any]:
    """HTTPS-Abruf: Statuscode und ob das Zertifikat gültig ist (Kette + Hostname)."""
    out: dict[str, Any] = {"url": f"https://{domain}/"}
    try:
        out.update(await asyncio.to_thread(_fetch_cert, domain))
    except ssl.SSLCertVerificationError as exc:
        out.update({"cert_valid": False, "cert_error": exc.verify_message or "Zertifikat ungültig"})
    except (OSError, ssl.SSLError) as exc:
        out.update({"cert_valid": False, "cert_error": f"TLS-Verbindung fehlgeschlagen ({type(exc).__name__})"})
    try:
        async with httpx.AsyncClient(timeout=HTTPS_TIMEOUT, follow_redirects=False, verify=True) as client:
            resp = await client.get(out["url"])
        out["status_code"] = resp.status_code
        if resp.is_redirect:
            out["location"] = resp.headers.get("location")
    except httpx.HTTPError as exc:
        out["status_code"] = None
        out["request_error"] = type(exc).__name__
    out["ok"] = bool(out.get("cert_valid")) and out.get("status_code") is not None and out["status_code"] < 500
    return out

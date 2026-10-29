"""Nginx-Proxy-Manager-Tools (npm_*): Proxy-Hosts, Zertifikate, Übersichten."""

from __future__ import annotations

import datetime
from typing import Any

from . import audit, guard, netcheck
from .app import npm, portainer, tool
from .config import settings
from .errors import GuardError, NpmError, UnclearStateError
from .tools_portainer import container_name, published_ports

CERT_WARN_DAYS = 14
NGINX_ERR_MAX_CHARS = 500


# ---------------------------------------------------------------------------
# Hilfsfunktionen (auch von tools_workflow genutzt)
# ---------------------------------------------------------------------------


def _parse_dt(value: Any) -> datetime.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    if " " in v and "T" not in v:
        v = v.replace(" ", "T", 1)
    try:
        dt = datetime.datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def cert_info(cert: dict[str, Any] | None) -> dict[str, Any] | None:
    if not cert:
        return None
    exp = _parse_dt(cert.get("expires_on"))
    days = (exp - datetime.datetime.now(datetime.timezone.utc)).days if exp else None
    return {
        "id": cert.get("id"),
        "name": cert.get("nice_name"),
        "provider": cert.get("provider"),
        "domain_names": cert.get("domain_names") or [],
        "expires_on": cert.get("expires_on"),
        "days_left": days,
        "expiring_soon": days is not None and days < CERT_WARN_DAYS,
        "expired": days is not None and days < 0,
    }


def host_summary(h: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": h.get("id"),
        "domain_names": h.get("domain_names") or [],
        "forward": f"{h.get('forward_scheme')}://{h.get('forward_host')}:{h.get('forward_port')}",
        "forward_host": h.get("forward_host"),
        "forward_port": h.get("forward_port"),
        "enabled": bool(h.get("enabled")),
        "ssl_forced": bool(h.get("ssl_forced")),
        "certificate": cert_info(h.get("certificate")),
        "online": (h.get("meta") or {}).get("nginx_online"),
    }


def host_detail(h: dict[str, Any]) -> dict[str, Any]:
    out = host_summary(h)
    out.update(
        {
            "forward_scheme": h.get("forward_scheme"),
            "certificate_id": h.get("certificate_id"),
            "websocket": bool(h.get("allow_websocket_upgrade")),
            "block_exploits": bool(h.get("block_exploits")),
            "caching_enabled": bool(h.get("caching_enabled")),
            "http2": bool(h.get("http2_support")),
            "hsts": bool(h.get("hsts_enabled")),
            "hsts_subdomains": bool(h.get("hsts_subdomains")),
            "access_list_id": h.get("access_list_id"),
            "access_list": (h.get("access_list") or {}).get("name"),
            "advanced_config": guard.redact_advanced_config(h.get("advanced_config")),
            "locations": [
                {
                    "path": loc.get("path"),
                    "forward": guard.location_target(loc),
                    "access_list_id": loc.get("access_list_id"),
                    "advanced_config": guard.redact_advanced_config(loc.get("advanced_config")),
                }
                for loc in h.get("locations") or []
            ],
            "nginx_error": (h.get("meta") or {}).get("nginx_err"),
            "created_on": h.get("created_on"),
            "modified_on": h.get("modified_on"),
        }
    )
    return out


async def find_hosts_by_domain(domains: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Proxy- und Redirection-Hosts, die eine der Domains schon verwenden."""
    wanted = {d.lower() for d in domains}
    hits: dict[str, list[dict[str, Any]]] = {"proxy_hosts": [], "redirection_hosts": []}
    for h in await npm().proxy_hosts():
        if wanted & {d.lower() for d in h.get("domain_names") or []}:
            hits["proxy_hosts"].append({"id": h.get("id"), "domain_names": h.get("domain_names")})
    for h in await npm().redirection_hosts():
        if wanted & {d.lower() for d in h.get("domain_names") or []}:
            hits["redirection_hosts"].append({"id": h.get("id"), "domain_names": h.get("domain_names")})
    return hits


async def resolve_host_id(id_or_domain: Any) -> int:
    if isinstance(id_or_domain, int) or (isinstance(id_or_domain, str) and id_or_domain.strip().isdigit()):
        return guard.validate_positive_id(id_or_domain, "id")
    domain = guard.validate_domain(str(id_or_domain))
    for h in await npm().proxy_hosts():
        if domain in [d.lower() for d in h.get("domain_names") or []]:
            return int(h["id"])
    raise NpmError(f"Kein Proxy-Host mit Domain '{domain}' gefunden.")


async def build_create_payload(
    domains: list[str],
    scheme: str,
    host: str,
    port: int,
    websocket: bool,
    block_exploits: bool,
    ssl: bool,
    http2: bool,
    hsts: bool,
    access_list_id: int | None,
    advanced_config: str | None,
    locations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    # advanced_config wird 1:1 nginx-Konfiguration: nur Direktiven aus der Allowlist (guard),
    # sonst GuardError - auch in der Vorschau ohne confirm.
    payload: dict[str, Any] = {
        "domain_names": domains,
        "forward_scheme": scheme,
        "forward_host": host,
        "forward_port": port,
        "allow_websocket_upgrade": bool(websocket),
        "block_exploits": bool(block_exploits),
        "caching_enabled": False,
        "access_list_id": int(access_list_id) if access_list_id else 0,
        "advanced_config": guard.validate_advanced_config(advanced_config),
        "certificate_id": "new" if ssl else 0,
        "ssl_forced": bool(ssl),
        "http2_support": bool(ssl and http2),
        "hsts_enabled": bool(ssl and hsts),
        "hsts_subdomains": False,
        "meta": {},
        "locations": guard.validate_locations(locations),
    }
    if ssl:
        if await npm().legacy_letsencrypt_meta():
            email = settings().npm_default_email
            if not email:
                raise GuardError("Diese NPM-Version verlangt eine Let's-Encrypt-E-Mail: NPM_DEFAULT_EMAIL setzen.")
            payload["meta"] = {"letsencrypt_email": email, "letsencrypt_agree": True, "dns_challenge": False}
        else:
            payload["meta"] = {"dns_challenge": False}
    return payload


def _payload_preview(payload: dict[str, Any]) -> dict[str, Any]:
    p = dict(payload)
    if p.get("advanced_config"):
        p["advanced_config"] = guard.redact_advanced_config(p["advanced_config"])
    if p.get("locations"):
        p["locations"] = [_location_view(loc) for loc in p["locations"]]
    return p


# ---------------------------------------------------------------------------
# Custom Locations
# ---------------------------------------------------------------------------


def _location_view(loc: dict[str, Any]) -> dict[str, Any]:
    out = {"path": loc.get("path"), "ziel": guard.location_target(loc),
           "advanced_config": guard.redact_advanced_config(loc.get("advanced_config"))}
    if loc.get("access_list_id") is not None:
        out["access_list_id"] = loc.get("access_list_id")
    return out


def _location_key(loc: dict[str, Any], with_acl: bool = True) -> tuple[Any, ...]:
    """Vergleichswert einer Location (ohne id); leere Werte gelten als gleich."""
    try:
        port = int(loc.get("forward_port"))
    except (TypeError, ValueError):
        port = loc.get("forward_port")
    key: tuple[Any, ...] = (
        loc.get("path"), loc.get("forward_scheme"), loc.get("forward_host"), port,
        loc.get("forward_path") or "", (loc.get("advanced_config") or "").strip(),
    )
    if with_acl:
        key += (int(loc.get("access_list_id") or 0),)
    return key


def _locations_match(stored: list[dict[str, Any]], sent: list[dict[str, Any]], with_acl: bool) -> bool:
    return [_location_key(x, with_acl) for x in stored] == [_location_key(x, with_acl) for x in sent]


async def check_location_targets(locations: list[dict[str, Any]], label: str = "locations") -> None:
    """Ziel einer neuen oder geänderten Location: nur DOCKER_HOST_IP mit einem Port, den ein für mcp
    sichtbarer Container veröffentlicht, oder ein für mcp sichtbarer Container im NPM-Netz
    (NPM_DOCKER_NETWORK). Loopback, Port 81/9000/9443 und forward_host mit '/' sperrt schon guard."""
    if not locations:
        return
    cfg = settings()
    host_ip = cfg.docker_host_ip.lower()
    if not host_ip and not cfg.npm_docker_network:
        raise GuardError("Weder DOCKER_HOST_IP noch NPM_DOCKER_NETWORK ist gesetzt - Location-Ziele nicht prüfbar.")
    endpoints = [ep["Id"] for ep in await portainer().endpoints()]
    host_ports: set[int] | None = None
    for loc in locations:
        where = f"{label} {loc['path']}"
        target = loc["forward_host"].lower()
        if host_ip and target == host_ip:
            if host_ports is None:
                host_ports = set()
                for eid in endpoints:
                    for c in await portainer().containers(eid, True):
                        host_ports |= published_ports(c)
            if loc["forward_port"] not in host_ports:
                raise GuardError(
                    f"{where}: Port {loc['forward_port']} auf {cfg.docker_host_ip} wird von keinem für mcp sichtbaren "
                    "Container veröffentlicht."
                )
            continue
        if cfg.npm_docker_network:
            for eid in endpoints:
                found = [c for c in await portainer().containers(eid, True, {"name": [loc["forward_host"]]})
                         if container_name(c) == loc["forward_host"]]
                if not found:
                    continue
                data = await portainer().container_inspect(eid, loc["forward_host"])
                networks = ((data.get("NetworkSettings") or {}).get("Networks") or {}).keys()
                if cfg.npm_docker_network in networks:
                    break
                raise GuardError(
                    f"{where}: Container {loc['forward_host']} hängt nicht im NPM-Netz {cfg.npm_docker_network}."
                )
            else:
                raise GuardError(
                    f"{where}: Ziel {loc['forward_host']} ist weder DOCKER_HOST_IP noch ein für mcp sichtbarer "
                    f"Container im NPM-Netz {cfg.npm_docker_network}."
                )
            continue
        raise GuardError(f"{where}: Ziel {loc['forward_host']} ist nicht erlaubt - nur DOCKER_HOST_IP ({cfg.docker_host_ip}).")


async def apply_location_acl_support(locations: list[dict[str, Any]]) -> str | None:
    """access_list_id nur senden, wenn das Schema der Instanz es im Location-Objekt kennt
    (v2.16.0, nicht v2.12.6). Entfernt das Feld sonst in place und gibt einen Hinweis zurück."""
    if not any("access_list_id" in loc for loc in locations):
        return None
    if await npm().location_access_list_supported():
        return None
    for loc in locations:
        loc.pop("access_list_id", None)
    return "access_list_id wird nicht gesendet: diese NPM-Version kennt das Feld bei Locations nicht."


def _merge_locations(
    current: list[dict[str, Any]], sets: list[dict[str, Any]], removes: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(vollständige neue Liste, Änderungen). Nicht genannte Locations bleiben unverändert inkl. id;
    eine ersetzte behält ihre id, neue werden angehängt."""
    by_path = {s["path"]: s for s in sets}
    merged: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for old in current:
        path = old.get("path")
        if path in removes:
            changes.append({"pfad": path, "aktion": "entfernt", "ziel_vorher": guard.location_target(old)})
            continue
        new = by_path.get(path)
        if new is None or path in seen:
            merged.append(old)
            continue
        seen.add(path)
        item = {"id": old["id"], **new} if old.get("id") is not None else dict(new)
        if "access_list_id" not in new and "access_list_id" in old:
            item["access_list_id"] = old["access_list_id"]
        merged.append(item)
        if _location_key(item) != _location_key(old):
            changes.append({
                "pfad": path, "aktion": "geändert", "ziel": guard.location_target(item),
                "ziel_vorher": guard.location_target(old),
                "advanced_config": guard.redact_advanced_config(item.get("advanced_config")),
                "advanced_config_vorher": guard.redact_advanced_config(old.get("advanced_config")),
            })
    for new in sets:
        if new["path"] not in seen and new["path"] not in {o.get("path") for o in current}:
            merged.append(dict(new))
            changes.append({"pfad": new["path"], "aktion": "neu", "ziel": guard.location_target(new),
                            "advanced_config": guard.redact_advanced_config(new.get("advanced_config"))})
    return merged, changes


def _audit_location_changes(host: dict[str, Any], changes: list[dict[str, Any]]) -> None:
    for ch in changes:
        audit.log_event(
            "proxy_host_location_change", proxy_host_id=host.get("id"), domain_names=host.get("domain_names"),
            pfad=ch["pfad"], aktion=ch["aktion"], ziel=ch.get("ziel") or ch.get("ziel_vorher"),
        )


def _nginx_state(h: dict[str, Any]) -> tuple[bool | None, str | None]:
    meta = h.get("meta") or {}
    err = meta.get("nginx_err")
    if err:
        err = guard.redact_text(str(err))[:NGINX_ERR_MAX_CHARS]
    return meta.get("nginx_online"), err


async def _write_locations(
    host_id: int, before: dict[str, Any], merged: list[dict[str, Any]], changes: list[dict[str, Any]]
) -> dict[str, Any]:
    """PUT nur mit locations, danach prüfen: gespeicherte Liste = geschickte, nginx_online.
    Fällt nginx aus, einmal die vorherigen Locations zurückschreiben und erneut prüfen."""
    old = list(before.get("locations") or [])
    with_acl = any("access_list_id" in x for x in merged)
    target = {"id": host_id, "domain_names": before.get("domain_names")}
    result: dict[str, Any] = {"executed": True, "action": "proxy_host_update", "target": target,
                              "locations": changes, "ok": False}
    put_error = None
    try:
        await npm().update_proxy_host(host_id, {"locations": merged})
    except NpmError as exc:
        # Fehlerantwort heisst nicht sicher "nichts gespeichert": Ist-Zustand lesen.
        put_error = str(exc)
    after = await npm().proxy_host(host_id)
    stored = list(after.get("locations") or [])
    if put_error is not None and _locations_match(stored, old, with_acl):
        raise NpmError(f"Locations nicht geändert: {put_error}")
    _audit_location_changes(before, changes)
    if put_error is not None:
        result["put_error"] = put_error

    online, err = _nginx_state(after)
    if after.get("enabled") and online is False:
        result["error"] = "nginx-Test nach der Änderung fehlgeschlagen; NPM hat die Config des Hosts entfernt."
        result["nginx_err"] = err
        result["restore"] = await _restore_locations(host_id, before, old)
        if not result["restore"]["ok"]:
            result["warnung"] = (
                f"Wiederherstellung fehlgeschlagen - Proxy-Host {host_id} ({', '.join(before.get('domain_names') or [])}) "
                "ist OFFLINE. Sofort im NPM prüfen."
            )
        result["proxy_host"] = host_detail(await npm().proxy_host(host_id))
        return result
    if not _locations_match(stored, merged, with_acl):
        result["error"] = "Die gespeicherten Locations weichen von den geschickten ab. Mit npm_proxy_host_get prüfen."
        result["gespeichert"] = [_location_view(x) for x in stored]
        result["geschickt"] = [_location_view(x) for x in merged]
        result["proxy_host"] = host_detail(after)
        return result
    if not after.get("enabled"):
        result["note"] = "Proxy-Host ist deaktiviert; NPM schreibt dann keine nginx-Config, nginx wurde nicht geprüft."
    result["ok"] = True
    result["proxy_host"] = host_detail(after)
    return result


async def _restore_locations(host_id: int, before: dict[str, Any], old: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False}
    try:
        await npm().update_proxy_host(host_id, {"locations": old})
        h = await npm().proxy_host(host_id)
    except (NpmError, UnclearStateError) as exc:
        out["error"] = str(exc)
    else:
        online, err = _nginx_state(h)
        out["nginx_online"] = online
        out["locations_restored"] = _locations_match(list(h.get("locations") or []), old, True)
        if err and online is False:
            out["nginx_err"] = err
        out["ok"] = online is True and out["locations_restored"]
    audit.log_event(
        "proxy_host_location_restore", proxy_host_id=host_id, domain_names=before.get("domain_names"),
        ok=out["ok"], nginx_online=out.get("nginx_online"),
    )
    return out


async def precheck_proxy_host_create(domains: list[str], ssl: bool) -> dict[str, Any]:
    """Schutzliste, Duplikate und (bei ssl) DNS -> PUBLIC_IP. Wirft GuardError."""
    guard.require_protected_domains_configured()
    guard.block(guard.domain_protection(domains))
    taken = await find_hosts_by_domain(domains)
    if taken["proxy_hosts"] or taken["redirection_hosts"]:
        raise GuardError(f"Domain bereits in NPM vergeben: {taken}")
    dns = None
    if ssl:
        public_ip = settings().public_ip
        if not public_ip:
            raise GuardError("PUBLIC_IP ist nicht gesetzt - DNS-Vorabprüfung für das Zertifikat nicht möglich.")
        dns = await netcheck.check_dns(domains, public_ip)
        if not dns["ok"]:
            raise GuardError(f"DNS-Vorabprüfung fehlgeschlagen, nichts angelegt: {dns['domains']}")
    return {"duplicates": "keine", "dns": dns}


async def create_proxy_host_with_ssl(payload: dict[str, Any], ssl: bool, http2: bool, hsts: bool) -> dict[str, Any]:
    """Proxy-Host anlegen. Bei ssl wird danach ssl_forced (und http2/hsts) gesetzt,
    da NPM diese Flags beim Anlegen mit certificate_id='new' zurücksetzt.
    Fehler werden mit dem tatsächlichen Ist-Zustand gemeldet."""
    domains = payload["domain_names"]
    steps: dict[str, Any] = {}
    try:
        created = await npm().create_proxy_host(payload)
    except NpmError as exc:
        state = await _actual_state(domains)
        raise NpmError(f"Proxy-Host anlegen fehlgeschlagen: {exc}. Ist-Zustand: {state}") from None
    host_id = (created or {}).get("id")
    steps["proxy_host_id"] = host_id
    if not ssl:
        return {"proxy_host": host_detail(await npm().proxy_host(host_id)), **steps}
    current = await npm().proxy_host(host_id)
    if not current.get("certificate_id"):
        steps["ssl_forced_set"] = False
        steps["problem"] = "Proxy-Host angelegt, aber kein Zertifikat zugeordnet."
        return {"proxy_host": host_detail(current), **steps}
    try:
        updated = await npm().update_proxy_host(
            host_id, {"ssl_forced": True, "http2_support": bool(http2), "hsts_enabled": bool(hsts)}
        )
        steps["ssl_forced_set"] = bool((updated or {}).get("ssl_forced"))
    except NpmError as exc:
        steps["ssl_forced_set"] = False
        steps["problem"] = f"Zertifikat vorhanden, ssl_forced setzen fehlgeschlagen: {exc}"
    return {"proxy_host": host_detail(await npm().proxy_host(host_id)), **steps}


async def _actual_state(domains: list[str]) -> dict[str, Any]:
    try:
        hosts = [host_summary(h) for h in await npm().proxy_hosts() if set(domains) & set(h.get("domain_names") or [])]
        certs = [
            cert_info(c) for c in await npm().certificates() if set(domains) & set(c.get("domain_names") or [])
        ]
        return {"proxy_hosts": hosts, "certificates": certs}
    except NpmError as exc:
        return {"unbekannt": str(exc)}


# ---------------------------------------------------------------------------
# Lesende Tools
# ---------------------------------------------------------------------------


@tool()
async def npm_version() -> Any:
    """NPM-Version und Status (GET /api/)."""
    return await npm().version()


@tool()
async def npm_proxy_host_list(filter: str | None = None) -> list[dict[str, Any]]:
    """Proxy-Hosts: id, Domains, Forward-Ziel, enabled, Zertifikat inkl. Ablaufdatum, ssl_forced.
    filter: optional, Teil einer Domain oder des Forward-Hosts."""
    out = [host_summary(h) for h in await npm().proxy_hosts()]
    if filter:
        f = filter.lower()
        out = [h for h in out if any(f in d.lower() for d in h["domain_names"]) or f in str(h["forward_host"]).lower()]
    return out


@tool()
async def npm_proxy_host_get(id_or_domain: str | int) -> dict[str, Any]:
    """Ein Proxy-Host per id oder Domain, mit allen Einstellungen (advanced_config geschwärzt)."""
    host_id = await resolve_host_id(id_or_domain)
    return host_detail(await npm().proxy_host(host_id))


@tool()
async def npm_certificate_list() -> list[dict[str, Any]]:
    """Zertifikate mit Ablaufdatum; expiring_soon=true, wenn weniger als 14 Tage gültig."""
    certs = [cert_info(c) for c in await npm().certificates()]
    return sorted(certs, key=lambda c: (c["days_left"] is None, c["days_left"] if c["days_left"] is not None else 0))


@tool()
async def npm_redirection_host_list() -> list[dict[str, Any]]:
    """Redirection-Hosts (Weiterleitungen)."""
    return [
        {
            "id": h.get("id"),
            "domain_names": h.get("domain_names") or [],
            "forward": f"{h.get('forward_scheme')}://{h.get('forward_domain_name')}",
            "http_code": h.get("forward_http_code"),
            "preserve_path": bool(h.get("preserve_path")),
            "enabled": bool(h.get("enabled")),
            "certificate": cert_info(h.get("certificate")),
        }
        for h in await npm().redirection_hosts()
    ]


@tool()
async def npm_stream_list() -> list[dict[str, Any]]:
    """TCP/UDP-Streams."""
    return [
        {
            "id": s.get("id"),
            "incoming_port": s.get("incoming_port"),
            "forward": f"{s.get('forwarding_host')}:{s.get('forwarding_port')}",
            "tcp": bool(s.get("tcp_forwarding")),
            "udp": bool(s.get("udp_forwarding")),
            "enabled": bool(s.get("enabled")),
        }
        for s in await npm().streams()
    ]


@tool()
async def npm_access_list_list() -> list[dict[str, Any]]:
    """Access-Lists (nur Name und Anzahl Einträge, keine Benutzernamen oder Passwörter)."""
    return [
        {
            "id": a.get("id"),
            "name": a.get("name"),
            "satisfy_any": bool(a.get("satisfy_any")),
            "pass_auth": bool(a.get("pass_auth")),
            "auth_users": len(a.get("items") or []),
            "client_rules": len(a.get("clients") or []),
            "proxy_host_count": a.get("proxy_host_count"),
        }
        for a in await npm().access_lists()
    ]


@tool()
async def npm_host_report() -> Any:
    """Anzahl Proxy-, Redirection-, Dead-Hosts und Streams (GET /api/reports/hosts)."""
    return await npm().host_report()


# ---------------------------------------------------------------------------
# Schreibende Tools
# ---------------------------------------------------------------------------


@tool()
async def npm_proxy_host_create(
    domain_names: list[str],
    forward_scheme: str,
    forward_host: str,
    forward_port: int,
    websocket: bool = False,
    block_exploits: bool = True,
    ssl: bool = True,
    http2: bool = True,
    hsts: bool = False,
    access_list_id: int | None = None,
    advanced_config: str | None = None,
    locations: list[dict[str, Any]] | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Proxy-Host anlegen. Duplikate werden verhindert. Bei ssl=true muss jede
    Domain auf PUBLIC_IP auflösen, sonst Abbruch; dann wird ein Let's-Encrypt-
    Zertifikat angefordert und ssl_forced gesetzt. advanced_config: nur einzelne
    nginx-Direktiven aus der Allowlist (add_header, expires, client_max_body_size,
    proxy_*_timeout, proxy_buffer*, gzip*, real_ip_header, set_real_ip_from), keine
    Blöcke, kein location/proxy_pass/alias/root/include.
    locations: Custom Locations wie bei npm_proxy_host_update (locations_set), gleiche Prüfungen.
    Ohne confirm=true nur Vorschau."""
    domains = guard.validate_domains(domain_names)
    scheme, host, port = guard.validate_forward(forward_scheme, forward_host, forward_port)
    locs = guard.validate_locations(locations)
    checks = await precheck_proxy_host_create(domains, ssl)
    await check_location_targets(locs)
    acl_note = await apply_location_acl_support(locs)
    payload = await build_create_payload(
        domains, scheme, host, port, websocket, block_exploits, ssl, http2, hsts, access_list_id, advanced_config, locs
    )
    if acl_note:
        checks["hinweis"] = acl_note
    if not guard.is_confirmed(confirm):
        return guard.preview("proxy_host_create", payload=_payload_preview(payload), checks=checks)
    result = await create_proxy_host_with_ssl(payload, ssl, http2, hsts)
    if locs and result.get("proxy_host_id"):
        _audit_location_changes(
            {"id": result["proxy_host_id"], "domain_names": domains},
            [{"pfad": x["path"], "aktion": "neu", "ziel": guard.location_target(x)} for x in locs],
        )
    return {"executed": True, "action": "proxy_host_create", **result}


_UPDATE_FIELDS = {
    "domain_names": "domain_names",
    "forward_scheme": "forward_scheme",
    "forward_host": "forward_host",
    "forward_port": "forward_port",
    "websocket": "allow_websocket_upgrade",
    "block_exploits": "block_exploits",
    "ssl_forced": "ssl_forced",
    "http2": "http2_support",
    "hsts": "hsts_enabled",
    "access_list_id": "access_list_id",
    "advanced_config": "advanced_config",
}


@tool()
async def npm_proxy_host_update(
    id: int,
    domain_names: list[str] | None = None,
    forward_scheme: str | None = None,
    forward_host: str | None = None,
    forward_port: int | None = None,
    websocket: bool | None = None,
    block_exploits: bool | None = None,
    ssl_forced: bool | None = None,
    http2: bool | None = None,
    hsts: bool | None = None,
    access_list_id: int | None = None,
    advanced_config: str | None = None,
    locations_set: list[dict[str, Any]] | None = None,
    locations_remove: list[str] | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Proxy-Host ändern - nur die übergebenen Felder. Holt den aktuellen Stand
    und zeigt den Diff. Geschützte Domains werden blockiert. advanced_config nur mit
    Direktiven aus der Allowlist (wie bei npm_proxy_host_create).
    Custom Locations (nicht zusammen mit den übrigen Feldern):
    locations_set: Liste von {path, forward_scheme, forward_host, forward_port, forward_path?,
    advanced_config?, access_list_id?}; gleicher path ersetzt die vorhandene Location, sonst neu.
    locations_remove: Pfade, die entfernt werden. Alle übrigen Locations bleiben unverändert.
    path: '/segment[/segment...]' (nicht '/' allein). Ziel nur DOCKER_HOST_IP mit einem von einem
    sichtbaren Container veröffentlichten Port oder ein Container im NPM-Netz; nie Loopback,
    nie Port 81/9000/9443. Schlägt der nginx-Test danach fehl, werden die vorherigen Locations
    einmal automatisch zurückgeschrieben. Ohne confirm=true nur Vorschau."""
    guard.require_protected_domains_configured()
    host_id = guard.validate_positive_id(id, "id")
    if advanced_config is not None:
        advanced_config = guard.validate_advanced_config(advanced_config)
    if locations_set or locations_remove:
        others = [k for k, v in {
            "domain_names": domain_names, "forward_scheme": forward_scheme, "forward_host": forward_host,
            "forward_port": forward_port, "websocket": websocket, "block_exploits": block_exploits,
            "ssl_forced": ssl_forced, "http2": http2, "hsts": hsts, "access_list_id": access_list_id,
            "advanced_config": advanced_config,
        }.items() if v is not None]
        if others:
            raise GuardError(f"Locations bitte in einem eigenen Aufruf ändern, ohne {', '.join(others)}.")
        return await _update_locations(host_id, locations_set, locations_remove, confirm)
    current = await npm().proxy_host(host_id)
    guard.block(guard.domain_protection(current.get("domain_names") or []))

    given = {
        "domain_names": domain_names, "forward_scheme": forward_scheme, "forward_host": forward_host,
        "forward_port": forward_port, "websocket": websocket, "block_exploits": block_exploits,
        "ssl_forced": ssl_forced, "http2": http2, "hsts": hsts, "access_list_id": access_list_id,
        "advanced_config": advanced_config,
    }
    changes: dict[str, Any] = {}
    for param, value in given.items():
        if value is None:
            continue
        field = _UPDATE_FIELDS[param]
        if param == "domain_names":
            value = guard.validate_domains(value)
            guard.block(guard.domain_protection(value))
            new = [d for d in value if d not in (current.get("domain_names") or [])]
            if new:
                taken = await find_hosts_by_domain(new)
                if taken["proxy_hosts"] or taken["redirection_hosts"]:
                    raise GuardError(f"Domain bereits in NPM vergeben: {taken}")
        elif param in ("forward_scheme", "forward_host", "forward_port"):
            s, h, p = guard.validate_forward(
                forward_scheme or current.get("forward_scheme"),
                forward_host or current.get("forward_host"),
                forward_port or current.get("forward_port"),
            )
            value = {"forward_scheme": s, "forward_host": h, "forward_port": p}[param]
        elif param == "access_list_id":
            value = int(value)
        if current.get(field) != value and not (isinstance(value, bool) and bool(current.get(field)) == value):
            changes[field] = value

    if (changes.get("ssl_forced") or changes.get("http2_support") or changes.get("hsts_enabled")) and not current.get("certificate_id"):
        raise GuardError("ssl_forced/http2/hsts brauchen ein Zertifikat; der Proxy-Host hat keins.")

    def show(field: str, v: Any) -> Any:
        return guard.redact_advanced_config(v) if field == "advanced_config" else v

    diff = {f: {"before": show(f, current.get(f)), "after": show(f, v)} for f, v in changes.items()}
    target = {"id": host_id, "domain_names": current.get("domain_names")}
    if not changes:
        return {"executed": False, "preview": False, "action": "proxy_host_update", "target": target, "diff": {}, "note": "Keine Änderung."}
    if not guard.is_confirmed(confirm):
        return guard.preview("proxy_host_update", target=target, diff=diff)
    await npm().update_proxy_host(host_id, changes)
    return {"executed": True, "action": "proxy_host_update", "target": target, "diff": diff,
            "proxy_host": host_detail(await npm().proxy_host(host_id))}


async def _update_locations(
    host_id: int, locations_set: list[dict[str, Any]] | None, locations_remove: list[str] | None, confirm: bool
) -> dict[str, Any]:
    sets = guard.validate_locations(locations_set, "locations_set")
    if locations_remove is not None and not isinstance(locations_remove, list):
        raise GuardError("locations_remove muss eine Liste von Pfaden sein.")
    removes: list[str] = []
    for i, p in enumerate(locations_remove or []):
        path = guard.validate_location_path(p, f"locations_remove[{i}]")
        if path not in removes:
            removes.append(path)
    both = sorted({s["path"] for s in sets} & set(removes))
    if both:
        raise GuardError(f"Pfad in locations_set und locations_remove zugleich: {both}")
    current = await npm().proxy_host(host_id)
    guard.block(guard.domain_protection(current.get("domain_names") or []))
    existing = list(current.get("locations") or [])
    missing = [p for p in removes if p not in {loc.get("path") for loc in existing}]
    if missing:
        raise GuardError(f"locations_remove: keine Location mit Pfad {missing} auf diesem Proxy-Host.")
    merged, changes = _merge_locations(existing, sets, removes)
    if len(merged) > guard.LOCATIONS_MAX:
        raise GuardError(f"Höchstens {guard.LOCATIONS_MAX} Locations pro Host (wären {len(merged)}).")
    paths = [loc.get("path") for loc in merged]
    dup = sorted({p for p in paths if paths.count(p) > 1})
    if dup:
        raise GuardError(f"Pfad mehrfach vorhanden: {dup}")
    changed_paths = {ch["pfad"] for ch in changes if ch["aktion"] != "entfernt"}
    await check_location_targets([s for s in sets if s["path"] in changed_paths], "locations_set")
    acl_note = await apply_location_acl_support(merged)

    target = {"id": host_id, "domain_names": current.get("domain_names")}
    if not changes:
        return {"executed": False, "preview": False, "action": "proxy_host_update", "target": target,
                "locations": [], "note": "Keine Änderung."}
    extra = {"hinweis": acl_note} if acl_note else {}
    if not guard.is_confirmed(confirm):
        return guard.preview("proxy_host_update", target=target, locations=changes,
                             locations_after=[_location_view(x) for x in merged], **extra)
    result = await _write_locations(host_id, current, merged, changes)
    return {**result, **extra}


async def _enable_disable(host_id: int, enable: bool, confirm: bool) -> dict[str, Any]:
    guard.require_protected_domains_configured()
    hid = guard.validate_positive_id(host_id, "id")
    current = await npm().proxy_host(hid)
    guard.block(guard.domain_protection(current.get("domain_names") or []))
    action = "proxy_host_enable" if enable else "proxy_host_disable"
    target = host_summary(current)
    if bool(current.get("enabled")) == enable:
        return {"executed": False, "preview": False, "action": action, "target": target,
                "note": "Proxy-Host ist bereits " + ("aktiv." if enable else "deaktiviert.")}
    if not guard.is_confirmed(confirm):
        return guard.preview(action, target=target)
    if enable:
        await npm().enable_proxy_host(hid)
    else:
        await npm().disable_proxy_host(hid)
    return {"executed": True, "action": action, "target": host_summary(await npm().proxy_host(hid))}


@tool()
async def npm_proxy_host_enable(id: int, confirm: bool = False) -> dict[str, Any]:
    """Proxy-Host aktivieren. Ohne confirm=true nur Vorschau."""
    return await _enable_disable(id, True, confirm)


@tool()
async def npm_proxy_host_disable(id: int, confirm: bool = False) -> dict[str, Any]:
    """Proxy-Host deaktivieren (nicht löschen). Geschützte Domains werden blockiert.
    Ohne confirm=true nur Vorschau."""
    return await _enable_disable(id, False, confirm)


@tool()
async def npm_certificate_renew(id: int, confirm: bool = False) -> dict[str, Any]:
    """Let's-Encrypt-Zertifikat erneuern. Ohne confirm=true nur Vorschau."""
    cid = guard.validate_positive_id(id, "id")
    certs = {c.get("id"): c for c in await npm().certificates()}
    cert = certs.get(cid)
    if not cert:
        raise NpmError(f"Zertifikat {cid} nicht gefunden.")
    if cert.get("provider") != "letsencrypt":
        raise GuardError(f"Zertifikat {cid} ist kein Let's-Encrypt-Zertifikat (provider={cert.get('provider')}).")
    target = cert_info(cert)
    if not guard.is_confirmed(confirm):
        return guard.preview("certificate_renew", target=target)
    renewed = await npm().renew_certificate(cid)
    return {"executed": True, "action": "certificate_renew", "before": target, "after": cert_info(renewed if isinstance(renewed, dict) else None)}

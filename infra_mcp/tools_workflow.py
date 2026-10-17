"""Kombinierte Abläufe (infra_*): Dienst veröffentlichen, aktualisieren, Status.

Bei Fehlern wird nichts automatisch zurückgebaut. Die Antwort nennt genau,
was angelegt wurde und was fehlt.
"""

from __future__ import annotations

import asyncio
from typing import Any

from . import guard, netcheck
from .app import npm, portainer, tool
from .config import settings
from .errors import GuardError, InfraError, NpmError, PortainerError, UnclearStateError
from .tools_npm import (
    build_create_payload,
    create_proxy_host_with_ssl,
    find_hosts_by_domain,
    host_summary,
)
from .tools_portainer import (
    ERROR_RE,
    _block_protected_stack,
    _require_compose_type,
    env_pairs,
    fetch_logs,
    find_stack_by_name,
    precheck_stack_create,
    redeploy_stack,
    stack_containers,
    stack_summary,
    wait_until_running,
)
from .version import version_info

LOG_TAIL_REPORT = 30
CONTAINER_APPEAR_SECONDS = 30
CONTAINER_POLL_SECONDS = 3.0


@tool()
def infra_version() -> dict[str, str]:
    """Version des laufenden infra-mcp (APP_VERSION aus dem Git-Tag), Commit und Build-Zeit."""
    return version_info()


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _container_name(c: dict[str, Any]) -> str:
    return ((c.get("Names") or ["/"])[0]).lstrip("/")


async def _find_service_container(endpoint_id: int, stack_name: str, service: str) -> dict[str, Any] | None:
    """Container eines Compose-Dienstes. Wartet kurz, falls er noch nicht gelistet ist."""
    attempts = max(1, int(CONTAINER_APPEAR_SECONDS / max(CONTAINER_POLL_SECONDS, 0.1)))
    for _ in range(attempts):
        for c in await stack_containers(endpoint_id, stack_name):
            if (c.get("Labels") or {}).get("com.docker.compose.service") == service:
                return c
        await asyncio.sleep(CONTAINER_POLL_SECONDS)
    return None


async def _log_tail(endpoint_id: int, container: str, lines: int = LOG_TAIL_REPORT) -> list[str]:
    try:
        return (await fetch_logs(endpoint_id, container, lines)).splitlines()[-lines:]
    except InfraError as exc:
        return [f"(Logs nicht lesbar: {exc})"]


async def _proxy_hosts_for(names: set[str]) -> list[dict[str, Any]]:
    wanted = {n.lower() for n in names if n}
    return [h for h in await npm().proxy_hosts() if str(h.get("forward_host") or "").lower() in wanted]


def _network_hint(network: str, service: str) -> str:
    return (
        f"Der Dienst '{service}' muss im Docker-Netz '{network}' von NPM hängen. In der Compose-Datei ergänzen:\n"
        f"  services:\n    {service}:\n      networks: [npm]\n"
        f"  networks:\n    npm:\n      external: true\n      name: {network}"
    )


# ---------------------------------------------------------------------------
# infra_publish_service
# ---------------------------------------------------------------------------


@tool()
async def infra_publish_service(
    stack_name: str,
    endpoint_id: int,
    compose_content: str,
    domain: str,
    forward_port: int,
    env: dict[str, str] | None = None,
    websocket: bool = False,
    service: str | None = None,
    forward_scheme: str = "http",
    allow_docker_socket: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Neuen Dienst komplett veröffentlichen:
    1. Prüfen: Stack-Name und Domain frei, Domain löst auf PUBLIC_IP auf, Compose gültig,
       Dienst hängt im NPM-Netz (NPM_DOCKER_NETWORK).
    2. Stack anlegen und warten, bis der Container läuft (healthy, falls Healthcheck), max. 120 s.
    3. Forward-Ziel = Containername im gemeinsamen Netz mit NPM (wird nach dem Start geprüft).
    4. Proxy-Host mit Let's-Encrypt-Zertifikat anlegen, ssl_forced setzen.
    5. HTTPS-Abruf testen (Statuscode, Zertifikat gültig).
    service: Name des Compose-Dienstes, nötig wenn die Datei mehrere Dienste hat.
    Bei Fehlern wird nichts zurückgebaut; die Antwort nennt, was angelegt wurde und was fehlt.
    Ohne confirm=true nur Prüfung und Vorschau.
    """
    cfg = settings()
    if not cfg.npm_docker_network:
        raise GuardError("NPM_DOCKER_NETWORK ist nicht gesetzt (Docker-Netz, in dem NPM hängt).")
    if not cfg.public_ip:
        raise GuardError("PUBLIC_IP ist nicht gesetzt.")
    guard.require_protected_domains_configured()

    # 1. Prüfungen (auch in der Vorschau)
    doc = await precheck_stack_create(stack_name, endpoint_id, compose_content, allow_docker_socket)
    eid = int(endpoint_id)
    d = guard.validate_domain(domain)
    guard.block(guard.domain_protection([d]))
    scheme, _, port = guard.validate_forward(forward_scheme, "placeholder", forward_port)
    taken = await find_hosts_by_domain([d])
    if taken["proxy_hosts"] or taken["redirection_hosts"]:
        raise GuardError(f"Domain '{d}' ist in NPM bereits vergeben: {taken}")
    dns = await netcheck.check_dns([d], cfg.public_ip)
    if not dns["ok"]:
        raise GuardError(f"DNS-Vorabprüfung fehlgeschlagen, nichts angelegt: {dns['domains'][d]}")

    services = list(doc["services"].keys())
    if service is None:
        if len(services) != 1:
            raise GuardError(f"Compose-Datei hat mehrere Dienste {services}; Parameter service angeben.")
        service = services[0]
    if service not in doc["services"]:
        raise GuardError(f"Dienst '{service}' nicht in der Compose-Datei (vorhanden: {services}).")
    if cfg.npm_docker_network not in guard.compose_service_networks(doc, service):
        raise GuardError("Abbruch vor dem Anlegen. " + _network_hint(cfg.npm_docker_network, service))
    expected_name = (doc["services"][service] or {}).get("container_name") or f"{stack_name}-{service}-1"
    pairs = env_pairs(env)

    plan = {
        "stack": {"name": stack_name, "endpoint_id": eid, "services": services, "env_names": [p["name"] for p in pairs]},
        "service": service,
        "forward": f"{scheme}://{expected_name}:{port}",
        "domain": d,
        "dns": dns["domains"][d],
        "npm_network": cfg.npm_docker_network,
        "compose": guard.redact_compose(compose_content),
    }
    if not guard.is_confirmed(confirm):
        return guard.preview("publish_service", plan=plan)

    report: dict[str, Any] = {"executed": True, "action": "publish_service", "ok": False, "created": [], "missing": []}
    all_parts = ["stack", "container_running", "proxy_host", "certificate", "https_ok"]

    def fail(step: str, message: str, done: list[str], **extra: Any) -> dict[str, Any]:
        report.update(failed_step=step, error=guard.redact_text(message), **extra)
        report["missing"] = [p for p in all_parts if p not in done]
        return report

    # 2. Stack anlegen
    done: list[str] = []
    try:
        created = await portainer().stack_create_compose(eid, stack_name, compose_content, pairs)
    except UnclearStateError as exc:
        return fail("stack_create", str(exc), done, state="unklar")
    except PortainerError as exc:
        existing = await find_stack_by_name(stack_name)
        if existing:
            report["created"].append({"stack": stack_summary(existing)})
            done.append("stack")
        return fail("stack_create", str(exc), done)
    stack_id = (created or {}).get("Id")
    report["created"].append({"stack": {"id": stack_id, "name": stack_name}})
    done.append("stack")

    container = await _find_service_container(eid, stack_name, service)
    if not container:
        return fail("wait_running", f"Kein Container für Dienst '{service}' gefunden.", done)
    cname = _container_name(container)
    wait = await wait_until_running(eid, [cname])
    report["container"] = {"name": cname, **wait["containers"].get(cname, {})}
    if not wait["ok"]:
        return fail("wait_running", wait["reason"], done, logs=await _log_tail(eid, cname))
    done.append("container_running")

    # 3. Forward-Ziel im NPM-Netz
    data = await portainer().container_inspect(eid, cname)
    networks = list(((data.get("NetworkSettings") or {}).get("Networks") or {}).keys())
    if cfg.npm_docker_network not in networks:
        return fail("network_check", _network_hint(cfg.npm_docker_network, service), done, container_networks=networks)

    # 4. Proxy-Host mit Zertifikat
    try:
        payload = await build_create_payload([d], scheme, cname, port, websocket, True, True, True, False, None, None)
        result = await create_proxy_host_with_ssl(payload, True, True, False)
    except (NpmError, UnclearStateError, GuardError) as exc:
        state = await find_hosts_by_domain([d])
        if state["proxy_hosts"]:
            done.append("proxy_host")
        return fail("proxy_host_create", str(exc), done, npm_state=state)
    host = result["proxy_host"]
    report["created"].append({"proxy_host": host})
    done.append("proxy_host")
    if host.get("certificate"):
        report["created"].append({"certificate": host["certificate"]})
        done.append("certificate")
    if result.get("problem"):
        return fail("certificate", result["problem"], done)

    # 5. HTTPS-Test
    https = await netcheck.https_check(d)
    report["https"] = https
    if not https["ok"]:
        return fail("https_check", "HTTPS-Test nicht erfolgreich (siehe https).", done)
    done.append("https_ok")
    report["ok"] = True
    report["missing"] = []
    return report


# ---------------------------------------------------------------------------
# infra_update_service
# ---------------------------------------------------------------------------


@tool()
async def infra_update_service(stack_name: str, confirm: bool = False) -> dict[str, Any]:
    """Update ausrollen: Images neu pullen, Stack redeployen (prune aus), warten bis
    running/healthy, danach die letzten Log-Zeilen und den HTTPS-Test der zugehörigen
    Domain(s) ausgeben. Ohne confirm=true nur Vorschau."""
    name = guard.validate_stack_name(stack_name)
    stack = await find_stack_by_name(name)
    if not stack:
        raise GuardError(f"Stack '{name}' nicht gefunden.")
    _require_compose_type(stack)
    await _block_protected_stack(stack)
    eid = stack["EndpointId"]
    before = await stack_containers(eid, stack["Name"])
    names = {_container_name(c) for c in before} | {(c.get("Labels") or {}).get("com.docker.compose.service", "") for c in before}
    hosts = await _proxy_hosts_for(names)
    domains = [dom for h in hosts for dom in h.get("domain_names") or []]
    info = {
        "stack": stack_summary(stack),
        "containers": [{"name": _container_name(c), "image": c.get("Image"), "state": c.get("State")} for c in before],
        "domains": domains,
    }
    if not guard.is_confirmed(confirm):
        return guard.preview("update_service", **info, pull_image=True, prune=False)

    report: dict[str, Any] = {"executed": True, "action": "update_service", **info}
    report["redeploy"] = await redeploy_stack(stack, pull_image=True)
    after = await stack_containers(eid, stack["Name"])
    cnames = [_container_name(c) for c in after]
    wait = await wait_until_running(eid, cnames) if cnames else {"ok": False, "reason": "Keine Container gefunden", "containers": {}}
    report["wait"] = wait
    report["logs"] = {c: await _log_tail(eid, c) for c in cnames}
    report["https"] = {dom: await netcheck.https_check(dom) for dom in domains}
    report["ok"] = bool(wait["ok"]) and all(r["ok"] for r in report["https"].values())
    return report


# ---------------------------------------------------------------------------
# infra_service_status
# ---------------------------------------------------------------------------


async def _locate_by_domain(domain: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]], dict[str, Any] | None]:
    """Domain -> (Stack, Proxy-Hosts, Container)."""
    hosts = [h for h in await npm().proxy_hosts() if domain in [x.lower() for x in h.get("domain_names") or []]]
    if not hosts:
        raise NpmError(f"Kein Proxy-Host für '{domain}' gefunden.")
    target = str(hosts[0].get("forward_host") or "")
    for ep in await portainer().endpoints():
        for c in await portainer().containers(ep["Id"], True, {"name": [target]}):
            if _container_name(c) == target:
                project = (c.get("Labels") or {}).get("com.docker.compose.project")
                stack = await find_stack_by_name(project) if project else None
                return stack, hosts, {**c, "_endpoint_id": ep["Id"]}
    return None, hosts, None


@tool()
async def infra_service_status(stack_name_or_domain: str) -> dict[str, Any]:
    """Übersicht zu einem Dienst (Stack-Name oder Domain): Stack, Container-Status,
    Health, letzte Fehler im Log, Proxy-Host, Zertifikatsablauf, DNS und HTTPS-Test."""
    target = (stack_name_or_domain or "").strip().lower()
    out: dict[str, Any] = {"query": target}
    stack = None
    hosts: list[dict[str, Any]] = []
    containers: list[dict[str, Any]] = []
    eid = None
    if "." in target:
        d = guard.validate_domain(target)
        stack, hosts, single = await _locate_by_domain(d)
        if single:
            eid = single["_endpoint_id"]
            containers = [single]
        if not single:
            out["warning"] = f"Forward-Ziel '{hosts[0].get('forward_host')}' ist kein sichtbarer Container."
    else:
        name = guard.validate_stack_name(target)
        stack = await find_stack_by_name(name)
        if not stack:
            raise GuardError(f"Stack '{name}' nicht gefunden.")
    if stack:
        eid = stack.get("EndpointId") or eid
        containers = await stack_containers(eid, stack["Name"])
        if not hosts:
            names = {_container_name(c) for c in containers} | {
                (c.get("Labels") or {}).get("com.docker.compose.service", "") for c in containers
            }
            hosts = await _proxy_hosts_for(names)
    out["stack"] = stack_summary(stack) if stack else None

    cont_out = []
    for c in containers:
        cname = _container_name(c)
        data = await portainer().container_inspect(eid, cname)
        state = data.get("State") or {}
        lines = (await fetch_logs(eid, cname, 200, None, bool((data.get("Config") or {}).get("Tty")))).splitlines()
        errors = [ln for ln in lines if ERROR_RE.search(ln)][-10:]
        cont_out.append(
            {
                "name": cname,
                "image": (data.get("Config") or {}).get("Image"),
                "status": state.get("Status"),
                "health": (state.get("Health") or {}).get("Status"),
                "restart_count": data.get("RestartCount"),
                "started_at": state.get("StartedAt"),
                "exit_code": state.get("ExitCode"),
                "oom_killed": state.get("OOMKilled"),
                "recent_errors": errors,
            }
        )
    out["containers"] = cont_out
    out["proxy_hosts"] = [host_summary(h) for h in hosts]
    domains = sorted({dom for h in hosts for dom in h.get("domain_names") or []})
    if domains and settings().public_ip:
        out["dns"] = await netcheck.check_dns(domains, settings().public_ip)
    out["https"] = {dom: await netcheck.https_check(dom) for dom in domains}
    return out

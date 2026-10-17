"""Portainer-Tools (portainer_*): Container, Stacks, Images, Volumes, Netzwerke."""

from __future__ import annotations

import asyncio
import datetime
import re
import time
from typing import Any

from . import guard
from .app import portainer, tool
from .errors import GuardError, PortainerError, UnclearStateError
from .portainer_client import (
    DEPLOY_TIMEOUT,
    STACK_STATUS,
    STACK_STATUS_DEPLOYING,
    STACK_STATUS_ERROR,
    STACK_TYPES,
    demux_docker_stream,
    summarize_stats,
)

LOG_TAIL_MAX = 5000
LOG_OUTPUT_MAX_CHARS = 60_000
WAIT_RUNNING_SECONDS = 120
WAIT_POLL_SECONDS = 3.0
STACK_DEPLOY_POLL_SECONDS = 2.0


# ---------------------------------------------------------------------------
# Hilfsfunktionen (auch von tools_workflow genutzt)
# ---------------------------------------------------------------------------


def _ts(value: Any) -> str | None:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc).isoformat()
    return None


def container_summary(c: dict[str, Any]) -> dict[str, Any]:
    """Kurzform eines Eintrags aus /containers/json."""
    labels = c.get("Labels") or {}
    names = [n.lstrip("/") for n in c.get("Names") or []]
    ports = []
    for p in c.get("Ports") or []:
        if p.get("PublicPort"):
            ports.append(f"{p.get('IP', '')}:{p['PublicPort']}->{p.get('PrivatePort')}/{p.get('Type')}")
        else:
            ports.append(f"{p.get('PrivatePort')}/{p.get('Type')}")
    return {
        "id": (c.get("Id") or "")[:12],
        "name": names[0] if names else "",
        "image": c.get("Image"),
        "state": c.get("State"),
        "status": c.get("Status"),
        "stack": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "ports": sorted(set(ports)),
        "created": _ts(c.get("Created")),
    }


def inspect_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Status, Image, Ports, Mounts, RestartPolicy, Health, Networks. Env nur Namen."""
    state = data.get("State") or {}
    cfg = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    net = data.get("NetworkSettings") or {}
    health = state.get("Health") or None
    health_out = None
    if health:
        logs = health.get("Log") or []
        last = logs[-1] if logs else {}
        health_out = {
            "status": health.get("Status"),
            "failing_streak": health.get("FailingStreak"),
            "last_exit_code": last.get("ExitCode"),
            "last_output": guard.redact_text((last.get("Output") or "").strip()[-500:]),
        }
    ports = {}
    for cport, bindings in (net.get("Ports") or {}).items():
        ports[cport] = [f"{b.get('HostIp', '')}:{b.get('HostPort')}" for b in bindings or []]
    mounts = [
        {
            "type": m.get("Type"),
            "source": m.get("Name") or m.get("Source"),
            "destination": m.get("Destination"),
            "rw": m.get("RW"),
        }
        for m in data.get("Mounts") or []
    ]
    networks = {
        name: {"ip": n.get("IPAddress"), "aliases": n.get("Aliases") or [], "dns_names": n.get("DNSNames") or []}
        for name, n in (net.get("Networks") or {}).items()
    }
    labels = cfg.get("Labels") or {}
    return {
        "id": (data.get("Id") or "")[:12],
        "name": (data.get("Name") or "").lstrip("/"),
        "image": cfg.get("Image"),
        "image_id": data.get("Image"),
        "status": state.get("Status"),
        "running": state.get("Running"),
        "restarting": state.get("Restarting"),
        "exit_code": state.get("ExitCode"),
        "error": state.get("Error") or None,
        "oom_killed": state.get("OOMKilled"),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "restart_count": data.get("RestartCount"),
        "restart_policy": host.get("RestartPolicy"),
        "health": health_out,
        "ports": ports,
        "mounts": mounts,
        "networks": networks,
        "env_names": guard.env_names(cfg.get("Env")),
        "stack": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "tty": cfg.get("Tty"),
    }


def stack_summary(s: dict[str, Any]) -> dict[str, Any]:
    git = s.get("GitConfig") or None
    return {
        "id": s.get("Id"),
        "name": s.get("Name"),
        "type": STACK_TYPES.get(s.get("Type"), s.get("Type")),
        "status": STACK_STATUS.get(s.get("Status"), s.get("Status")),
        "endpoint_id": s.get("EndpointId"),
        "git": {"url": git.get("URL"), "reference": git.get("ReferenceName"), "file": git.get("ConfigFilePath")} if git else None,
        "env_names": guard.env_names(s.get("Env")),
        "created": _ts(s.get("CreationDate")),
        "updated": _ts(s.get("UpdateDate")),
        "updated_by": s.get("UpdatedBy") or None,
    }


async def find_stack_by_name(name: str) -> dict[str, Any] | None:
    for s in await portainer().stacks():
        if (s.get("Name") or "").lower() == name.lower():
            return s
    return None


async def stack_containers(endpoint_id: int, stack_name: str) -> list[dict[str, Any]]:
    return await portainer().containers(
        endpoint_id, True, {"label": [f"com.docker.compose.project={stack_name}"]}
    )


def parse_since(since: str | int | None) -> int | None:
    """'10m', '2h', '1d', Unix-Zeitstempel oder ISO-Datum -> Unix-Zeitstempel."""
    if since is None or since == "":
        return None
    if isinstance(since, (int, float)):
        return int(since)
    s = str(since).strip()
    m = re.fullmatch(r"(\d+)\s*([smhd])", s.lower())
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return int(time.time()) - int(m.group(1)) * mult
    if s.isdigit():
        return int(s)
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise GuardError(f"since nicht verständlich: {since!r} (z.B. '30m', '2h', '1d', Unix-Zeit oder ISO-Datum)") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def filter_lines(text: str, grep: str | None) -> list[str]:
    lines = text.splitlines()
    if not grep:
        return lines
    try:
        rx = re.compile(grep, re.IGNORECASE)
        return [ln for ln in lines if rx.search(ln)]
    except re.error:
        g = grep.lower()
        return [ln for ln in lines if g in ln.lower()]


async def fetch_logs(endpoint_id: int, container: str, tail: int, since: int | None = None, tty: bool | None = None) -> str:
    raw = await portainer().container_logs(endpoint_id, container, tail, since)
    if tty is None:
        tty = bool(((await portainer().container_inspect(endpoint_id, container)).get("Config") or {}).get("Tty"))
    text = raw.decode("utf-8", errors="replace") if tty else demux_docker_stream(raw)
    return guard.redact_text(text)


ERROR_RE = re.compile(r"(?i)\b(error|exception|fatal|traceback|critical|panic|failed|refused|denied)\b")


async def wait_until_running(endpoint_id: int, containers: list[str], timeout: float = WAIT_RUNNING_SECONDS) -> dict[str, Any]:
    """Wartet, bis alle Container laufen (bzw. healthy sind, falls ein Healthcheck
    definiert ist). Bricht ab bei unhealthy, exited/dead oder nach timeout Sekunden."""
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while True:
        all_ok = True
        failed = False
        for name in containers:
            try:
                data = await portainer().container_inspect(endpoint_id, name)
            except PortainerError as exc:
                last[name] = {"status": "unbekannt", "error": str(exc)}
                all_ok = False
                continue
            state = data.get("State") or {}
            health = (state.get("Health") or {}).get("Status")
            status = state.get("Status")
            last[name] = {"status": status, "health": health, "restart_count": data.get("RestartCount")}
            if status in ("exited", "dead") or health == "unhealthy":
                failed = True
            if status != "running" or (health is not None and health != "healthy"):
                all_ok = False
        if all_ok:
            return {"ok": True, "containers": last}
        if failed:
            return {"ok": False, "reason": "Container beendet oder unhealthy", "containers": last}
        if time.monotonic() >= deadline:
            return {"ok": False, "reason": f"Nach {int(timeout)} s nicht running/healthy", "containers": last}
        await asyncio.sleep(WAIT_POLL_SECONDS)


async def _inspect_checked(endpoint_id: int, container: str) -> dict[str, Any]:
    c = guard.validate_container_ref(container)
    return await portainer().container_inspect(endpoint_id, c)


async def _stack_checked(stack_id: int) -> dict[str, Any]:
    sid = guard.validate_positive_id(stack_id, "stack_id")
    return await portainer().stack(sid)


async def _block_protected_stack(stack: dict[str, Any]) -> None:
    """Stack-Name geschützt oder einer seiner Container geschützt -> blockieren."""
    guard.block(guard.stack_protection(stack.get("Name") or ""))
    endpoint_id = stack.get("EndpointId")
    if endpoint_id:
        for c in await stack_containers(endpoint_id, stack.get("Name") or ""):
            name = (c.get("Names") or ["/"])[0]
            guard.block(guard.container_protection(name, c.get("Labels") or {}, c.get("Id") or ""))


# ---------------------------------------------------------------------------
# Lesende Tools
# ---------------------------------------------------------------------------


@tool()
async def portainer_version() -> Any:
    """Portainer-Version (GET /api/system/version)."""
    return await portainer().version()


@tool()
async def portainer_endpoint_list() -> list[dict[str, Any]]:
    """Portainer-Umgebungen (Endpoints) mit id, Name, Typ und Status."""
    out = []
    for e in await portainer().endpoints():
        out.append(
            {
                "id": e.get("Id"),
                "name": e.get("Name"),
                "type": e.get("Type"),
                "status": {1: "up", 2: "down"}.get(e.get("Status"), e.get("Status")),
                "url": e.get("URL"),
            }
        )
    return out


@tool()
async def portainer_container_list(endpoint_id: int, all: bool = True, filter_name: str | None = None) -> list[dict[str, Any]]:
    """Container einer Umgebung auflisten.

    endpoint_id: Portainer-Umgebung (siehe portainer_endpoint_list).
    all: true = auch gestoppte Container.
    filter_name: optional, Teil des Containernamens.
    """
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    filters = {"name": [filter_name]} if filter_name else None
    return [container_summary(c) for c in await portainer().containers(eid, bool(all), filters)]


@tool()
async def portainer_container_inspect(endpoint_id: int, container: str) -> dict[str, Any]:
    """Details eines Containers: Status, Image, Ports, Mounts, RestartPolicy,
    Health, Networks. Env-Werte werden nicht ausgegeben, nur Variablennamen."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    return inspect_summary(await _inspect_checked(eid, container))


@tool()
async def portainer_container_logs(
    endpoint_id: int, container: str, tail: int = 200, since: str | None = None, grep: str | None = None
) -> dict[str, Any]:
    """Container-Logs (stdout+stderr, mit Zeitstempel).

    tail: Anzahl Zeilen vom Ende (1-5000).
    since: optional, z.B. '30m', '2h', '1d', Unix-Zeit oder ISO-Datum.
    grep: optional, Regex (case-insensitive) bzw. Text, nur passende Zeilen.
    Lange Ausgaben werden vorne gekürzt (die neuesten Zeilen bleiben).
    """
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    data = await _inspect_checked(eid, container)
    n = max(1, min(int(tail), LOG_TAIL_MAX))
    text = await fetch_logs(eid, data.get("Id") or container, n, parse_since(since), bool((data.get("Config") or {}).get("Tty")))
    lines = filter_lines(text, grep)
    truncated = False
    out = "\n".join(lines)
    if len(out) > LOG_OUTPUT_MAX_CHARS:
        out = out[-LOG_OUTPUT_MAX_CHARS:]
        out = out.split("\n", 1)[1] if "\n" in out else out
        truncated = True
    return {
        "container": (data.get("Name") or "").lstrip("/"),
        "lines": len(lines),
        "truncated": truncated,
        "logs": out,
    }


@tool()
async def portainer_container_stats(endpoint_id: int, container: str) -> dict[str, Any]:
    """Aktuelle Ressourcen: CPU-%, RAM genutzt/Limit, Netzwerk rx/tx."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    data = await _inspect_checked(eid, container)
    if (data.get("State") or {}).get("Status") != "running":
        return {"container": (data.get("Name") or "").lstrip("/"), "status": (data.get("State") or {}).get("Status"), "stats": None}
    raw = await portainer().container_stats(eid, data.get("Id") or container)
    return {"container": (data.get("Name") or "").lstrip("/"), "status": "running", "stats": summarize_stats(raw or {})}


@tool()
async def portainer_stack_list() -> list[dict[str, Any]]:
    """Alle Stacks mit id, Name, Typ (compose/git), Status und Umgebung. Env nur Namen."""
    return [stack_summary(s) for s in await portainer().stacks()]


@tool()
async def portainer_stack_file(stack_id: int) -> dict[str, Any]:
    """Compose-Datei eines Stacks. Werte mit PASSWORD, TOKEN, KEY, SECRET im Namen sind geschwärzt."""
    stack = await _stack_checked(stack_id)
    content = await portainer().stack_file(stack["Id"])
    return {"stack": stack_summary(stack), "compose": guard.redact_compose(content)}


@tool()
async def portainer_image_list(endpoint_id: int) -> list[dict[str, Any]]:
    """Images einer Umgebung (Tags, Grösse, Erstellt)."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    return [
        {
            "id": (i.get("Id") or "").replace("sha256:", "")[:12],
            "tags": i.get("RepoTags") or [],
            "size_mb": round((i.get("Size") or 0) / 1048576, 1),
            "created": _ts(i.get("Created")),
            "containers": i.get("Containers"),
        }
        for i in await portainer().images(eid)
    ]


@tool()
async def portainer_volume_list(endpoint_id: int) -> list[dict[str, Any]]:
    """Volumes einer Umgebung."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    data = await portainer().volumes(eid)
    return [
        {
            "name": v.get("Name"),
            "driver": v.get("Driver"),
            "stack": (v.get("Labels") or {}).get("com.docker.compose.project"),
            "created": v.get("CreatedAt"),
        }
        for v in (data.get("Volumes") or [])
    ]


@tool()
async def portainer_network_list(endpoint_id: int) -> list[dict[str, Any]]:
    """Docker-Netzwerke einer Umgebung."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    return [
        {
            "id": (n.get("Id") or "")[:12],
            "name": n.get("Name"),
            "driver": n.get("Driver"),
            "scope": n.get("Scope"),
            "internal": n.get("Internal"),
            "stack": (n.get("Labels") or {}).get("com.docker.compose.project"),
        }
        for n in await portainer().networks(eid)
    ]


# ---------------------------------------------------------------------------
# Schreibende Tools
# ---------------------------------------------------------------------------


@tool()
async def portainer_container_action(endpoint_id: int, container: str, action: str, confirm: bool = False) -> dict[str, Any]:
    """Container starten, stoppen oder neu starten (action: start|stop|restart).
    Ohne confirm=true nur Vorschau. Geschützte Container werden blockiert."""
    eid = guard.validate_positive_id(endpoint_id, "endpoint_id")
    if action not in ("start", "stop", "restart"):
        raise GuardError("action muss start, stop oder restart sein.")
    data = await _inspect_checked(eid, container)
    name = data.get("Name") or container
    labels = (data.get("Config") or {}).get("Labels") or {}
    guard.block(guard.container_protection(name, labels, data.get("Id") or ""))
    target = {
        "container": name.lstrip("/"),
        "id": (data.get("Id") or "")[:12],
        "image": (data.get("Config") or {}).get("Image"),
        "current_status": (data.get("State") or {}).get("Status"),
        "stack": labels.get("com.docker.compose.project"),
    }
    if not guard.is_confirmed(confirm):
        return guard.preview(f"container_{action}", target=target)
    result = await portainer().container_action(eid, data["Id"], action)
    after = await portainer().container_inspect(eid, data["Id"])
    return {
        "executed": True,
        "action": f"container_{action}",
        "target": target,
        "note": "Container war bereits im Zielzustand." if isinstance(result, dict) and result.get("not_modified") else None,
        "status_after": (after.get("State") or {}).get("Status"),
    }


async def wait_for_stack_deploy(stack_id: int, timeout: float = DEPLOY_TIMEOUT) -> dict[str, Any]:
    """Portainer (ab 2.4x) rollt Compose- und Git-Stacks nach PUT asynchron aus: der Request kehrt
    sofort zurück, der Stack steht auf Status 3 (deploying) und wechselt danach auf 1 (active)
    oder 4 (error, Meldung in DeploymentStatus). Hier wird auf das Ende gewartet."""
    deadline = time.monotonic() + timeout
    while True:
        stack = await portainer().stack(stack_id)
        status = stack.get("Status")
        if status != STACK_STATUS_DEPLOYING:
            break
        if time.monotonic() >= deadline:
            raise UnclearStateError(
                f"Stack {stack_id} steht nach {int(timeout)} s noch auf 'deploying'. Zustand unklar - bitte "
                "zuerst den Ist-Zustand prüfen (portainer_stack_list, portainer_container_list)."
            )
        await asyncio.sleep(STACK_DEPLOY_POLL_SECONDS)
    if status == STACK_STATUS_ERROR:
        history = stack.get("DeploymentStatus") or []
        message = next((h.get("Message") for h in reversed(history) if h.get("Message")), "") or "keine Meldung"
        raise PortainerError(f"Portainer: Deploy von Stack {stack_id} fehlgeschlagen: {guard.redact_text(message)[:500]}")
    return {"status": STACK_STATUS.get(status, status)}


async def redeploy_stack(stack: dict[str, Any], pull_image: bool) -> dict[str, Any]:
    """Compose-Stack: PUT /stacks/{id} mit bestehendem StackFileContent und Env.
    Git-Stack: PUT /stacks/{id}/git/redeploy. Immer prune=false."""
    sid, eid = stack["Id"], stack.get("EndpointId")
    pull = bool(pull_image)
    if stack.get("GitConfig"):
        payload = {
            "Prune": False,
            "PullImage": pull,
            "RepullImageAndRedeploy": pull,
        }
        await portainer().stack_git_redeploy(sid, eid, payload)
        done = await wait_for_stack_deploy(sid)
        return {"method": "git_redeploy", "pull_image": pull, "prune": False, "stack_status": done["status"]}
    content = await portainer().stack_file(sid)
    if not content:
        raise PortainerError(f"Stack {sid}: Compose-Datei konnte nicht gelesen werden, Redeploy abgebrochen.")
    payload = {
        "StackFileContent": content,
        "Env": stack.get("Env") or [],
        "Prune": False,
        "PullImage": pull,
        # ab Portainer 2.36 heisst das Feld RepullImageAndRedeploy; PullImage gilt weiter als Alias
        "RepullImageAndRedeploy": pull,
    }
    await portainer().stack_update_compose(sid, eid, payload)
    done = await wait_for_stack_deploy(sid)
    return {"method": "compose_update", "pull_image": pull, "prune": False, "stack_status": done["status"]}


def _require_compose_type(stack: dict[str, Any]) -> None:
    if stack.get("Type") != 2:
        raise GuardError(
            f"Stack '{stack.get('Name')}' ist vom Typ {STACK_TYPES.get(stack.get('Type'), stack.get('Type'))}; "
            "unterstützt werden nur Docker-Compose-Stacks."
        )


@tool()
async def portainer_stack_redeploy(stack_id: int, pull_image: bool = True, confirm: bool = False) -> dict[str, Any]:
    """Stack neu ausrollen (Compose: bestehende Datei und Env, Git: git/redeploy),
    pull_image=true zieht die Images neu, prune ist immer aus. Ohne confirm=true nur Vorschau."""
    stack = await _stack_checked(stack_id)
    _require_compose_type(stack)
    await _block_protected_stack(stack)
    summary = stack_summary(stack)
    if not guard.is_confirmed(confirm):
        return guard.preview(
            "stack_redeploy",
            stack=summary,
            method="git_redeploy" if stack.get("GitConfig") else "compose_update",
            pull_image=bool(pull_image),
            prune=False,
        )
    info = await redeploy_stack(stack, pull_image)
    return {"executed": True, "action": "stack_redeploy", "stack": summary, **info}


async def _stack_start_stop(stack_id: int, action: str, confirm: bool) -> dict[str, Any]:
    stack = await _stack_checked(stack_id)
    _require_compose_type(stack)
    await _block_protected_stack(stack)
    summary = stack_summary(stack)
    if not guard.is_confirmed(confirm):
        return guard.preview(f"stack_{action}", stack=summary)
    if action == "start":
        await portainer().stack_start(stack["Id"], stack["EndpointId"])
    else:
        await portainer().stack_stop(stack["Id"], stack["EndpointId"])
    return {"executed": True, "action": f"stack_{action}", "stack": summary}


@tool()
async def portainer_stack_start(stack_id: int, confirm: bool = False) -> dict[str, Any]:
    """Gestoppten Stack starten. Ohne confirm=true nur Vorschau."""
    return await _stack_start_stop(stack_id, "start", confirm)


@tool()
async def portainer_stack_stop(stack_id: int, confirm: bool = False) -> dict[str, Any]:
    """Stack stoppen (Container bleiben erhalten, nichts wird gelöscht). Ohne confirm=true nur Vorschau."""
    return await _stack_start_stop(stack_id, "stop", confirm)


def env_pairs(env: dict[str, Any] | None) -> list[dict[str, str]]:
    if not env:
        return []
    if not isinstance(env, dict):
        raise GuardError("env muss ein Objekt {NAME: wert} sein.")
    out = []
    for k, v in env.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(k)):
            raise GuardError(f"Ungültiger Env-Name: {k!r}")
        out.append({"name": str(k), "value": "" if v is None else str(v)})
    return out


async def precheck_stack_create(name: str, endpoint_id: int, compose_content: str, allow_docker_socket: bool) -> dict[str, Any]:
    n = guard.validate_stack_name(name)
    guard.block(guard.stack_protection(n))
    guard.validate_positive_id(endpoint_id, "endpoint_id")
    doc = guard.validate_compose(compose_content, allow_docker_socket)
    if await find_stack_by_name(n):
        raise GuardError(f"Stack-Name '{n}' ist bereits vergeben.")
    return doc


@tool()
async def portainer_stack_create(
    name: str,
    endpoint_id: int,
    compose_content: str,
    env: dict[str, str] | None = None,
    allow_docker_socket: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Neuen Compose-Stack anlegen. Die Compose-Datei wird vorher geprüft
    (YAML gültig, keine privileged-Container, kein Docker-Socket-Mount ohne
    allow_docker_socket=true). env: {NAME: wert}. Ohne confirm=true nur Vorschau."""
    doc = await precheck_stack_create(name, endpoint_id, compose_content, allow_docker_socket)
    pairs = env_pairs(env)
    details = {
        "name": name,
        "endpoint_id": int(endpoint_id),
        "services": list(doc["services"].keys()),
        "env_names": [p["name"] for p in pairs],
        "compose": guard.redact_compose(compose_content),
    }
    if not guard.is_confirmed(confirm):
        return guard.preview("stack_create", **details)
    created = await portainer().stack_create_compose(int(endpoint_id), name, compose_content, pairs)
    details.pop("compose")
    return {"executed": True, "action": "stack_create", "stack_id": (created or {}).get("Id"), **details}

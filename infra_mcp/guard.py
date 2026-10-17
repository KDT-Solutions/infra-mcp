"""Schutzregeln, confirm-Logik und Schwärzung.

- Schutzlisten: geschützte Container, Stacks und Domains werden nie gestoppt,
  neu gestartet, redeployt, geändert oder deaktiviert.
- confirm: Jedes schreibende Tool führt nur mit confirm=true aus, sonst liefert
  es eine Vorschau (Payload bzw. Diff, betroffene Objekte).
- Schwärzung: Env-Werte, Secrets in Compose-Dateien, advanced_config und
  bekannte Secret-Werte aus der Konfiguration erscheinen nie im Klartext.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Iterable

import yaml

from .config import settings
from .errors import GuardError

MASK = "***"

SECRET_NAME_RE = re.compile(r"(PASSWORD|PASSWD|PASS|TOKEN|KEY|SECRET|CREDENTIAL|AUTH)", re.IGNORECASE)

# Docker-Container-/Stack-Namen, Hostnamen
_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_STACK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9_.-]{0,252}[A-Za-z0-9])?$")


# ---------------------------------------------------------------------------
# Eingabeprüfung
# ---------------------------------------------------------------------------


def validate_container_ref(container: str) -> str:
    c = (container or "").strip().lstrip("/")
    if not _CONTAINER_RE.match(c):
        raise GuardError(f"Ungültiger Container-Name/-ID: {container!r}")
    return c


def validate_stack_name(name: str) -> str:
    n = (name or "").strip()
    if not _STACK_NAME_RE.match(n):
        raise GuardError(
            f"Ungültiger Stack-Name {name!r}: erlaubt sind Kleinbuchstaben, Ziffern, '-' und '_' "
            "(Beginn mit Buchstabe oder Ziffer, max. 63 Zeichen)."
        )
    return n


def validate_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        raise GuardError(f"Ungültiger Domainname: {domain!r}")
    return d


def validate_domains(domains: Iterable[str] | str) -> list[str]:
    if isinstance(domains, str):
        domains = [p for p in re.split(r"[\s,]+", domains) if p]
    out: list[str] = []
    for d in domains:
        v = validate_domain(d)
        if v not in out:
            out.append(v)
    if not out:
        raise GuardError("Mindestens ein Domainname ist nötig.")
    return out


def validate_forward(scheme: str, host: str, port: int) -> tuple[str, str, int]:
    s = (scheme or "").strip().lower()
    if s not in ("http", "https"):
        raise GuardError("forward_scheme muss 'http' oder 'https' sein.")
    h = (host or "").strip()
    if not _HOST_RE.match(h):
        raise GuardError(f"Ungültiger forward_host: {host!r}")
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise GuardError("forward_port muss eine Zahl sein.") from None
    if not 1 <= p <= 65535:
        raise GuardError("forward_port muss zwischen 1 und 65535 liegen.")
    return s, h, p


def validate_positive_id(value: Any, label: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise GuardError(f"{label} muss eine positive Ganzzahl sein.") from None
    if v < 1:
        raise GuardError(f"{label} muss eine positive Ganzzahl sein.")
    return v


# ---------------------------------------------------------------------------
# Schutzlisten
# ---------------------------------------------------------------------------


def _matches(name: str, patterns: Iterable[str]) -> str | None:
    n = (name or "").strip().lstrip("/").lower()
    for p in patterns:
        if fnmatch.fnmatchcase(n, p):
            return p
    return None


def container_protection(name: str, labels: dict[str, str] | None = None, container_id: str = "") -> str | None:
    """Grund, warum der Container geschützt ist, sonst None."""
    cfg = settings()
    hit = _matches(name, cfg.protected_containers)
    if hit:
        return f"Container '{name.lstrip('/')}' ist geschützt (Muster '{hit}' in PROTECTED_CONTAINERS)."
    project = (labels or {}).get("com.docker.compose.project", "")
    if project:
        hit = _matches(project, cfg.protected_stacks)
        if hit:
            return f"Container '{name.lstrip('/')}' gehört zum geschützten Stack '{project}' (Muster '{hit}')."
    own = own_container_id()
    if own and container_id and container_id.startswith(own):
        return "Das ist der Container von infra-mcp selbst."
    return None


def stack_protection(stack_name: str) -> str | None:
    hit = _matches(stack_name, settings().protected_stacks)
    if hit:
        return f"Stack '{stack_name}' ist geschützt (Muster '{hit}' in PROTECTED_STACKS)."
    return None


def domain_protection(domains: Iterable[str]) -> str | None:
    for d in domains:
        hit = _matches(d, settings().protected_domains)
        if hit:
            return f"Domain '{d}' ist geschützt (Muster '{hit}' in PROTECTED_DOMAINS)."
    return None


def require_protected_domains_configured() -> None:
    """Fail-safe: Ohne PROTECTED_DOMAINS keine schreibenden NPM-Aktionen."""
    if not settings().protected_domains:
        raise GuardError(
            "PROTECTED_DOMAINS ist nicht gesetzt. Schreibende NPM-Aktionen sind gesperrt, bis mindestens "
            "die Domains von Portainer, NPM und infra-mcp eingetragen sind."
        )


def block(reason: str | None) -> None:
    if reason:
        raise GuardError(f"Blockiert: {reason}")


def own_container_id() -> str:
    """Docker setzt den Hostnamen standardmässig auf die kurze Container-ID."""
    try:
        with open("/etc/hostname", encoding="utf-8") as f:
            host = f.read().strip()
    except OSError:
        return ""
    return host if re.fullmatch(r"[0-9a-f]{12,64}", host) else ""


# ---------------------------------------------------------------------------
# confirm / Vorschau
# ---------------------------------------------------------------------------


def preview(action: str, **details: Any) -> dict[str, Any]:
    """Antwort für schreibende Tools ohne confirm=true: nichts wurde ausgeführt."""
    return {
        "executed": False,
        "preview": True,
        "action": action,
        **details,
        "hint": "Nichts ausgeführt. Zum Ausführen denselben Aufruf mit confirm=true wiederholen.",
    }


def is_confirmed(confirm: Any) -> bool:
    return confirm is True


# ---------------------------------------------------------------------------
# Schwärzung
# ---------------------------------------------------------------------------


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME_RE.search(name or ""))


def redact_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Bekannte Secret-Werte und Bearer-/Basic-Header aus Freitext entfernen."""
    if not text:
        return text
    out = text
    for s in (*settings().secret_values(), *extra_secrets):
        if s and len(s) >= 4:
            out = out.replace(s, MASK)
    out = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 " + MASK, out)
    out = re.sub(r"(?i)(x-api-key|authorization)(\s*[:=]\s*)\S+", r"\1\2" + MASK, out)
    return out


def env_names(env: Any) -> list[str]:
    """Nur Variablennamen ausgeben. Akzeptiert Docker-Format ["K=V"], Portainer
    [{"name","value"}] und dict."""
    if not env:
        return []
    names: list[str] = []
    if isinstance(env, dict):
        names = [str(k) for k in env]
    else:
        for item in env:
            if isinstance(item, dict):
                names.append(str(item.get("name", "")))
            else:
                names.append(str(item).split("=", 1)[0])
    return [n for n in names if n]


_COMPOSE_LINE_RE = re.compile(
    r"""^(?P<prefix>\s*(?:-\s*)?["']?)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>\s*[:=]\s*)(?P<value>.*?)(?P<suffix>["']?\s*)$"""
)
_PLAIN_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def redact_compose(content: str) -> str:
    """Werte von Schlüsseln mit PASSWORD/TOKEN/KEY/SECRET im Namen schwärzen.
    Reine Variablen-Referenzen wie ${DB_PASSWORD} bleiben sichtbar, da sie kein
    Secret enthalten; Default-Werte wie ${X:-wert} werden geschwärzt."""
    lines = []
    for line in (content or "").splitlines():
        m = _COMPOSE_LINE_RE.match(line)
        if m and is_secret_name(m.group("name")):
            value = m.group("value").strip().strip("\"'")
            if value and not _PLAIN_REF_RE.match(value) and value not in ("|", ">", "|-", ">-"):
                prefix = m.group("prefix")
                # "- 'KEY=wert'": die öffnende Anführung steht im Präfix und wird wieder geschlossen
                closing = prefix[-1] if prefix and prefix[-1] in "\"'" else ""
                line = f"{prefix}{m.group('name')}{m.group('sep')}{MASK}{closing}"
        lines.append(line)
    return redact_text("\n".join(lines))


_ADV_SECRET_RE = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie|auth_basic_user_file|x-api-key|bearer|basic)"
)


def redact_advanced_config(text: str | None) -> str:
    """nginx advanced_config: Zeilen mit Secret-Bezug auf die Direktive kürzen."""
    if not text:
        return ""
    out = []
    for line in text.splitlines():
        if _ADV_SECRET_RE.search(line):
            stripped = line.strip()
            directive = stripped.split(None, 1)[0] if stripped else ""
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}{directive} {MASK};" if directive else line)
        else:
            out.append(line)
    return redact_text("\n".join(out))


_PARAM_SUMMARY_KEYS = {"compose_content", "advanced_config"}


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Tool-Parameter für das Audit-Log: keine Secrets, keine grossen Inhalte."""
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in _PARAM_SUMMARY_KEYS:
            out[k] = {"chars": len(v)} if isinstance(v, str) else None
        elif k == "env":
            out[k] = {"names": env_names(v)}
        elif is_secret_name(k):
            out[k] = MASK
        elif isinstance(v, str):
            out[k] = redact_text(v)[:500]
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Compose-Prüfung
# ---------------------------------------------------------------------------


def _volume_sources(service: dict[str, Any]) -> list[str]:
    sources: list[str] = []
    for vol in service.get("volumes") or []:
        if isinstance(vol, str):
            sources.append(vol.split(":", 1)[0])
        elif isinstance(vol, dict):
            src = vol.get("source")
            if isinstance(src, str):
                sources.append(src)
    return sources


def validate_compose(content: str, allow_docker_socket: bool = False) -> dict[str, Any]:
    """Compose-Datei prüfen: YAML parsebar, services vorhanden, keine
    privileged-Container, kein Docker-Socket-Mount ohne allow_docker_socket=true.
    Gibt das geparste Dokument zurück."""
    if not content or not content.strip():
        raise GuardError("compose_content ist leer.")
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (Zeile {mark.line + 1}, Spalte {mark.column + 1})" if mark else ""
        raise GuardError(f"Compose-Datei ist kein gültiges YAML{where}.") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
        raise GuardError("Compose-Datei enthält keinen 'services'-Abschnitt mit mindestens einem Dienst.")
    problems: list[str] = []
    for name, svc in doc["services"].items():
        if not isinstance(svc, dict):
            problems.append(f"Dienst '{name}' ist kein Objekt.")
            continue
        if svc.get("privileged") in (True, "true", "True"):
            problems.append(f"Dienst '{name}': privileged ist nicht erlaubt.")
        if not allow_docker_socket:
            for src in _volume_sources(svc):
                if src.rstrip("/").endswith("docker.sock"):
                    problems.append(
                        f"Dienst '{name}': Docker-Socket-Mount ({src}) nur mit allow_docker_socket=true erlaubt."
                    )
    if problems:
        raise GuardError("Compose-Prüfung fehlgeschlagen: " + " ".join(problems))
    return doc


def compose_service_networks(doc: dict[str, Any], service: str) -> list[str]:
    """Tatsächliche Docker-Netzwerknamen, an denen ein Dienst hängt (external name aufgelöst)."""
    svc = doc["services"][service] or {}
    nets = svc.get("networks") or []
    keys = list(nets.keys()) if isinstance(nets, dict) else [n for n in nets if isinstance(n, str)]
    top = doc.get("networks") or {}
    out = []
    for key in keys:
        definition = top.get(key) or {}
        real = definition.get("name") if isinstance(definition, dict) and definition.get("name") else key
        out.append(str(real))
    return out

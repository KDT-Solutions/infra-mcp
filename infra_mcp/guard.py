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
import posixpath
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


# ---------------------------------------------------------------------------
# NPM advanced_config: nginx-Direktiven-Allowlist
# ---------------------------------------------------------------------------

# advanced_config landet 1:1 in der nginx-Konfiguration des NPM-Containers. Ohne Allowlist liessen
# sich damit location-Blöcke, proxy_pass auf interne Dienste (NPM-Admin-API, Portainer, LAN),
# alias/root auf /data oder /etc/letsencrypt, include, Lua-Code usw. einschleusen. Erlaubt sind nur
# einzelne Direktiven der Form "<direktive> <argumente>;" aus dieser Liste - keine Blöcke.
ADVANCED_CONFIG_MAX_CHARS = 4000
ADVANCED_CONFIG_MAX_LINES = 60

_ADV_SIZE = r"\d+[kKmMgG]?"
_ADV_TIME = r"\d+(?:ms|s|m|h|d)?"
_ADV_ONOFF = r"(?:on|off)"
ALLOWED_NGINX_DIRECTIVES: dict[str, str] = {
    # Name: Regex für die Argumente (ganze Zeile ohne Direktive und ohne abschliessendes ';')
    "add_header": r"[A-Za-z0-9_-]+\s+(?:\"[^\"{}]*\"|'[^'{}]*'|[^\s\"'{}]+)(?:\s+always)?",
    "expires": r"(?:modified\s+)?[@+-]?[A-Za-z0-9:]+|max|off|epoch",
    "client_max_body_size": _ADV_SIZE,
    "proxy_read_timeout": _ADV_TIME,
    "proxy_send_timeout": _ADV_TIME,
    "proxy_connect_timeout": _ADV_TIME,
    "proxy_buffering": _ADV_ONOFF,
    "proxy_buffer_size": _ADV_SIZE,
    "proxy_buffers": rf"\d+\s+{_ADV_SIZE}",
    "gzip": _ADV_ONOFF,
    "gzip_types": r"[A-Za-z0-9+./*_-]+(?:\s+[A-Za-z0-9+./*_-]+)*",
    "real_ip_header": r"[A-Za-z0-9_-]+",
    "set_real_ip_from": r"(?:[0-9a-fA-F:.]+(?:/\d{1,3})?|unix:)",
}
_ADV_LINE_RE = re.compile(r"^\s*([a-z_]+)\s+(.*?)\s*;\s*$")


def validate_advanced_config(text: str | None, label: str = "advanced_config") -> str:
    """nginx advanced_config auf die Direktiven-Allowlist prüfen. Gibt den bereinigten Text
    zurück (Zeilenenden normalisiert) oder wirft GuardError mit der ersten abgelehnten Zeile."""
    if text is None:
        return ""
    if not isinstance(text, str):
        raise GuardError(f"{label} muss ein Text sein.")
    if not text.strip():
        return ""
    if len(text) > ADVANCED_CONFIG_MAX_CHARS:
        raise GuardError(f"{label}: maximal {ADVANCED_CONFIG_MAX_CHARS} Zeichen erlaubt.")
    allowed = ", ".join(sorted(ALLOWED_NGINX_DIRECTIVES))
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > ADVANCED_CONFIG_MAX_LINES:
        raise GuardError(f"{label}: maximal {ADVANCED_CONFIG_MAX_LINES} Zeilen erlaubt.")
    out: list[str] = []
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(stripped)
            continue
        if any(ord(ch) < 32 for ch in stripped) or "{" in stripped or "}" in stripped:
            raise GuardError(
                f"{label} Zeile {n}: Blöcke ('{{', '}}') und Steuerzeichen sind nicht erlaubt - nur einzelne Direktiven "
                f"der Form '<direktive> <argumente>;' aus: {allowed}."
            )
        m = _ADV_LINE_RE.match(stripped)
        if not m or ";" in m.group(2):
            raise GuardError(
                f"{label} Zeile {n}: {stripped[:80]!r} ist nicht erlaubt - pro Zeile genau eine Direktive der Form "
                f"'<direktive> <argumente>;' aus: {allowed}."
            )
        directive, args = m.group(1), m.group(2)
        pattern = ALLOWED_NGINX_DIRECTIVES.get(directive)
        if pattern is None:
            raise GuardError(f"{label} Zeile {n}: Direktive '{directive}' ist nicht erlaubt. Erlaubt sind nur: {allowed}.")
        if not re.fullmatch(pattern, args):
            raise GuardError(f"{label} Zeile {n}: Argumente von '{directive}' ({args[:80]!r}) sind nicht erlaubt.")
        out.append(f"{directive} {args};")
    return "\n".join(out).strip()


def validate_locations(locations: Any) -> list[dict[str, Any]]:
    """locations[].advanced_config gleich prüfen wie advanced_config."""
    if not locations:
        return []
    if not isinstance(locations, list):
        raise GuardError("locations muss eine Liste sein.")
    out = []
    for i, loc in enumerate(locations):
        if not isinstance(loc, dict):
            raise GuardError(f"locations[{i}] muss ein Objekt sein.")
        item = dict(loc)
        item["advanced_config"] = validate_advanced_config(loc.get("advanced_config"), f"locations[{i}].advanced_config")
        out.append(item)
    return out


_PARAM_SUMMARY_KEYS = {"compose_content", "advanced_config"}


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Tool-Parameter für das Audit-Log: keine Secrets, keine grossen Inhalte."""
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in _PARAM_SUMMARY_KEYS:
            out[k] = {"chars": len(v)} if isinstance(v, str) else None
        elif k in ("env", "env_set"):
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


# security_opt: nur dieser Eintrag ist erlaubt. Alles andere (seccomp/apparmor
# unconfined, label:disable, ...) würde Schutzmechanismen des Hosts aushebeln.
ALLOWED_SECURITY_OPTS = {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}

# Namespace-Optionen: "host" macht den Container praktisch zum Host, "container:<id>" und
# "service:<name>" hängen ihn in die Namespaces eines fremden Containers (z.B. NPM, Portainer).
_NAMESPACE_KEYS = ("pid", "ipc", "uts", "userns_mode", "network_mode", "cgroup")
_FOREIGN_NAMESPACE_PREFIXES = ("container:", "service:")

# Host-Pfade, die nie eingebunden werden dürfen, auch nicht read-only: "/" (alles) sowie
# /run und /var/run (Unix-Sockets wie docker.sock oder containerd.sock bleiben über einen
# read-only-Mount voll nutzbar - ":ro" verhindert kein connect()).
_FORBIDDEN_HOST_PATHS = ("/", "/run", "/var/run")

# Host-Pfade, die nur read-only eingebunden werden dürfen - unabhängig von der Allowlist
# (Präfix-Vergleich auf normalisierten Pfaden).
_SENSITIVE_HOST_PATHS = (
    "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/var/lib/docker", "/var/lib/containerd", "/var/lib/portainer", "/var/spool/cron", "/etc/cron",
)

# Weit gefasste Host-Pfade (Home-Verzeichnisse inkl. ~/.ssh, /opt, /srv): read-write nur, wenn
# der Betreiber in BIND_MOUNT_ALLOWED_PREFIXES ausdrücklich ein Verzeichnis *unterhalb* freigegeben
# hat (z.B. /srv/stacks). Ein Eintrag "/srv" oder "/home" allein erlaubt darunter nur read-only.
_GUARDED_HOST_PATHS = ("/home", "/opt", "/srv")

# Erlaubte Pfade des Docker-Sockets (nach Normalisierung).
_DOCKER_SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock")

# Service-Felder, in denen Compose-Variablen (${X}) die Prüfung aushebeln könnten: Portainer
# interpoliert sie erst beim Deploy, hier wäre nur der Platzhalter sichtbar.
_NO_VARIABLE_KEYS = (
    "privileged", "cap_add", "devices", "device_cgroup_rules", "security_opt", "volumes", "volumes_from",
    "cgroup_parent", "sysctls", "ulimits", "extends", "env_file", *_NAMESPACE_KEYS,
)

# ulimits: keine unbegrenzten Werte (-1), Obergrenzen gegen Ressourcen-Erschöpfung des Hosts.
_ULIMIT_MAX = {"nofile": 1_048_576, "nproc": 65_536}


def _under(path: str, base: str) -> bool:
    """path liegt auf oder unterhalb von base (beide normalisiert, absolut). "/" trifft nur sich selbst."""
    if base == "/":
        return path == "/"
    return path == base or path.startswith(base + "/")


def _normalize_host_path(src: str) -> tuple[str | None, str | None]:
    """(normalisierter Pfad, Fehler). Absolute Pfade werden mit posixpath.normpath normalisiert;
    '..' wird abgelehnt (würde die Präfix-Prüfung umgehen: /home/../etc)."""
    if ".." in src.replace("\\", "/").split("/"):
        return None, f"Host-Pfad {src} enthält '..' und ist nicht erlaubt."
    norm = posixpath.normpath(src)
    if not norm.startswith("/"):
        return None, f"Host-Pfad {src} ist nicht absolut."
    return "/" + norm.lstrip("/"), None  # normpath lässt "//x" stehen (POSIX), hier egal


def _volume_entries(service: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """(Art, Quelle, read_only) je Volume-Eintrag eines Dienstes.
    Art: 'bind' (absoluter Host-Pfad), 'relative' (./pfad im Projektverzeichnis), 'volume'
    (benanntes Volume), 'other' (tmpfs/npipe/cluster/unbekannt) oder 'invalid'."""
    out: list[tuple[str, str, bool]] = []
    for vol in service.get("volumes") or []:
        if isinstance(vol, str):
            parts = vol.split(":")
            if len(parts) == 1:
                continue  # anonymes Volume (nur Container-Pfad)
            src = parts[0]
            mode = parts[2] if len(parts) >= 3 else ""
            ro = "ro" in mode.split(",")
            if src.startswith("/"):
                kind = "bind"
            elif src.startswith(("./", "../", "~", ".")):
                kind = "relative"
            else:
                kind = "volume"
        elif isinstance(vol, dict):
            vtype = str(vol.get("type") or "volume").strip().lower()
            src = vol.get("source")
            ro = bool(vol.get("read_only"))
            if vtype == "bind":
                src = "" if src is None else str(src)
                kind = "bind" if src.startswith("/") else "relative"
            elif vtype == "volume":
                if src is None:
                    continue  # anonymes Volume
                src = str(src)
                kind = "volume"
            elif vtype == "tmpfs":
                continue
            else:
                src, kind = str(src or vtype), "other"
        else:
            out.append(("invalid", str(vol), False))
            continue
        out.append((kind, src, ro))
    return out


def _contains_variable(value: Any) -> bool:
    try:
        return "$" in yaml.safe_dump(value, default_flow_style=True)
    except yaml.YAMLError:
        return True


def _check_relative_source(name: str, src: str, problems: list[str]) -> None:
    """Relative Bind-Mounts (./config) zeigen in das Projektverzeichnis des Stacks (Compose-Datei
    bzw. Git-Checkout) und sind erlaubt, solange sie es nicht verlassen."""
    if src.startswith("~"):
        problems.append(f"Dienst '{name}': Bind-Mount {src} (Home-Verzeichnis) ist nicht erlaubt.")
        return
    norm = posixpath.normpath(src)
    if norm == ".." or norm.startswith("../") or norm.startswith("/"):
        problems.append(f"Dienst '{name}': Bind-Mount {src} verlässt das Projektverzeichnis des Stacks.")


def _check_bind_source(name: str, src: str, ro: bool, problems: list[str]) -> None:
    cfg = settings()
    norm, err = _normalize_host_path(src)
    if err:
        problems.append(f"Dienst '{name}': {err}")
        return
    if norm in _DOCKER_SOCKET_PATHS:
        if not cfg.allow_docker_socket_stacks:
            problems.append(
                f"Dienst '{name}': Docker-Socket-Mount ({src}) ist gesperrt. Freischalten nur serverseitig "
                "über ALLOW_DOCKER_SOCKET_STACKS=true in der Umgebung von infra-mcp."
            )
        return
    if any(_under(norm, f) for f in _FORBIDDEN_HOST_PATHS):
        problems.append(f"Dienst '{name}': Host-Pfad {src} ist nicht erlaubt, auch nicht read-only.")
        return
    if not ro and any(_under(norm, s) for s in _SENSITIVE_HOST_PATHS):
        problems.append(f"Dienst '{name}': Host-Pfad {src} nur read-only (':ro') erlaubt.")
        return
    allowed = [p for p in cfg.bind_mount_allowed_prefixes if _under(norm, p)]
    if not allowed:
        if cfg.bind_mount_allowed_prefixes:
            problems.append(
                f"Dienst '{name}': Bind-Mount {src} liegt ausserhalb der freigegebenen Verzeichnisse "
                f"({', '.join(cfg.bind_mount_allowed_prefixes)}, BIND_MOUNT_ALLOWED_PREFIXES)."
            )
        else:
            problems.append(
                f"Dienst '{name}': Bind-Mount {src} ist nicht erlaubt - BIND_MOUNT_ALLOWED_PREFIXES ist leer, "
                "also sind keine Host-Pfade freigegeben (benannte Volumes verwenden)."
            )
        return
    if ro:
        return
    for g in _GUARDED_HOST_PATHS:
        if _under(norm, g) and not any(p != g and _under(p, g) for p in allowed):
            problems.append(
                f"Dienst '{name}': Host-Pfad {src} nur read-only (':ro') erlaubt - read-write unter {g} nur, wenn "
                f"BIND_MOUNT_ALLOWED_PREFIXES ein Verzeichnis unterhalb von {g} ausdrücklich freigibt (z.B. {g}/stacks)."
            )
            return


def _check_namespaces(name: str, svc: dict[str, Any], problems: list[str]) -> None:
    for key in _NAMESPACE_KEYS:
        raw = svc.get(key)
        if raw is None:
            continue
        val = str(raw).strip().lower()
        if val == "host" or val.startswith(_FOREIGN_NAMESPACE_PREFIXES):
            problems.append(f"Dienst '{name}': {key}: {raw} ist nicht erlaubt.")
    if svc.get("cgroup_parent"):
        problems.append(f"Dienst '{name}': cgroup_parent ist nicht erlaubt.")


def _check_sysctls(name: str, svc: dict[str, Any], problems: list[str]) -> None:
    """sysctls: nur net.* (wirken im Netz-Namespace des Containers). Alles andere (kernel.*,
    fs.*, vm.*) wird konservativ abgelehnt."""
    raw = svc.get("sysctls")
    if not raw:
        return
    keys = list(raw.keys()) if isinstance(raw, dict) else [str(e).split("=", 1)[0] for e in (raw if isinstance(raw, list) else [raw])]
    for k in keys:
        if not str(k).strip().startswith("net."):
            problems.append(f"Dienst '{name}': sysctl '{k}' ist nicht erlaubt (nur net.*).")


def _check_ulimits(name: str, svc: dict[str, Any], problems: list[str]) -> None:
    """ulimits: nur ganze Zahlen >= 0 (kein -1 = unbegrenzt), nofile und nproc mit Obergrenze."""
    raw = svc.get("ulimits")
    if not raw:
        return
    if not isinstance(raw, dict):
        problems.append(f"Dienst '{name}': ulimits muss ein Objekt sein.")
        return
    for key, val in raw.items():
        values = list(val.values()) if isinstance(val, dict) else [val]
        for v in values:
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                problems.append(f"Dienst '{name}': ulimit '{key}' = {v!r} ist nicht erlaubt (nur ganze Zahlen >= 0).")
                break
            cap = _ULIMIT_MAX.get(str(key))
            if cap is not None and v > cap:
                problems.append(f"Dienst '{name}': ulimit '{key}' = {v} überschreitet das Maximum {cap}.")
                break


def _check_file_refs(name: str, svc: dict[str, Any], problems: list[str]) -> None:
    """extends/env_file dürfen keine Dateien ausserhalb des Projektverzeichnisses lesen."""
    ext = svc.get("extends")
    if isinstance(ext, dict) and ext.get("file"):
        problems.append(f"Dienst '{name}': extends mit 'file' ist nicht erlaubt.")
    env_files = svc.get("env_file")
    if env_files is None:
        return
    entries = env_files if isinstance(env_files, list) else [env_files]
    for e in entries:
        path = e.get("path") if isinstance(e, dict) else e
        p = str(path or "")
        if p.startswith("/") or p.startswith("~") or ".." in p.split("/"):
            problems.append(f"Dienst '{name}': env_file {p} ist nicht erlaubt (nur Dateien im Projektverzeichnis).")


def _defined_volumes(doc: dict[str, Any], problems: list[str]) -> set[str]:
    """Top-level 'volumes': nur einfache, vom Stack selbst angelegte Volumes. Abgelehnt werden
    external (fremde Volumes wie portainer_data), name (gleiche Wirkung: bestehendes Volume wird
    übernommen), driver_opts (type: none, device: /..., o: bind = versteckter Bind-Mount) und
    fremde Treiber."""
    top = doc.get("volumes")
    if top is None:
        return set()
    if not isinstance(top, dict):
        problems.append("Top-level 'volumes' muss ein Objekt sein.")
        return set()
    if _contains_variable(top):
        problems.append("Top-level 'volumes': Variablen (${...}) sind hier nicht erlaubt.")
    defined: set[str] = set()
    for key, definition in top.items():
        k = str(key)
        if definition is None:
            defined.add(k)
            continue
        if not isinstance(definition, dict):
            problems.append(f"Volume '{k}': Definition muss ein Objekt sein.")
            continue
        bad = [f for f in ("external", "name", "driver_opts") if definition.get(f) not in (None, False, "", {})]
        driver = definition.get("driver")
        if driver not in (None, "", "local"):
            bad.append("driver")
        if bad:
            problems.append(f"Volume '{k}': {', '.join(bad)} ist nicht erlaubt (nur einfache, im Stack angelegte Volumes).")
            continue
        defined.add(k)
    return defined


def _check_top_level_files(doc: dict[str, Any], problems: list[str]) -> None:
    """Top-level secrets/configs mit 'file' lesen Dateien aus dem Projektverzeichnis und hängen sie
    in den Container - absolute Pfade oder '..' dürfen das nicht verlassen; external ist Swarm."""
    for section in ("secrets", "configs"):
        top = doc.get(section)
        if not top:
            continue
        if not isinstance(top, dict):
            problems.append(f"Top-level '{section}' muss ein Objekt sein.")
            continue
        for key, definition in top.items():
            if not isinstance(definition, dict):
                continue
            if definition.get("external"):
                problems.append(f"{section} '{key}': external ist nicht erlaubt.")
            f = str(definition.get("file") or "")
            if f and (f.startswith("/") or f.startswith("~") or ".." in f.split("/") or "$" in f):
                problems.append(f"{section} '{key}': file {f} ist nicht erlaubt (nur Dateien im Projektverzeichnis).")


def validate_compose(content: str) -> dict[str, Any]:
    """Compose-Datei prüfen: YAML parsebar, services vorhanden und keine Optionen,
    mit denen ein Container aus seiner Isolation ausbricht:
    - kein privileged, kein cap_add, keine devices, kein cgroup_parent,
    - security_opt nur no-new-privileges,
    - keine Host- oder Fremd-Namespaces (pid/ipc/uts/userns/network/cgroup: host, container:, service:),
    - sysctls nur net.*, ulimits nur begrenzte Werte,
    - Bind-Mounts nur unterhalb BIND_MOUNT_ALLOWED_PREFIXES (leer = keine), nie '/', /run, /var/run,
      sensible Pfade (/etc, /root, /var/lib/docker, ...) nur read-only, keine '..'-Pfade,
    - Docker-Socket nur mit ALLOW_DOCKER_SOCKET_STACKS=true (Server-Einstellung),
    - kein volumes_from, benannte Volumes nur, wenn im Dokument ohne external/name/driver_opts definiert,
    - keine Variablen in sicherheitsrelevanten Feldern (würden erst beim Deploy aufgelöst).
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
    defined_volumes = _defined_volumes(doc, problems)
    _check_top_level_files(doc, problems)
    for name, svc in doc["services"].items():
        if not isinstance(svc, dict):
            problems.append(f"Dienst '{name}' ist kein Objekt.")
            continue
        for key in _NO_VARIABLE_KEYS:
            if key in svc and _contains_variable(svc.get(key)):
                problems.append(f"Dienst '{name}': Variablen (${{...}}) in '{key}' sind nicht erlaubt.")
        if svc.get("privileged") in (True, "true", "True"):
            problems.append(f"Dienst '{name}': privileged ist nicht erlaubt.")
        if svc.get("cap_add"):
            problems.append(f"Dienst '{name}': cap_add ist nicht erlaubt.")
        if svc.get("devices") or svc.get("device_cgroup_rules"):
            problems.append(f"Dienst '{name}': devices ist nicht erlaubt.")
        sec = svc.get("security_opt") or []
        if isinstance(sec, str):
            sec = [sec]
        for opt in sec:
            if str(opt).strip().lower() not in ALLOWED_SECURITY_OPTS:
                problems.append(f"Dienst '{name}': security_opt '{opt}' ist nicht erlaubt (nur no-new-privileges).")
        _check_namespaces(name, svc, problems)
        _check_sysctls(name, svc, problems)
        _check_ulimits(name, svc, problems)
        _check_file_refs(name, svc, problems)
        if svc.get("volumes_from"):
            problems.append(f"Dienst '{name}': volumes_from ist nicht erlaubt (hängt Volumes fremder Container ein).")
        for kind, src, ro in _volume_entries(svc):
            if kind == "bind":
                _check_bind_source(name, src, ro, problems)
            elif kind == "relative":
                _check_relative_source(name, src, problems)
            elif kind == "volume":
                if src not in defined_volumes:
                    problems.append(
                        f"Dienst '{name}': Volume '{src}' ist nicht im Top-level-Abschnitt 'volumes' dieser "
                        "Compose-Datei definiert (externe oder fremde Volumes sind nicht erlaubt)."
                    )
            else:
                problems.append(f"Dienst '{name}': Volume-Eintrag {src!r} ist nicht erlaubt (nur bind, volume, tmpfs).")
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


_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def interpolate(value: str, env: dict[str, str] | None) -> str:
    """Compose-Variablen ${VAR}, ${VAR:-default}, ${VAR-default}, $VAR mit den Stack-Env-Werten auflösen."""
    env = env or {}

    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(4)
        op, default = m.group(2), m.group(3) or ""
        val = env.get(name)
        if op == ":-" and not val:
            return default
        if op == "-" and val is None:
            return default
        return "" if val is None else str(val)

    return _VAR_RE.sub(repl, str(value))


def compose_published_port(
    doc: dict[str, Any], service: str, container_port: int, env: dict[str, str] | None = None
) -> tuple[str, int] | None:
    """(Bind-Adresse, Host-Port), unter dem der Dienst container_port auf dem Host veröffentlicht.
    Bind-Adresse "" = alle Interfaces. None, wenn der Port nicht veröffentlicht wird."""
    svc = doc["services"].get(service) or {}
    for entry in svc.get("ports") or []:
        if isinstance(entry, dict):
            target = interpolate(str(entry.get("target", "")), env)
            published = interpolate(str(entry.get("published", "")), env)
            host_ip = interpolate(str(entry.get("host_ip", "")), env)
        else:
            spec = interpolate(str(entry), env).split("/", 1)[0]
            parts = spec.split(":")
            if len(parts) == 1:
                continue  # nur Container-Port, Docker wählt einen zufälligen Host-Port
            target = parts[-1]
            published = parts[-2]
            host_ip = ":".join(parts[:-2])
        if target.strip().isdigit() and int(target) == int(container_port) and published.strip().isdigit():
            return host_ip.strip().strip("[]"), int(published)
    return None

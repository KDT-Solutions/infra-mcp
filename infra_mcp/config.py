"""Konfiguration ausschliesslich über Umgebungsvariablen (siehe README).

Secrets (PORTAINER_API_KEY, NPM_PASSWORD, MCP_API_KEY) kommen nur aus der
Umgebung bzw. den Portainer-Stack-Variablen und werden nie ins Image gebaut.
"""

from __future__ import annotations

import logging
import os
import posixpath
from dataclasses import dataclass

logger = logging.getLogger("infra_mcp.config")

# Diese Muster gelten immer, zusätzlich zu den Werten aus PROTECTED_CONTAINERS /
# PROTECTED_STACKS. Ein gesetzter Env-Wert kann sie also nicht versehentlich aufheben.
DEFAULT_PROTECTED_CONTAINERS = ("portainer*", "nginx-proxy-manager*", "npm*", "infra-mcp*")
DEFAULT_PROTECTED_STACKS = ("portainer*", "nginx-proxy-manager*", "npm*", "infra-mcp*")


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


def _list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(p.strip().lower() for p in value.split(",") if p.strip())


def _merge(defaults: tuple[str, ...], extra: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for p in (*defaults, *extra):
        if p not in out:
            out.append(p)
    return tuple(out)


def _bind_prefixes(value: str | None) -> tuple[str, ...]:
    """BIND_MOUNT_ALLOWED_PREFIXES: absolute, normalisierte Basisverzeichnisse für Bind-Mounts.
    Fail-safe: ungültige Einträge (relativ, mit '..', oder '/' = alles) werden verworfen und
    geloggt, statt die Prüfung zu weiten."""
    out: list[str] = []
    for raw in (value or "").split(","):
        p = raw.strip()
        if not p:
            continue
        norm = posixpath.normpath(p)
        norm = "/" + norm.lstrip("/") if norm.startswith("/") else norm
        if not norm.startswith("/") or norm == "/" or ".." in norm.split("/"):
            logger.warning("BIND_MOUNT_ALLOWED_PREFIXES: Eintrag %r ignoriert (muss absolut, ohne '..' und nicht '/' sein).", p)
            continue
        if norm not in out:
            out.append(norm)
    return tuple(out)


@dataclass(frozen=True)
class Settings:
    portainer_url: str
    portainer_api_key: str
    portainer_tls_verify: bool
    npm_url: str
    npm_user: str
    npm_password: str
    npm_default_email: str
    npm_docker_network: str
    public_ip: str
    protected_containers: tuple[str, ...]
    protected_stacks: tuple[str, ...]
    protected_domains: tuple[str, ...]
    mcp_api_key: str
    node_exporter_url: str = ""
    metrics_interval: int = 60
    metrics_file: str = ""
    docker_host_ip: str = ""
    git_allowed_repo_prefixes: tuple[str, ...] = ()
    # Docker-Socket-Mounts in Stacks nur, wenn der Betreiber das serverseitig freischaltet.
    # Kein Tool-Parameter: der Client (das Modell) darf sich das nicht selbst erlauben.
    allow_docker_socket_stacks: bool = False
    # Bind-Mounts nur unterhalb dieser Basisverzeichnisse. Leer = keine Bind-Mounts.
    bind_mount_allowed_prefixes: tuple[str, ...] = ()

    def secret_values(self) -> tuple[str, ...]:
        """Werte, die in keiner Ausgabe und keinem Log auftauchen dürfen."""
        return tuple(v for v in (self.portainer_api_key, self.npm_password, self.mcp_api_key) if v and len(v) >= 4)


def load_settings() -> Settings:
    env = os.environ
    return Settings(
        portainer_url=env.get("PORTAINER_URL", "").strip().rstrip("/"),
        portainer_api_key=env.get("PORTAINER_API_KEY", "").strip(),
        portainer_tls_verify=_bool(env.get("PORTAINER_TLS_VERIFY"), True),
        npm_url=env.get("NPM_URL", "").strip().rstrip("/"),
        npm_user=env.get("NPM_USER", "").strip(),
        npm_password=env.get("NPM_PASSWORD", ""),
        npm_default_email=env.get("NPM_DEFAULT_EMAIL", "").strip(),
        npm_docker_network=env.get("NPM_DOCKER_NETWORK", "").strip(),
        public_ip=env.get("PUBLIC_IP", "").strip(),
        protected_containers=_merge(DEFAULT_PROTECTED_CONTAINERS, _list(env.get("PROTECTED_CONTAINERS"))),
        protected_stacks=_merge(DEFAULT_PROTECTED_STACKS, _list(env.get("PROTECTED_STACKS"))),
        protected_domains=_list(env.get("PROTECTED_DOMAINS")),
        mcp_api_key=env.get("MCP_API_KEY", ""),
        node_exporter_url=env.get("NODE_EXPORTER_URL", "").strip(),
        metrics_interval=max(10, _int(env.get("METRICS_INTERVAL"), 60)),
        metrics_file=env.get("METRICS_FILE", "").strip(),
        docker_host_ip=env.get("DOCKER_HOST_IP", "").strip(),
        git_allowed_repo_prefixes=tuple(
            p.strip().rstrip("/").lower() + "/" for p in env.get("GIT_ALLOWED_REPO_PREFIXES", "").split(",") if p.strip()
        ),
        allow_docker_socket_stacks=_bool(env.get("ALLOW_DOCKER_SOCKET_STACKS"), False),
        bind_mount_allowed_prefixes=_bind_prefixes(env.get("BIND_MOUNT_ALLOWED_PREFIXES")),
    )


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset() -> None:
    """Nur für Tests: Konfiguration beim nächsten Zugriff neu aus der Umgebung lesen."""
    global _settings
    _settings = None

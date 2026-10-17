"""Git-Repositories für Git-Stacks: URL-Prüfung und Abruf der Compose-Datei.

Bei einem Git-Stack holt Portainer die Compose-Datei selbst aus dem Repository.
Damit die Compose-Prüfung (guard.validate_compose) nicht umgangen wird, lädt
infra-mcp die Datei vorher selbst und prüft sie. Unterstützt sind öffentliche
GitHub-Repositories (Abruf über raw.githubusercontent.com); andere Hosts oder
private Repositories werden abgelehnt, weil die Datei dann nicht geprüft
werden kann.
"""

from __future__ import annotations

import re

import httpx

from .config import settings
from .errors import GuardError

FETCH_TIMEOUT = 15.0
MAX_COMPOSE_BYTES = 512 * 1024

_GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")
_REF_RE = re.compile(r"^refs/(heads|tags)/[A-Za-z0-9._/-]{1,200}$")
_PATH_RE = re.compile(r"^(?!/)(?!.*\.\.)[A-Za-z0-9._/-]{1,300}$")


def validate_repo(url: str, reference: str, compose_path: str) -> tuple[str, str, str, str, str]:
    """Prüft URL, Referenz und Pfad. Gibt (url, owner, repo, reference, path) zurück."""
    u = (url or "").strip()
    m = _GITHUB_RE.match(u)
    if not m:
        raise GuardError(
            "repository_url muss ein öffentliches GitHub-Repository sein (https://github.com/<owner>/<repo>). "
            "Andere Hosts werden nicht unterstützt, weil die Compose-Datei vorher geprüft werden muss."
        )
    owner, repo = m.group(1), m.group(2)
    canonical = f"https://github.com/{owner}/{repo}"
    allowed = settings().git_allowed_repo_prefixes
    if allowed and not any((canonical.lower() + "/").startswith(p) for p in allowed):
        raise GuardError(f"Repository {canonical} ist nicht in GIT_ALLOWED_REPO_PREFIXES freigegeben.")
    ref = (reference or "").strip()
    if not _REF_RE.match(ref):
        raise GuardError("reference muss die Form refs/heads/<branch> oder refs/tags/<tag> haben.")
    path = (compose_path or "").strip()
    if not _PATH_RE.match(path):
        raise GuardError(f"Ungültiger compose_path: {compose_path!r}")
    return canonical, owner, repo, ref, path


def raw_url(owner: str, repo: str, reference: str, path: str) -> str:
    short = re.sub(r"^refs/(heads|tags)/", "", reference)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{short}/{path}"


async def fetch_compose(owner: str, repo: str, reference: str, path: str) -> str:
    url = raw_url(owner, repo, reference, path)
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=False) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise GuardError(f"Compose-Datei konnte nicht aus GitHub geladen werden ({type(exc).__name__}).") from None
    if resp.status_code == 404:
        raise GuardError(
            f"Compose-Datei {path} auf {reference} nicht gefunden (oder Repository privat). "
            "Private Repositories werden nicht unterstützt."
        )
    if resp.status_code != 200:
        raise GuardError(f"Compose-Datei konnte nicht geladen werden (HTTP {resp.status_code}).")
    if len(resp.content) > MAX_COMPOSE_BYTES:
        raise GuardError("Compose-Datei ist grösser als 512 KB.")
    return resp.text

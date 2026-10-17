"""Version des laufenden Servers.

Die Version kommt ausschliesslich aus Git-Tags: GitHub Actions baut bei Tag
vX.Y.Z das Image und setzt APP_VERSION=X.Y.Z, GIT_SHA und BUILD_TIME als
Build-Args. Ohne Tag (manueller Build, lokaler Checkout) lautet die Version
"dev-<kurzer Commit-Hash>".
"""

from __future__ import annotations

import os
import subprocess

_REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_sha() -> str:
    sha = os.environ.get("GIT_SHA", "").strip()
    if sha and sha != "unbekannt":
        return sha
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=_REPO_DIR, capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()
    except Exception:
        return ""


def version_info() -> dict[str, str]:
    sha = _git_sha()
    version = os.environ.get("APP_VERSION", "").strip()
    if not version:
        version = f"dev-{sha[:7]}" if sha else "dev-unbekannt"
    return {
        "name": "infra-mcp",
        "version": version,
        "commit": sha or "unbekannt",
        "build_time": os.environ.get("BUILD_TIME", "").strip() or "unbekannt",
    }


__version__ = version_info()["version"]

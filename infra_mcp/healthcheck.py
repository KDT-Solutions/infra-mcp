"""Docker-HEALTHCHECK: ruft /healthz mit dem eigenen Bearer-Token ab.
Exit 0 = gesund, 1 = nicht erreichbar oder Fehler."""

import os
import sys
import urllib.request


def main() -> int:
    port = os.environ.get("MCP_PORT", "8000")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/healthz",
        headers={"Authorization": f"Bearer {os.environ.get('MCP_API_KEY', '')}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())

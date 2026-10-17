"""Schutz des MCP-HTTP-Endpunkts (Bearer-Token, fail-safe Start, CORS) und Audit-Log."""

import json

import pytest
from starlette.testclient import TestClient

API_KEY = "test-mcp-api-key"
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def server():
    from infra_mcp import server as srv

    return srv


@pytest.fixture
def http_client(server):
    app = server._build_http_app(API_KEY)
    with TestClient(app, base_url="https://infra-mcp.example.com") as client:
        yield client


def init_request():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
    }


def test_refuses_start_without_api_key(server, monkeypatch):
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server.main()
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server._build_http_app("")


def test_request_without_token_is_401(http_client):
    resp = http_client.post("/mcp", json=init_request(), headers=HEADERS)
    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthorized"}


@pytest.mark.parametrize("auth", ["Bearer wrong", f"bearer {API_KEY}", API_KEY, f"Bearer {API_KEY}x", "Basic abc"])
def test_wrong_token_is_401(http_client, auth):
    resp = http_client.post("/mcp", json=init_request(), headers={**HEADERS, "Authorization": auth})
    assert resp.status_code == 401


def test_healthz_also_needs_token(http_client):
    assert http_client.get("/healthz").status_code == 401
    ok = http_client.get("/healthz", headers={"Authorization": f"Bearer {API_KEY}"})
    assert ok.status_code == 200 and ok.json()["status"] == "ok"


def test_valid_token_passes(http_client):
    resp = http_client.post("/mcp", json=init_request(), headers={**HEADERS, "Authorization": f"Bearer {API_KEY}"})
    assert resp.status_code == 200
    assert resp.json()["result"]["serverInfo"]["name"] == "infra-mcp"


def test_cors_preflight_without_token(http_client):
    resp = http_client.options(
        "/mcp",
        headers={
            "Origin": "https://client.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers


async def test_tool_call_is_audited_without_secrets(server, capsys):
    from mcp.server.mcpserver.exceptions import ToolError

    from infra_mcp.app import mcp

    with pytest.raises(ToolError, match="Stack-Name"):
        await mcp.call_tool(
            "portainer_stack_create",
            {"name": "Bad Name", "endpoint_id": 1, "compose_content": "services: {}", "env": {"DB_PASSWORD": "geheim123"}},
        )
    lines = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.startswith("{")]
    entry = [e for e in lines if e.get("tool") == "portainer_stack_create"][-1]
    assert entry["event"] == "tool_call" and entry["status"] == "error"
    assert entry["params"]["env"] == {"names": ["DB_PASSWORD"]}
    assert entry["params"]["compose_content"] == {"chars": 12}
    assert "geheim123" not in json.dumps(lines)


async def test_tool_list_has_prefixes(server):
    from infra_mcp.app import mcp

    names = [t.name for t in await mcp.list_tools()]
    assert all(n.startswith(("portainer_", "npm_", "infra_")) for n in names)
    assert len(names) == 33

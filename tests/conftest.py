"""Gemeinsame Fixtures. Alle HTTP-Requests laufen gegen respx-Mocks, nie gegen echte APIs."""

import os
import sys

import pytest
import respx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PORTAINER_URL = "https://portainer.example.com"
PORTAINER_API = f"{PORTAINER_URL}/api"
NPM_API = "http://npm.example.com:81/api"
PORTAINER_KEY = "ptr_test-portainer-key-value"
NPM_PASSWORD = "npm-test-password-value"
PUBLIC_IP = "203.0.113.10"
NPM_NETWORK = "npm_proxy"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    values = {
        "PORTAINER_URL": PORTAINER_URL,
        "PORTAINER_API_KEY": PORTAINER_KEY,
        "PORTAINER_TLS_VERIFY": "1",
        "NPM_URL": NPM_API,
        "NPM_USER": "mcp@example.com",
        "NPM_PASSWORD": NPM_PASSWORD,
        "NPM_DEFAULT_EMAIL": "admin@example.com",
        "NPM_DOCKER_NETWORK": NPM_NETWORK,
        "PUBLIC_IP": PUBLIC_IP,
        "PROTECTED_CONTAINERS": "db-main",
        "PROTECTED_STACKS": "core-*",
        "PROTECTED_DOMAINS": "portainer.example.com,npm.example.com,infra-mcp.example.com",
        "MCP_API_KEY": "test-mcp-api-key",
    }
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    for k in ("APP_VERSION", "GIT_SHA", "BUILD_TIME"):
        monkeypatch.delenv(k, raising=False)
    from infra_mcp import app, config

    config.reset()
    app.set_clients(None, None)
    yield values
    config.reset()
    app.set_clients(None, None)


@pytest.fixture(autouse=True)
def fast_polling(monkeypatch):
    from infra_mcp import tools_portainer, tools_workflow

    monkeypatch.setattr(tools_portainer, "WAIT_POLL_SECONDS", 0)
    monkeypatch.setattr(tools_workflow, "CONTAINER_POLL_SECONDS", 0)
    monkeypatch.setattr(tools_workflow, "CONTAINER_APPEAR_SECONDS", 0.5)


@pytest.fixture
def mock():
    """Ein respx-Router für beide APIs. assert_all_mocked: jeder nicht gemockte Request schlägt fehl."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def npm_login(mock):
    """Standard-Login und modernes Schema (ohne letsencrypt_email, wie ab NPM v2.13)."""
    mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "jwt-1", "expires": "2999-01-01T00:00:00.000Z"})
    mock.get(f"{NPM_API}/schema").respond(200, json={"openapi": "3.1.0", "components": {"certificate": {"meta": {"dns_challenge": {}}}}})
    return mock


def written(router):
    """Alle schreibenden Requests (POST/PUT/DELETE) ausser dem NPM-Login."""
    return [
        c.request for c in router.calls
        if c.request.method in ("POST", "PUT", "DELETE", "PATCH") and not str(c.request.url).endswith("/api/tokens")
    ]

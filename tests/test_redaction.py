"""Schwärzung von Env, Compose, advanced_config, Fehlertexten und Audit-Parametern."""

from conftest import NPM_PASSWORD, PORTAINER_API, PORTAINER_KEY

from infra_mcp import guard, tools_portainer

COMPOSE = """services:
  app:
    image: ghcr.io/example/app:latest
    environment:
      - DB_PASSWORD=supersecret1
      - "API_TOKEN=tok-abc-123"
      - LOG_LEVEL=info
      - REF_ONLY_SECRET=${REF_ONLY_SECRET}
    labels:
      MY_SECRET: 'quoted-secret'
      PRIVATE_KEY: plainvalue
      DEFAULT_PASSWORD: ${X:-fallbacksecret}
      NORMAL: visible
"""


def test_compose_redaction():
    out = guard.redact_compose(COMPOSE)
    for secret in ("supersecret1", "tok-abc-123", "quoted-secret", "plainvalue", "fallbacksecret"):
        assert secret not in out
    assert "- DB_PASSWORD=***" in out
    assert '- "API_TOKEN=***"' in out
    assert "LOG_LEVEL=info" in out
    assert "REF_ONLY_SECRET=${REF_ONLY_SECRET}" in out
    assert "NORMAL: visible" in out
    assert "image: ghcr.io/example/app:latest" in out


def test_env_names_only():
    assert guard.env_names(["A=1", "B_PASSWORD=x"]) == ["A", "B_PASSWORD"]
    assert guard.env_names([{"name": "X", "value": "secret"}]) == ["X"]
    assert guard.env_names({"K": "v"}) == ["K"]
    assert guard.env_names(None) == []


def test_advanced_config_redaction():
    cfg = 'location / {\n  proxy_set_header Authorization "Basic dXNlcjpwYXNz";\n  proxy_read_timeout 60;\n}'
    out = guard.redact_advanced_config(cfg)
    assert "dXNlcjpwYXNz" not in out
    assert "proxy_set_header ***;" in out
    assert "proxy_read_timeout 60;" in out


def test_redact_text_removes_configured_secrets_and_headers():
    text = f"failed with key {PORTAINER_KEY} and pw {NPM_PASSWORD}; Authorization: Bearer abcdefghijklmnop"
    out = guard.redact_text(text)
    assert PORTAINER_KEY not in out and NPM_PASSWORD not in out
    assert "abcdefghijklmnop" not in out


def test_redact_params_for_audit():
    p = guard.redact_params(
        {"compose_content": "x" * 40, "env": {"DB_PASSWORD": "geheim"}, "api_token": "abc", "domain": "app.example.com"}
    )
    assert p["compose_content"] == {"chars": 40}
    assert p["env"] == {"names": ["DB_PASSWORD"]}
    assert p["api_token"] == "***"
    assert p["domain"] == "app.example.com"
    assert "geheim" not in str(p)


async def test_inspect_outputs_env_names_only(mock):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app/json").respond(
        200,
        json={
            "Id": "0123456789abcdef",
            "Name": "/app",
            "State": {"Status": "running", "Running": True, "Health": {"Status": "healthy", "Log": []}},
            "Config": {"Image": "ghcr.io/example/app:1.0", "Env": ["DB_PASSWORD=hunter2", "PORT=8080"], "Labels": {}},
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
            "NetworkSettings": {"Networks": {"npm_proxy": {"IPAddress": "172.20.0.5"}}, "Ports": {"8080/tcp": None}},
            "Mounts": [{"Type": "volume", "Name": "data", "Destination": "/data", "RW": True}],
        },
    )
    out = await tools_portainer.portainer_container_inspect(1, "app")
    assert out["env_names"] == ["DB_PASSWORD", "PORT"]
    assert "hunter2" not in str(out)
    assert out["health"]["status"] == "healthy"
    assert out["restart_policy"] == {"Name": "unless-stopped"}
    assert "npm_proxy" in out["networks"]


async def test_stack_file_redacted_and_env_names(mock):
    mock.get(f"{PORTAINER_API}/stacks/5").respond(
        200, json={"Id": 5, "Name": "app", "Type": 2, "Status": 1, "EndpointId": 1, "Env": [{"name": "TOKEN", "value": "t0ps3cret"}]}
    )
    mock.get(f"{PORTAINER_API}/stacks/5/file").respond(200, json={"StackFileContent": COMPOSE})
    out = await tools_portainer.portainer_stack_file(5)
    assert "supersecret1" not in out["compose"]
    assert out["stack"]["env_names"] == ["TOKEN"]
    assert "t0ps3cret" not in str(out)


async def test_portainer_error_does_not_leak_api_key(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(401, json={"message": "Invalid API key", "details": "bad"})
    from infra_mcp.errors import PortainerError

    try:
        await tools_portainer.portainer_stack_list()
    except PortainerError as exc:
        assert "401" in str(exc)
        assert PORTAINER_KEY not in str(exc)
    else:
        raise AssertionError("PortainerError erwartet")

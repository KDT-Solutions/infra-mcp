"""Host-Port-Modus (DOCKER_HOST_IP): Compose-Ports, Port-Prüfung, Zuordnung Proxy-Host <-> Stack."""

import json

import httpx
import pytest
from conftest import NPM_API, PORTAINER_API, PUBLIC_IP, written

from infra_mcp import config, guard, netcheck, tools_workflow
from infra_mcp.errors import GuardError

HOST_IP = "192.0.2.25"
DOMAIN = "app.example.com"
CONTAINER_LIST = f"{PORTAINER_API}/endpoints/1/docker/containers/json"
CONTAINER = f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/json"
COMPOSE = """services:
  web:
    image: ghcr.io/example/app:1.0
    ports:
      - "${BIND:-0.0.0.0}:${HOST_PORT:-8430}:8000"
"""


def container(ports=(8430,), name="app-web-1", project="app"):
    return {
        "Id": "abcabcabcabc0001", "Names": [f"/{name}"], "State": "running", "Image": "img",
        "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": "web"},
        "Ports": [{"IP": "0.0.0.0", "PrivatePort": 8000, "PublicPort": p, "Type": "tcp"} for p in ports],
    }


def host(hid, domain, port, fh=HOST_IP):
    return {
        "id": hid, "domain_names": [domain], "forward_scheme": "http", "forward_host": fh, "forward_port": port,
        "enabled": True, "certificate_id": 60, "ssl_forced": True, "meta": {}, "advanced_config": "", "locations": [],
        "certificate": {"id": 60, "provider": "letsencrypt", "expires_on": "2027-01-01 00:00:00", "domain_names": [domain]},
    }


@pytest.fixture
def host_mode(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST_IP", HOST_IP)
    monkeypatch.delenv("NPM_DOCKER_NETWORK", raising=False)
    config.reset()

    async def resolve(domain):
        return [PUBLIC_IP]

    async def https(domain):
        return {"url": f"https://{domain}/", "ok": True, "status_code": 200, "cert_valid": True}

    monkeypatch.setattr(netcheck, "resolve_ipv4", resolve)
    monkeypatch.setattr(netcheck, "https_check", https)


# ---------------------------------------------------------------------------
# Compose-Ports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ports, env, expected",
    [
        (['"8430:8000"'], None, ("", 8430)),
        (['"127.0.0.1:8430:8000/tcp"'], None, ("127.0.0.1", 8430)),
        (['"${B:-0.0.0.0}:${P:-8430}:8000"'], None, ("0.0.0.0", 8430)),
        (['"${B:-0.0.0.0}:${P:-8430}:8000"'], {"P": "9001"}, ("0.0.0.0", 9001)),
        (["{target: 8000, published: 8431}"], None, ("", 8431)),
        (['"8000"'], None, None),
        (['"8430:9999"'], None, None),
    ],
)
def test_compose_published_port(ports, env, expected):
    doc = guard.validate_compose("services:\n  web:\n    image: x\n    ports:\n" + "".join(f"      - {p}\n" for p in ports))
    assert guard.compose_published_port(doc, "web", 8000, env) == expected


def test_interpolate():
    assert guard.interpolate("${A:-x}-${B-y}-$C", {"B": "", "C": "c"}) == "x--c"


# ---------------------------------------------------------------------------
# infra_publish_service im Host-Port-Modus
# ---------------------------------------------------------------------------


@pytest.fixture
def happy(npm_login, host_mode):
    m = npm_login
    m.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    m.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[host(1, "other.example.com", 8426)])
    m.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    m.get(CONTAINER_LIST).respond(200, json=[container(ports=(8427,), name="infra-mcp", project="infra-mcp")])
    m.post(f"{PORTAINER_API}/stacks/create/standalone/string").respond(200, json={"Id": 80})
    m.get(f"{PORTAINER_API}/stacks/80").respond(200, json={"Id": 80, "Type": 2, "EndpointId": 1, "Status": 1})
    m.get(CONTAINER).respond(200, json={"Id": "abcabcabcabc0001", "Name": "/app-web-1", "State": {"Status": "running"},
                                        "Config": {"Tty": False}, "RestartCount": 0})
    m.post(f"{NPM_API}/nginx/proxy-hosts").respond(201, json={"id": 50})
    m.get(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json=host(50, DOMAIN, 8430))
    m.put(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json={"id": 50, "ssl_forced": True})
    return m


async def publish(**kw):
    args = dict(stack_name="app", endpoint_id=1, compose_content=COMPOSE, domain=DOMAIN, forward_port=8000)
    args.update(kw)
    return await tools_workflow.infra_publish_service(**args)


async def test_preview_shows_host_forward(happy):
    out = await publish()
    assert out["plan"]["forward"] == f"http://{HOST_IP}:8430"
    assert out["plan"]["host_port"]["port"] == 8430
    assert written(happy) == []


async def test_publish_forwards_to_host_ip_and_port(happy):
    # Nach dem Anlegen listet Portainer den neuen Container
    happy.get(CONTAINER_LIST).mock(side_effect=[
        httpx.Response(200, json=[container(ports=(8427,), name="infra-mcp", project="infra-mcp")]),
        httpx.Response(200, json=[container()]),
    ])
    out = await publish(confirm=True)
    assert out["ok"] is True, out
    req = [c.request for c in happy.calls if c.request.method == "POST" and c.request.url.path == "/api/nginx/proxy-hosts"][0]
    body = json.loads(req.read())
    assert body["forward_host"] == HOST_IP and body["forward_port"] == 8430


async def test_port_taken_by_visible_container(happy):
    happy.get(CONTAINER_LIST).respond(200, json=[container(ports=(8430,), name="other", project="other")])
    with pytest.raises(GuardError, match="8430 ist belegt.*Container other.*8431"):
        await publish(confirm=True)
    assert written(happy) == []


async def test_port_taken_by_npm_target_of_invisible_container(happy):
    happy.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[host(1, "mcp.example.com", 8430)])
    with pytest.raises(GuardError, match="NPM-Proxy-Host mcp.example.com"):
        await publish(confirm=True)
    assert written(happy) == []


async def test_port_not_published(happy):
    with pytest.raises(GuardError, match="veröffentlicht Container-Port 8000 nicht"):
        await publish(compose_content="services:\n  web:\n    image: x\n")


async def test_port_bound_to_localhost(happy):
    with pytest.raises(GuardError, match="an 127.0.0.1 gebunden"):
        await publish(env={"BIND": "127.0.0.1"})


async def test_port_check_after_start(happy):
    happy.get(CONTAINER_LIST).mock(side_effect=[
        httpx.Response(200, json=[]),
        httpx.Response(200, json=[container(ports=())]),
        httpx.Response(200, json=[container(ports=())]),
    ])
    out = await publish(confirm=True)
    assert out["failed_step"] == "port_check"
    assert "proxy_host" in out["missing"]


# ---------------------------------------------------------------------------
# Zuordnung Proxy-Host <-> Stack über den Host-Port
# ---------------------------------------------------------------------------


@pytest.fixture
def status_env(npm_login, host_mode):
    m = npm_login
    m.get(f"{PORTAINER_API}/stacks").respond(200, json=[{"Id": 39, "Name": "app", "Type": 2, "Status": 1, "EndpointId": 1}])
    m.get(f"{PORTAINER_API}/endpoints").respond(200, json=[{"Id": 1}])
    m.get(CONTAINER_LIST).respond(200, json=[container()])
    m.get(CONTAINER).respond(200, json={"Id": "abcabcabcabc0001", "Name": "/app-web-1", "Config": {"Tty": True},
                                        "State": {"Status": "running"}, "RestartCount": 0})
    m.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/logs").respond(200, content=b"ok\n")
    m.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[
        host(1, DOMAIN, 8430),
        host(2, "elsewhere.example.com", 8430, fh="192.0.2.99"),  # gleicher Port, anderer Host
    ])
    return m


async def test_status_by_stack_finds_domain_via_port(status_env):
    out = await tools_workflow.infra_service_status("app")
    assert [h["domain_names"] for h in out["proxy_hosts"]] == [[DOMAIN]]


async def test_status_by_domain_finds_stack_via_port(status_env):
    out = await tools_workflow.infra_service_status(DOMAIN)
    assert out["stack"]["name"] == "app"
    assert out["containers"][0]["name"] == "app-web-1"


async def test_update_preview_lists_domain_via_port(status_env):
    out = await tools_workflow.infra_update_service("app")
    assert out["domains"] == [DOMAIN]

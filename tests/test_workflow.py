"""infra_publish_service mit gemockten APIs, inkl. Fehler in jedem Schritt,
sowie infra_update_service und infra_service_status."""

import json

import httpx
import pytest
from conftest import NPM_API, NPM_NETWORK, PORTAINER_API, PUBLIC_IP, written

from infra_mcp import netcheck, tools_workflow
from infra_mcp.errors import GuardError

DOMAIN = "app.example.com"
COMPOSE = f"""services:
  web:
    image: ghcr.io/example/app:1.0
    networks: [proxy]
networks:
  proxy:
    external: true
    name: {NPM_NETWORK}
"""
CONTAINER_LIST = f"{PORTAINER_API}/endpoints/1/docker/containers/json"
CONTAINER = f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/json"


def listed(state="running"):
    return [{
        "Id": "abcabcabcabc0001", "Names": ["/app-web-1"], "State": state, "Image": "ghcr.io/example/app:1.0",
        "Labels": {"com.docker.compose.project": "app", "com.docker.compose.service": "web"},
    }]


def inspected(status="running", health=None, networks=(NPM_NETWORK,)):
    state = {"Status": status}
    if health:
        state["Health"] = {"Status": health, "Log": []}
    return {
        "Id": "abcabcabcabc0001", "Name": "/app-web-1", "State": state, "RestartCount": 0,
        "Config": {"Image": "ghcr.io/example/app:1.0", "Tty": False, "Labels": {}},
        "NetworkSettings": {"Networks": {n: {"IPAddress": "172.20.0.9"} for n in networks}},
    }


def host(hid=50, cert=True):
    return {
        "id": hid, "domain_names": [DOMAIN], "forward_scheme": "http", "forward_host": "app-web-1", "forward_port": 8080,
        "enabled": True, "certificate_id": 60 if cert else 0, "ssl_forced": cert, "meta": {}, "advanced_config": "",
        "certificate": {"id": 60, "provider": "letsencrypt", "expires_on": "2027-01-01 00:00:00", "domain_names": [DOMAIN]} if cert else None,
        "locations": [],
    }


@pytest.fixture
def net(monkeypatch):
    state = {"ips": [PUBLIC_IP], "https": {"ok": True, "status_code": 200, "cert_valid": True}}

    async def resolve(domain):
        return state["ips"]

    async def https(domain):
        return {"url": f"https://{domain}/", **state["https"]}

    monkeypatch.setattr(netcheck, "resolve_ipv4", resolve)
    monkeypatch.setattr(netcheck, "https_check", https)
    return state


@pytest.fixture
def happy(npm_login, net):
    m = npm_login
    m.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    m.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    m.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    m.post(f"{PORTAINER_API}/stacks/create/standalone/string").respond(200, json={"Id": 77})
    m.get(CONTAINER_LIST).respond(200, json=listed())
    m.get(CONTAINER).respond(200, json=inspected(health="healthy"))
    m.post(f"{NPM_API}/nginx/proxy-hosts").respond(201, json={"id": 50})
    m.get(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json=host())
    m.put(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json={"id": 50, "ssl_forced": True})
    m.get(f"{PORTAINER_API}/endpoints/1/docker/containers/abcabcabcabc0001/logs").respond(200, content=b"")
    m.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/logs").respond(
        200, content=bytes([2, 0, 0, 0, 0, 0, 0, 12]) + b"fatal: boom\n"
    )
    return m


async def publish(**kw):
    args = dict(stack_name="app", endpoint_id=1, compose_content=COMPOSE, domain=DOMAIN, forward_port=8080)
    args.update(kw)
    return await tools_workflow.infra_publish_service(**args)


# ---------------------------------------------------------------------------
# Erfolg und Vorschau
# ---------------------------------------------------------------------------


async def test_publish_preview_creates_nothing(happy):
    out = await publish()
    assert out["preview"] is True
    assert out["plan"]["forward"] == "http://app-web-1:8080"
    assert out["plan"]["dns"]["ok"] is True
    assert written(happy) == []


async def test_publish_success(happy):
    out = await publish(confirm=True, env={"DB_PASSWORD": "pw"})
    assert out["ok"] is True, out
    assert out["missing"] == []
    stack_req = [c.request for c in happy.calls if c.request.url.path.endswith("/stacks/create/standalone/string")][0]
    assert json.loads(stack_req.read())["Env"] == [{"name": "DB_PASSWORD", "value": "pw"}]
    ph_req = [c.request for c in happy.calls if c.request.method == "POST" and c.request.url.path == "/api/nginx/proxy-hosts"][0]
    body = json.loads(ph_req.read())
    assert body["forward_host"] == "app-web-1" and body["forward_port"] == 8080 and body["certificate_id"] == "new"
    kinds = [list(x.keys())[0] for x in out["created"]]
    assert kinds == ["stack", "proxy_host", "certificate"]
    assert out["https"]["status_code"] == 200


# ---------------------------------------------------------------------------
# Schritt 1: Prüfungen
# ---------------------------------------------------------------------------


async def test_publish_stack_name_taken(happy):
    happy.get(f"{PORTAINER_API}/stacks").respond(200, json=[{"Id": 1, "Name": "app"}])
    with pytest.raises(GuardError, match="bereits vergeben"):
        await publish(confirm=True)
    assert written(happy) == []


async def test_publish_domain_taken(happy):
    happy.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[host()])
    with pytest.raises(GuardError, match="bereits vergeben"):
        await publish(confirm=True)
    assert written(happy) == []


async def test_publish_dns_not_pointing_to_public_ip(happy, net):
    net["ips"] = ["198.51.100.1"]
    with pytest.raises(GuardError, match="DNS"):
        await publish(confirm=True)
    assert written(happy) == []


async def test_publish_protected_domain(happy):
    with pytest.raises(GuardError, match="geschützt"):
        await publish(domain="npm.example.com", confirm=True)


async def test_publish_service_not_in_npm_network(happy):
    compose = "services:\n  web:\n    image: x\n"
    with pytest.raises(GuardError, match=NPM_NETWORK):
        await publish(compose_content=compose, confirm=True)
    assert written(happy) == []


async def test_publish_multiple_services_needs_service(happy):
    compose = COMPOSE.replace("networks:\n  proxy:", "  db:\n    image: postgres\nnetworks:\n  proxy:")
    with pytest.raises(GuardError, match="service"):
        await publish(compose_content=compose)


async def test_publish_privileged_rejected(happy):
    with pytest.raises(GuardError, match="privileged"):
        await publish(compose_content=COMPOSE.replace("    networks: [proxy]", "    privileged: true\n    networks: [proxy]"))


# ---------------------------------------------------------------------------
# Schritt 2: Stack anlegen / warten
# ---------------------------------------------------------------------------


async def test_publish_stack_create_error(happy):
    happy.post(f"{PORTAINER_API}/stacks/create/standalone/string").respond(500, json={"message": "compose up failed"})
    out = await publish(confirm=True)
    assert out["ok"] is False and out["failed_step"] == "stack_create"
    assert "compose up failed" in out["error"]
    assert out["created"] == []
    assert "stack" in out["missing"] and "proxy_host" in out["missing"]


async def test_publish_stack_create_timeout_unclear(happy):
    happy.post(f"{PORTAINER_API}/stacks/create/standalone/string").mock(side_effect=httpx.ReadTimeout("slow"))
    out = await publish(confirm=True)
    assert out["failed_step"] == "stack_create" and out["state"] == "unklar"
    assert "Ist-Zustand" in out["error"]
    creates = [c for c in happy.calls if c.request.url.path.endswith("/standalone/string")]
    assert len(creates) == 1  # nicht automatisch wiederholt


async def test_publish_container_exits(happy):
    happy.get(CONTAINER).respond(200, json=inspected(status="exited"))
    out = await publish(confirm=True)
    assert out["failed_step"] == "wait_running"
    assert out["created"][0]["stack"]["id"] == 77
    assert "proxy_host" in out["missing"]
    assert any("fatal: boom" in ln for ln in out["logs"])
    assert not [c for c in happy.calls if c.request.method == "POST" and c.request.url.path == "/api/nginx/proxy-hosts"]


async def test_publish_container_unhealthy(happy):
    happy.get(CONTAINER).respond(200, json=inspected(health="unhealthy"))
    out = await publish(confirm=True)
    assert out["failed_step"] == "wait_running"


async def test_publish_container_timeout(happy, monkeypatch):
    from infra_mcp import tools_portainer

    monkeypatch.setattr(tools_portainer, "WAIT_RUNNING_SECONDS", 0.05)
    original = tools_portainer.wait_until_running

    async def short_wait(eid, names, timeout=0.05):
        return await original(eid, names, timeout=0.05)

    monkeypatch.setattr(tools_workflow, "wait_until_running", short_wait)
    happy.get(CONTAINER).respond(200, json=inspected(health="starting"))
    out = await publish(confirm=True)
    assert out["failed_step"] == "wait_running"
    assert "nicht running/healthy" in out["error"]


async def test_publish_container_not_found(happy):
    happy.get(CONTAINER_LIST).respond(200, json=[])
    out = await publish(confirm=True)
    assert out["failed_step"] == "wait_running" and "Kein Container" in out["error"]


# ---------------------------------------------------------------------------
# Schritt 3: Netz
# ---------------------------------------------------------------------------


async def test_publish_container_not_in_npm_network(happy):
    happy.get(CONTAINER).respond(200, json=inspected(networks=("app_default",)))
    out = await publish(confirm=True)
    assert out["failed_step"] == "network_check"
    assert out["container_networks"] == ["app_default"]
    assert NPM_NETWORK in out["error"]
    assert "proxy_host" in out["missing"]


# ---------------------------------------------------------------------------
# Schritt 4: Proxy-Host / Zertifikat
# ---------------------------------------------------------------------------


async def test_publish_proxy_host_error_reports_state(happy):
    happy.post(f"{NPM_API}/nginx/proxy-hosts").respond(500, json={"error": {"message": "Certbot failed"}})
    happy.get(f"{NPM_API}/nginx/certificates").respond(200, json=[])
    out = await publish(confirm=True)
    assert out["failed_step"] == "proxy_host_create"
    assert "Certbot failed" in out["error"]
    assert out["created"][0]["stack"]["id"] == 77
    assert "proxy_host" in out["missing"] and "certificate" in out["missing"]


async def test_publish_proxy_host_created_but_no_certificate(happy):
    happy.get(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json=host(cert=False))
    out = await publish(confirm=True)
    assert out["failed_step"] == "certificate"
    assert "proxy_host" not in out["missing"]
    assert "certificate" in out["missing"]


async def test_publish_proxy_host_timeout_unclear(happy):
    happy.post(f"{NPM_API}/nginx/proxy-hosts").mock(side_effect=httpx.ReadTimeout("slow"))
    out = await publish(confirm=True)
    assert out["failed_step"] == "proxy_host_create"
    assert "unklar" in out["error"]


# ---------------------------------------------------------------------------
# Schritt 5: HTTPS
# ---------------------------------------------------------------------------


async def test_publish_https_fails(happy, net):
    net["https"] = {"ok": False, "status_code": None, "cert_valid": False, "cert_error": "self signed"}
    out = await publish(confirm=True)
    assert out["failed_step"] == "https_check"
    assert out["missing"] == ["https_ok"]
    assert out["https"]["cert_valid"] is False


# ---------------------------------------------------------------------------
# infra_update_service / infra_service_status
# ---------------------------------------------------------------------------


@pytest.fixture
def update_env(npm_login, net):
    m = npm_login
    m.get(f"{PORTAINER_API}/stacks").respond(200, json=[{"Id": 77, "Name": "app", "Type": 2, "Status": 1, "EndpointId": 1, "Env": []}])
    m.get(CONTAINER_LIST).respond(200, json=listed())
    m.get(CONTAINER).respond(200, json=inspected(health="healthy"))
    m.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[host()])
    m.get(f"{PORTAINER_API}/stacks/77/file").respond(200, json={"StackFileContent": COMPOSE})
    m.put(f"{PORTAINER_API}/stacks/77").respond(200, json={"Id": 77})
    m.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/logs").respond(200, content=b"started\n")
    m.get(f"{PORTAINER_API}/endpoints/1/docker/containers/abcabcabcabc0001/json").respond(200, json=inspected(health="healthy"))
    return m


async def test_update_preview_and_run(update_env):
    prev = await tools_workflow.infra_update_service("app")
    assert prev["preview"] is True and prev["domains"] == [DOMAIN]
    assert written(update_env) == []
    out = await tools_workflow.infra_update_service("app", confirm=True)
    assert out["ok"] is True
    assert out["redeploy"]["method"] == "compose_update"
    assert out["logs"]["app-web-1"] == ["started"]
    assert out["https"][DOMAIN]["status_code"] == 200


async def test_update_blocked_for_protected_stack(update_env):
    update_env.get(f"{PORTAINER_API}/stacks").respond(200, json=[{"Id": 1, "Name": "portainer", "Type": 2, "EndpointId": 1}])
    with pytest.raises(GuardError, match="geschützt"):
        await tools_workflow.infra_update_service("portainer", confirm=True)


async def test_status_by_stack_and_domain(update_env):
    update_env.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/logs").respond(
        200, content=b"ok\nERROR db connection refused\n"
    )
    update_env.get(f"{PORTAINER_API}/endpoints").respond(200, json=[{"Id": 1, "Name": "local"}])
    by_stack = await tools_workflow.infra_service_status("app")
    assert by_stack["containers"][0]["health"] == "healthy"
    assert by_stack["containers"][0]["recent_errors"] == ["ERROR db connection refused"]
    assert by_stack["proxy_hosts"][0]["certificate"]["id"] == 60
    by_domain = await tools_workflow.infra_service_status(DOMAIN)
    assert by_domain["stack"]["name"] == "app"
    assert by_domain["dns"]["ok"] is True


def test_infra_version(monkeypatch):
    monkeypatch.setenv("APP_VERSION", "0.1.0")
    monkeypatch.setenv("GIT_SHA", "0123456789abcdef")
    monkeypatch.setenv("BUILD_TIME", "2026-10-17T12:00:00Z")
    assert tools_workflow.infra_version() == {
        "name": "infra-mcp", "version": "0.1.0", "commit": "0123456789abcdef", "build_time": "2026-10-17T12:00:00Z",
    }


def test_version_without_tag_is_dev_hash(monkeypatch):
    monkeypatch.delenv("APP_VERSION", raising=False)
    monkeypatch.setenv("GIT_SHA", "fedcba9876543210")
    assert tools_workflow.infra_version()["version"] == "dev-fedcba9"

"""Schutzlisten, confirm-Logik, Duplikat-Prüfung, DNS-Vorabprüfung, Compose-Prüfung."""

import json

import httpx

import pytest
from conftest import NPM_API, PORTAINER_API, PUBLIC_IP, written

from infra_mcp import config, guard, netcheck, tools_npm, tools_portainer
from infra_mcp.errors import GuardError


def container_json(name, labels=None, cid="c0ffee0000000001", status="running"):
    return {
        "Id": cid,
        "Name": f"/{name}",
        "State": {"Status": status},
        "Config": {"Image": "img:1", "Labels": labels or {}, "Env": []},
    }


def proxy_host(hid, domains, enabled=True, cert_id=0, **extra):
    h = {
        "id": hid, "domain_names": domains, "forward_scheme": "http", "forward_host": "app", "forward_port": 8080,
        "enabled": enabled, "certificate_id": cert_id, "ssl_forced": False, "advanced_config": "", "meta": {},
        "allow_websocket_upgrade": False, "block_exploits": True, "http2_support": False, "hsts_enabled": False,
        "access_list_id": 0, "certificate": None, "locations": [],
    }
    h.update(extra)
    return h


@pytest.fixture
def dns_ok(monkeypatch):
    async def resolve(domain):
        return [PUBLIC_IP]

    monkeypatch.setattr(netcheck, "resolve_ipv4", resolve)


@pytest.fixture
def dns_wrong(monkeypatch):
    async def resolve(domain):
        return ["198.51.100.7"]

    monkeypatch.setattr(netcheck, "resolve_ipv4", resolve)


@pytest.fixture
def dns_missing(monkeypatch):
    async def resolve(domain):
        return []

    monkeypatch.setattr(netcheck, "resolve_ipv4", resolve)


# ---------------------------------------------------------------------------
# Schutzlisten
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["portainer", "portainer_agent", "nginx-proxy-manager-app-1", "npm", "infra-mcp", "db-main"])
def test_protected_container_names(name):
    assert guard.container_protection(f"/{name}") is not None


def test_unprotected_container():
    assert guard.container_protection("/whoami") is None


def test_container_protected_via_stack_label():
    reason = guard.container_protection("/core-db-1", {"com.docker.compose.project": "core-db"})
    assert "core-db" in reason


def test_defaults_stay_when_env_set(monkeypatch):
    monkeypatch.setenv("PROTECTED_CONTAINERS", "something-else")
    config.reset()
    assert guard.container_protection("/portainer") is not None
    assert guard.container_protection("/something-else") is not None


def test_domain_protection():
    assert guard.domain_protection(["npm.example.com"]) is not None
    assert guard.domain_protection(["app.example.com"]) is None


async def test_container_action_blocked_even_in_preview(mock):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/portainer/json").respond(200, json=container_json("portainer"))
    with pytest.raises(GuardError, match="geschützt"):
        await tools_portainer.portainer_container_action(1, "portainer", "restart")
    with pytest.raises(GuardError, match="geschützt"):
        await tools_portainer.portainer_container_action(1, "portainer", "restart", confirm=True)
    assert written(mock) == []


async def test_stack_redeploy_blocked_by_protected_container_in_stack(mock):
    mock.get(f"{PORTAINER_API}/stacks/3").respond(200, json={"Id": 3, "Name": "tools", "Type": 2, "EndpointId": 1, "Env": []})
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/json").respond(
        200, json=[{"Id": "x1", "Names": ["/db-main"], "Labels": {"com.docker.compose.project": "tools"}}]
    )
    with pytest.raises(GuardError, match="db-main"):
        await tools_portainer.portainer_stack_redeploy(3, confirm=True)
    assert written(mock) == []


async def test_stack_stop_blocked_for_protected_stack_name(mock):
    mock.get(f"{PORTAINER_API}/stacks/4").respond(200, json={"Id": 4, "Name": "infra-mcp", "Type": 2, "EndpointId": 1})
    with pytest.raises(GuardError, match="geschützt"):
        await tools_portainer.portainer_stack_stop(4, confirm=True)
    assert written(mock) == []


async def test_npm_writes_blocked_without_protected_domains(monkeypatch, npm_login):
    monkeypatch.setenv("PROTECTED_DOMAINS", "")
    config.reset()
    with pytest.raises(GuardError, match="PROTECTED_DOMAINS"):
        await tools_npm.npm_proxy_host_disable(1, confirm=True)
    assert written(npm_login) == []


async def test_npm_disable_blocked_for_protected_domain(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/7").respond(200, json=proxy_host(7, ["portainer.example.com"]))
    with pytest.raises(GuardError, match="geschützt"):
        await tools_npm.npm_proxy_host_disable(7, confirm=True)
    assert written(npm_login) == []


async def test_npm_update_blocked_for_protected_domain(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/7").respond(200, json=proxy_host(7, ["npm.example.com"]))
    with pytest.raises(GuardError, match="geschützt"):
        await tools_npm.npm_proxy_host_update(7, forward_port=9000, confirm=True)


async def test_npm_update_cannot_add_protected_domain(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json=proxy_host(8, ["app.example.com"]))
    with pytest.raises(GuardError, match="geschützt"):
        await tools_npm.npm_proxy_host_update(8, domain_names=["app.example.com", "npm.example.com"], confirm=True)


# ---------------------------------------------------------------------------
# confirm-Logik
# ---------------------------------------------------------------------------


async def test_container_action_preview_then_execute(mock):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/web/json").respond(200, json=container_json("web", cid="webid"))
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/webid/json").respond(200, json=container_json("web", cid="webid"))
    action = mock.post(f"{PORTAINER_API}/endpoints/1/docker/containers/webid/restart").respond(204)
    prev = await tools_portainer.portainer_container_action(1, "web", "restart")
    assert prev["executed"] is False and prev["preview"] is True
    assert prev["target"]["container"] == "web"
    assert action.call_count == 0
    done = await tools_portainer.portainer_container_action(1, "web", "restart", confirm=True)
    assert done["executed"] is True and action.call_count == 1


@pytest.mark.parametrize("confirm", [None, "true", 1, False])
async def test_confirm_must_be_literal_true(mock, confirm):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/web/json").respond(200, json=container_json("web"))
    out = await tools_portainer.portainer_container_action(1, "web", "stop", confirm=confirm)
    assert out["executed"] is False
    assert written(mock) == []


async def test_stack_redeploy_compose_payload(mock):
    env = [{"name": "DB_PASSWORD", "value": "geheim"}]
    mock.get(f"{PORTAINER_API}/stacks/9").respond(200, json={"Id": 9, "Name": "app", "Type": 2, "EndpointId": 2, "Env": env})
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    mock.get(f"{PORTAINER_API}/stacks/9/file").respond(200, json={"StackFileContent": "services:\n  app:\n    image: x\n"})
    put = mock.put(f"{PORTAINER_API}/stacks/9").respond(200, json={"Id": 9})
    prev = await tools_portainer.portainer_stack_redeploy(9)
    assert prev["preview"] is True and put.call_count == 0
    assert "geheim" not in json.dumps(prev)
    await tools_portainer.portainer_stack_redeploy(9, confirm=True)
    req = put.calls.last.request
    assert req.url.params["endpointId"] == "2"
    body = json.loads(req.read())
    assert body["StackFileContent"].startswith("services:")
    assert body["Env"] == env
    assert body["Prune"] is False and body["PullImage"] is True and body["RepullImageAndRedeploy"] is True


async def test_stack_redeploy_git(mock):
    mock.get(f"{PORTAINER_API}/stacks/10").respond(
        200, json={"Id": 10, "Name": "gitapp", "Type": 2, "EndpointId": 1, "GitConfig": {"URL": "https://git.example.com/r.git"}}
    )
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/json").respond(200, json=[])
    git = mock.put(f"{PORTAINER_API}/stacks/10/git/redeploy").respond(200, json={})
    out = await tools_portainer.portainer_stack_redeploy(10, confirm=True)
    assert out["method"] == "git_redeploy"
    body = json.loads(git.calls.last.request.read())
    assert body["Prune"] is False and body["PullImage"] is True
    assert "Env" not in body  # gespeicherte Env bleibt unverändert


async def test_stack_create_preview_and_execute(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    create = mock.post(f"{PORTAINER_API}/stacks/create/standalone/string").respond(200, json={"Id": 21})
    mock.get(f"{PORTAINER_API}/stacks/21").respond(200, json={"Id": 21, "Name": "web", "Type": 2, "EndpointId": 1, "Status": 1})
    compose = "services:\n  web:\n    image: nginx\n    environment:\n      - API_KEY=abc12345\n"
    prev = await tools_portainer.portainer_stack_create("web", 1, compose, env={"DB_PASSWORD": "pw-geheim"})
    assert prev["preview"] is True and create.call_count == 0
    assert "abc12345" not in json.dumps(prev) and "pw-geheim" not in json.dumps(prev)
    assert prev["env_names"] == ["DB_PASSWORD"]
    out = await tools_portainer.portainer_stack_create("web", 1, compose, env={"DB_PASSWORD": "pw-geheim"}, confirm=True)
    assert out["stack_id"] == 21 and out["stack_status"] == "active"
    body = json.loads(create.calls.last.request.read())
    assert body == {"Name": "web", "StackFileContent": compose, "Env": [{"name": "DB_PASSWORD", "value": "pw-geheim"}]}
    assert create.calls.last.request.url.params["endpointId"] == "1"


async def test_stack_create_rejects_existing_name(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[{"Id": 1, "Name": "web"}])
    with pytest.raises(GuardError, match="bereits vergeben"):
        await tools_portainer.portainer_stack_create("web", 1, "services:\n  a:\n    image: x\n", confirm=True)


async def test_proxy_host_update_shows_diff(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json=proxy_host(8, ["app.example.com"], forward_port=8080))
    put = npm_login.put(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json={"id": 8})
    prev = await tools_npm.npm_proxy_host_update(8, forward_port=9000, websocket=True, block_exploits=True)
    assert prev["preview"] is True and put.call_count == 0
    assert prev["diff"] == {
        "forward_port": {"before": 8080, "after": 9000},
        "allow_websocket_upgrade": {"before": False, "after": True},
    }
    await tools_npm.npm_proxy_host_update(8, forward_port=9000, websocket=True, confirm=True)
    assert json.loads(put.calls.last.request.read()) == {"forward_port": 9000, "allow_websocket_upgrade": True}


async def test_proxy_host_update_no_change(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json=proxy_host(8, ["app.example.com"]))
    out = await tools_npm.npm_proxy_host_update(8, forward_port=8080, confirm=True)
    assert out["executed"] is False and out["diff"] == {}
    assert written(npm_login) == []


async def test_enable_disable_preview(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json=proxy_host(8, ["app.example.com"], enabled=True))
    dis = npm_login.post(f"{NPM_API}/nginx/proxy-hosts/8/disable").respond(200, json=True)
    prev = await tools_npm.npm_proxy_host_disable(8)
    assert prev["preview"] is True and dis.call_count == 0
    await tools_npm.npm_proxy_host_disable(8, confirm=True)
    assert dis.call_count == 1


async def test_certificate_renew_preview(npm_login):
    npm_login.get(f"{NPM_API}/nginx/certificates").respond(
        200, json=[{"id": 3, "provider": "letsencrypt", "nice_name": "app.example.com", "domain_names": ["app.example.com"],
                    "expires_on": "2026-11-01 00:00:00"}]
    )
    renew = npm_login.post(f"{NPM_API}/nginx/certificates/3/renew").respond(200, json={"id": 3, "expires_on": "2027-01-30 00:00:00"})
    prev = await tools_npm.npm_certificate_renew(3)
    assert prev["preview"] is True and renew.call_count == 0
    out = await tools_npm.npm_certificate_renew(3, confirm=True)
    assert out["executed"] is True and renew.call_count == 1


# ---------------------------------------------------------------------------
# Duplikate und DNS
# ---------------------------------------------------------------------------


async def test_proxy_host_create_duplicate_proxy_host(npm_login, dns_ok):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[proxy_host(1, ["App.example.com"])])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    with pytest.raises(GuardError, match="bereits"):
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, confirm=True)
    assert written(npm_login) == []


async def test_proxy_host_create_duplicate_redirection_host(npm_login, dns_ok):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[{"id": 4, "domain_names": ["app.example.com"]}])
    with pytest.raises(GuardError, match="redirection_hosts"):
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, confirm=True)


async def test_proxy_host_create_dns_wrong_ip(npm_login, dns_wrong):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    with pytest.raises(GuardError, match="DNS") as exc:
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, confirm=True)
    assert "198.51.100.7" in str(exc.value) and PUBLIC_IP in str(exc.value)
    assert written(npm_login) == []


async def test_proxy_host_create_dns_missing_names_record(npm_login, dns_missing):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    with pytest.raises(GuardError) as exc:
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080)
    assert f"app.example.com. IN A {PUBLIC_IP}" in str(exc.value)


async def test_proxy_host_create_without_ssl_skips_dns(npm_login, dns_missing):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    out = await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, ssl=False)
    assert out["preview"] is True
    assert out["payload"]["certificate_id"] == 0 and out["payload"]["ssl_forced"] is False


async def test_proxy_host_create_ssl_payload_and_ssl_forced(npm_login, dns_ok):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    create = npm_login.post(f"{NPM_API}/nginx/proxy-hosts").respond(201, json={"id": 12})
    cert = {"id": 30, "provider": "letsencrypt", "expires_on": "2027-01-01 00:00:00", "domain_names": ["app.example.com"]}
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/12").respond(200, json=proxy_host(12, ["app.example.com"], cert_id=30, ssl_forced=True, certificate=cert))
    put = npm_login.put(f"{NPM_API}/nginx/proxy-hosts/12").respond(200, json={"id": 12, "ssl_forced": True})
    out = await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, websocket=True, confirm=True)
    body = json.loads(create.calls.last.request.read())
    assert body["certificate_id"] == "new"
    assert body["meta"] == {"dns_challenge": False}  # ab NPM 2.13 keine letsencrypt_email im Payload
    assert body["allow_websocket_upgrade"] is True and body["block_exploits"] is True
    assert json.loads(put.calls.last.request.read()) == {"ssl_forced": True, "http2_support": True, "hsts_enabled": False}
    assert out["ssl_forced_set"] is True
    assert out["proxy_host"]["certificate"]["id"] == 30


async def test_proxy_host_create_legacy_npm_sends_email(mock, dns_ok):
    mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"})
    mock.get(f"{NPM_API}/schema").respond(200, json={"meta": {"letsencrypt_email": {}, "letsencrypt_agree": {}}})
    mock.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    mock.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    out = await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080)
    assert out["payload"]["meta"] == {"letsencrypt_email": "admin@example.com", "letsencrypt_agree": True, "dns_challenge": False}


# ---------------------------------------------------------------------------
# Compose-Prüfung
# ---------------------------------------------------------------------------


def test_compose_invalid_yaml():
    with pytest.raises(GuardError, match="YAML"):
        guard.validate_compose("services: [unclosed")


def test_compose_privileged_rejected():
    with pytest.raises(GuardError, match="privileged"):
        guard.validate_compose("services:\n  a:\n    image: x\n    privileged: true\n")


@pytest.mark.parametrize(
    "volumes",
    [
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        "      - type: bind\n        source: /run/docker.sock\n        target: /var/run/docker.sock\n",
    ],
)
def test_compose_docker_socket_needs_flag(volumes):
    compose = "services:\n  a:\n    image: x\n    volumes:\n" + volumes
    with pytest.raises(GuardError, match="allow_docker_socket"):
        guard.validate_compose(compose)
    assert guard.validate_compose(compose, allow_docker_socket=True)["services"]["a"]


def test_compose_without_services():
    with pytest.raises(GuardError, match="services"):
        guard.validate_compose("version: '3'\n")


def test_compose_service_networks_resolves_external_name():
    doc = guard.validate_compose(
        "services:\n  a:\n    image: x\n    networks: [proxy]\nnetworks:\n  proxy:\n    external: true\n    name: npm_proxy\n"
    )
    assert guard.compose_service_networks(doc, "a") == ["npm_proxy"]


@pytest.mark.parametrize("bad", ["Web", "-web", "web app", "a" * 70])
def test_stack_name_validation(bad):
    with pytest.raises(GuardError):
        guard.validate_stack_name(bad)


@pytest.mark.parametrize("bad", ["../etc", "a/b", "", "x?y"])
def test_container_ref_validation(bad):
    with pytest.raises(GuardError):
        guard.validate_container_ref(bad)


# ---------------------------------------------------------------------------
# Strengere Compose-Prüfung
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extra,match", [
    ("    cap_add: [SYS_ADMIN]\n", "cap_add"),
    ("    devices: ['/dev/sda:/dev/sda']\n", "devices"),
    ("    security_opt: ['seccomp:unconfined']\n", "security_opt"),
    ("    security_opt: ['apparmor:unconfined']\n", "security_opt"),
    ("    pid: host\n", "pid"),
    ("    network_mode: host\n", "network_mode"),
    ("    userns_mode: host\n", "userns_mode"),
    ("    volumes:\n      - /:/host\n", "read-only"),
    ("    volumes:\n      - /etc:/hostetc:rw\n", "read-only"),
    ("    volumes:\n      - type: bind\n        source: /var/lib/docker\n        target: /d\n", "read-only"),
])
def test_compose_escape_options_rejected(extra, match):
    with pytest.raises(GuardError, match=match):
        guard.validate_compose("services:\n  a:\n    image: x\n" + extra)


@pytest.mark.parametrize("extra", [
    "    security_opt: ['no-new-privileges:true']\n",
    "    security_opt:\n      - no-new-privileges\n",
    "    volumes:\n      - /:/host:ro,rslave\n",
    "    volumes:\n      - /etc/localtime:/etc/localtime:ro\n",
    "    volumes:\n      - /srv/app/data:/data\n",
    "    volumes:\n      - appdata:/data\n",
    "    network_mode: bridge\n",
    "    cap_drop: [ALL]\n",
])
def test_compose_safe_options_allowed(extra):
    assert guard.validate_compose("services:\n  a:\n    image: x\n" + extra)


# ---------------------------------------------------------------------------
# portainer_stack_update
# ---------------------------------------------------------------------------

OLD_COMPOSE = "services:\n  app:\n    image: x\n    security_opt:\n      - no-new-privileges:true\n"
NEW_COMPOSE = "services:\n  app:\n    image: x\n"


@pytest.fixture
def upd(mock):
    env = [{"name": "API_TOKEN", "value": "token-geheim-123"}, {"name": "MODE", "value": "a"}]
    mock.get(f"{PORTAINER_API}/stacks/9").respond(
        200, json={"Id": 9, "Name": "app", "Type": 2, "EndpointId": 2, "Env": env, "Status": 1}
    )
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    mock.get(f"{PORTAINER_API}/stacks/9/file").respond(200, json={"StackFileContent": OLD_COMPOSE})
    put = mock.put(f"{PORTAINER_API}/stacks/9").respond(200, json={"Id": 9})
    return put


async def test_stack_update_preview_keeps_secrets_out(upd):
    prev = await tools_portainer.portainer_stack_update(9, compose_content=NEW_COMPOSE, env_set={"MODE": "b", "NEW": "1"})
    assert prev["preview"] is True and upd.call_count == 0
    assert "-      - no-new-privileges:true" in prev["compose_diff"]
    assert prev["env_added"] == ["NEW"] and prev["env_changed"] == ["MODE"]
    assert "token-geheim-123" not in json.dumps(prev)


async def test_stack_update_merges_env_and_keeps_existing(upd):
    out = await tools_portainer.portainer_stack_update(
        9, compose_content=NEW_COMPOSE, env_set={"MODE": "b"}, confirm=True
    )
    body = json.loads(upd.calls.last.request.read())
    assert body["StackFileContent"] == NEW_COMPOSE
    assert body["Env"] == [{"name": "API_TOKEN", "value": "token-geheim-123"}, {"name": "MODE", "value": "b"}]
    assert body["Prune"] is False
    assert out["stack_status"] == "active" and "token-geheim-123" not in json.dumps(out)


async def test_stack_update_env_unset_and_unknown(upd):
    with pytest.raises(GuardError, match="nicht im Stack"):
        await tools_portainer.portainer_stack_update(9, env_unset=["GIBTSNICHT"], confirm=True)
    await tools_portainer.portainer_stack_update(9, env_unset=["MODE"], confirm=True)
    body = json.loads(upd.calls.last.request.read())
    assert [e["name"] for e in body["Env"]] == ["API_TOKEN"]


async def test_stack_update_rejects_unsafe_compose(upd):
    with pytest.raises(GuardError, match="privileged"):
        await tools_portainer.portainer_stack_update(9, compose_content=NEW_COMPOSE + "    privileged: true\n", confirm=True)
    assert upd.call_count == 0


async def test_stack_update_nothing_to_do(upd):
    with pytest.raises(GuardError, match="Nichts zu ändern"):
        await tools_portainer.portainer_stack_update(9)
    with pytest.raises(GuardError, match="Keine Änderung"):
        await tools_portainer.portainer_stack_update(9, compose_content=OLD_COMPOSE)


async def test_stack_update_blocked_for_protected_stack(mock):
    mock.get(f"{PORTAINER_API}/stacks/3").respond(200, json={"Id": 3, "Name": "core-db", "Type": 2, "EndpointId": 1})
    with pytest.raises(GuardError):
        await tools_portainer.portainer_stack_update(3, compose_content=NEW_COMPOSE, confirm=True)


async def test_stack_update_git_stack_refused(mock):
    mock.get(f"{PORTAINER_API}/stacks/10").respond(
        200, json={"Id": 10, "Name": "gitapp", "Type": 2, "EndpointId": 1, "GitConfig": {"URL": "https://git.example.com/r.git"}}
    )
    with pytest.raises(GuardError, match="Git"):
        await tools_portainer.portainer_stack_update(10, compose_content=NEW_COMPOSE)


async def test_stack_update_reports_deploy_error(mock):
    mock.get(f"{PORTAINER_API}/stacks/9").mock(side_effect=[
        httpx.Response(200, json={"Id": 9, "Name": "app", "Type": 2, "EndpointId": 2, "Env": []}),
        httpx.Response(200, json={"Id": 9, "Status": 4, "DeploymentStatus": [{"Message": "port is already allocated"}]}),
    ])
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    mock.get(f"{PORTAINER_API}/stacks/9/file").respond(200, json={"StackFileContent": OLD_COMPOSE})
    mock.put(f"{PORTAINER_API}/stacks/9").respond(200, json={"Id": 9})
    from infra_mcp.errors import PortainerError

    with pytest.raises(PortainerError, match="already allocated"):
        await tools_portainer.portainer_stack_update(9, compose_content=NEW_COMPOSE, confirm=True)

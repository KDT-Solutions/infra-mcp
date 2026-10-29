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


# ---------------------------------------------------------------------------
# NPM advanced_config: nginx-Direktiven-Allowlist
# ---------------------------------------------------------------------------

ADV_OK = (
    "# Kommentar\n"
    "add_header X-Frame-Options SAMEORIGIN;\n"
    "add_header X-Robots-Tag \"noindex, nofollow\" always;\n"
    "add_header X-Request-Id $request_id;\n"
    "expires 30d;\n"
    "expires modified +24h;\n"
    "client_max_body_size 100m;\n"
    "proxy_read_timeout 300s;\n"
    "proxy_send_timeout 300;\n"
    "proxy_connect_timeout 10s;\n"
    "proxy_buffering off;\n"
    "proxy_buffer_size 16k;\n"
    "proxy_buffers 8 16k;\n"
    "gzip on;\n"
    "gzip_types text/plain application/json image/svg+xml;\n"
    "real_ip_header X-Forwarded-For;\n"
    "set_real_ip_from 10.0.0.0/8;\n"
    "  set_real_ip_from 2001:db8::/32;  \n"
)


def test_advanced_config_allowed_directives():
    out = guard.validate_advanced_config(ADV_OK)
    assert "proxy_buffers 8 16k;" in out and "set_real_ip_from 2001:db8::/32;" in out
    assert guard.validate_advanced_config(None) == "" and guard.validate_advanced_config("  \n ") == ""
    assert guard.validate_advanced_config("add_header X-A b;\r\nexpires off;") == "add_header X-A b;\nexpires off;"


@pytest.mark.parametrize("cfg,match", [
    ("location /x { proxy_pass http://127.0.0.1:81; }", "Blöcke"),
    ("location /k {\n  alias /data/;\n  autoindex on;\n}", "Blöcke"),
    ("proxy_pass http://portainer:9000;", "proxy_pass"),
    ("alias /etc/letsencrypt/;", "alias"),
    ("root /data;", "root"),
    ("include /etc/nginx/conf.d/*.conf;", "include"),
    ("return 301 https://evil.example;", "return"),
    ("rewrite ^ /x permanent;", "rewrite"),
    ("auth_basic_user_file /data/htpasswd;", "auth_basic_user_file"),
    ("access_by_lua_block { os.execute('id') }", "Blöcke"),
    ("content_by_lua 'ngx.say(1)';", "content_by_lua"),
    ("ssl_certificate /etc/letsencrypt/live/x/fullchain.pem;", "ssl_certificate"),
    ("add_header X-A b; proxy_pass http://x;", "genau eine Direktive"),
    ("add_header X-A \"b; proxy_pass http://x\";", "genau eine Direktive"),
    ("add_header X-A b", "genau eine Direktive"),
    ("add_header X-A b;; gzip on;", "genau eine Direktive"),
    ("add_header 'X A' b;", "Argumente von 'add_header'"),
    ("add_header X-A \"a\nb\";", "genau eine Direktive"),
    ("gzip maybe;", "Argumente von 'gzip'"),
    ("client_max_body_size $x;", "Argumente von 'client_max_body_size'"),
    ("set_real_ip_from evil.example;", "Argumente von 'set_real_ip_from'"),
    ("expires 30d {", "Blöcke"),
    ("add_header X-A b;\x00", "Steuerzeichen"),
    ("add_header X-A " + "b" * 4000 + ";", "Zeichen"),
    ("\n".join(["gzip on;"] * 61), "Zeilen"),
])
def test_advanced_config_rejected(cfg, match):
    with pytest.raises(GuardError, match=match):
        guard.validate_advanced_config(cfg)


def test_locations_advanced_config_checked():
    fwd = {"forward_scheme": "http", "forward_host": "app", "forward_port": 8080}
    with pytest.raises(GuardError, match=r"locations\[1\]\.advanced_config.*proxy_pass"):
        guard.validate_locations([
            {"path": "/a", **fwd, "advanced_config": "expires 1d;"},
            {"path": "/b", **fwd, "advanced_config": "proxy_pass http://127.0.0.1:81;"},
        ])
    out = guard.validate_locations([{"path": "/a", **fwd, "advanced_config": None}])
    assert out == [{"path": "/a", **fwd, "forward_path": "", "advanced_config": ""}]


async def test_proxy_host_create_preview_rejects_advanced_config(npm_login, dns_ok):
    """Ablehnung schon in der Vorschau ohne confirm, nichts wird angelegt."""
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    npm_login.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    bad = "location /x { proxy_pass http://127.0.0.1:81; }"
    with pytest.raises(GuardError, match="advanced_config"):
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, advanced_config=bad)
    with pytest.raises(GuardError, match="advanced_config"):
        await tools_npm.npm_proxy_host_create(["app.example.com"], "http", "app", 8080, advanced_config=bad, confirm=True)
    assert written(npm_login) == []
    out = await tools_npm.npm_proxy_host_create(
        ["app.example.com"], "http", "app", 8080, ssl=False, advanced_config="client_max_body_size 50m;\ngzip on;"
    )
    assert out["preview"] is True and out["payload"]["advanced_config"] == "client_max_body_size 50m;\ngzip on;"


async def test_proxy_host_update_rejects_advanced_config(npm_login):
    npm_login.get(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json=proxy_host(8, ["app.example.com"]))
    put = npm_login.put(f"{NPM_API}/nginx/proxy-hosts/8").respond(200, json={"id": 8})
    for cfg in ("alias /data/;", "proxy_pass http://portainer:9000;", "location / { }"):
        with pytest.raises(GuardError, match="advanced_config"):
            await tools_npm.npm_proxy_host_update(8, advanced_config=cfg)
        with pytest.raises(GuardError, match="advanced_config"):
            await tools_npm.npm_proxy_host_update(8, advanced_config=cfg, confirm=True)
    assert put.call_count == 0
    await tools_npm.npm_proxy_host_update(8, advanced_config="proxy_read_timeout 600s;", confirm=True)
    assert json.loads(put.calls.last.request.read()) == {"advanced_config": "proxy_read_timeout 600s;"}


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
        "      - /var/run/docker.sock:/var/run/docker.sock:ro\n",
        "      - type: bind\n        source: /run/docker.sock\n        target: /var/run/docker.sock\n",
        "      - /var/run/../run/docker.sock:/var/run/docker.sock\n",
    ],
)
def test_compose_docker_socket_needs_server_setting(volumes, monkeypatch):
    """Docker-Socket nur über die Server-Einstellung ALLOW_DOCKER_SOCKET_STACKS, nie per Tool-Parameter."""
    compose = "services:\n  a:\n    image: x\n    volumes:\n" + volumes
    unnormalized = ".." in volumes  # '..' wird immer abgelehnt, unabhängig von der Einstellung
    with pytest.raises(GuardError, match="'\\.\\.'" if unnormalized else "ALLOW_DOCKER_SOCKET_STACKS"):
        guard.validate_compose(compose)
    monkeypatch.setenv("ALLOW_DOCKER_SOCKET_STACKS", "true")
    config.reset()
    if unnormalized:
        with pytest.raises(GuardError, match="'\\.\\.'"):
            guard.validate_compose(compose)
    else:
        # Auch ohne BIND_MOUNT_ALLOWED_PREFIXES erlaubt, sobald serverseitig freigeschaltet
        assert guard.validate_compose(compose)["services"]["a"]


def test_compose_docker_socket_parameter_removed():
    import inspect

    from infra_mcp import tools_workflow

    for fn in (
        tools_portainer.portainer_stack_create,
        tools_portainer.portainer_stack_create_git,
        tools_portainer.portainer_stack_update,
        tools_workflow.infra_publish_service,
    ):
        assert "allow_docker_socket" not in inspect.signature(fn).parameters
    with pytest.raises(TypeError):
        guard.validate_compose("services:\n  a:\n    image: x\n", allow_docker_socket=True)


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


@pytest.fixture
def bind_allowlist(monkeypatch):
    """Betreiber gibt /srv/stacks und /home/deploy (read-write), /etc/localtime und /var/lib/docker
    (sensibel, nur ro) sowie /var und /opt (weit gefasst) frei."""
    monkeypatch.setenv("BIND_MOUNT_ALLOWED_PREFIXES", "/srv/stacks, /etc/localtime,/var/lib/docker,/var,/home/deploy,/opt")
    config.reset()


@pytest.mark.parametrize("extra,match", [
    ("    cap_add: [SYS_ADMIN]\n", "cap_add"),
    ("    devices: ['/dev/sda:/dev/sda']\n", "devices"),
    ("    security_opt: ['seccomp:unconfined']\n", "security_opt"),
    ("    security_opt: ['apparmor:unconfined']\n", "security_opt"),
    ("    pid: host\n", "pid"),
    ("    network_mode: host\n", "network_mode"),
    ("    userns_mode: host\n", "userns_mode"),
    ("    volumes:\n      - /:/host\n", "nicht erlaubt"),
    ("    volumes:\n      - /etc:/hostetc:rw\n", "read-only"),
    ("    volumes:\n      - type: bind\n        source: /var/lib/docker\n        target: /d\n", "read-only"),
])
def test_compose_escape_options_rejected(extra, match, bind_allowlist):
    with pytest.raises(GuardError, match=match):
        guard.validate_compose("services:\n  a:\n    image: x\n" + extra)


@pytest.mark.parametrize("extra", [
    "    security_opt: ['no-new-privileges:true']\n",
    "    security_opt:\n      - no-new-privileges\n",
    "    volumes:\n      - /etc/localtime:/etc/localtime:ro\n",
    "    volumes:\n      - /var/lib/docker:/d:ro\n",
    "    volumes:\n      - /srv/stacks/app/data:/data\n",
    "    volumes:\n      - /srv/stacks:/data:rw\n",
    "    volumes:\n      - /home/deploy/app:/data\n",
    "    volumes:\n      - /opt/app:/x:ro\n",
    "    volumes:\n      - type: bind\n        source: /srv/stacks/app\n        target: /data\n",
    "    volumes:\n      - ./config:/config:ro\n",
    "    volumes:\n      - appdata:/data\nvolumes:\n  appdata:\n",
    "    volumes:\n      - appdata:/data\nvolumes:\n  appdata: {}\n",
    "    volumes:\n      - appdata:/data\nvolumes:\n  appdata:\n    driver: local\n    labels: [x=y]\n",
    "    volumes:\n      - type: volume\n        source: appdata\n        target: /data\nvolumes:\n  appdata:\n",
    "    volumes:\n      - type: tmpfs\n        target: /tmp\n",
    "    volumes:\n      - /data\n",
    "    tmpfs: [/run]\n",
    "    network_mode: bridge\n",
    "    network_mode: none\n",
    "    cap_drop: [ALL]\n",
    "    sysctls:\n      net.core.somaxconn: 1024\n      net.ipv4.ip_unprivileged_port_start: 0\n",
    "    sysctls:\n      - net.ipv4.tcp_syncookies=1\n",
    "    ulimits:\n      nofile:\n        soft: 65536\n        hard: 65536\n      nproc: 4096\n",
    "    env_file: .env\n",
    "    env_file: [./app.env]\n",
])
def test_compose_safe_options_allowed(extra, bind_allowlist):
    assert guard.validate_compose("services:\n  a:\n    image: x\n" + extra)


# Umgehungen aus dem Security-Review: jede einzelne muss jetzt abgelehnt werden.
@pytest.mark.parametrize("extra,match", [
    # Docker-Socket über Verzeichnis-Mount read-only (ro verhindert kein connect())
    ("    volumes:\n      - /var/run:/h:ro\n", "auch nicht read-only"),
    ("    volumes:\n      - /run:/h:ro\n", "auch nicht read-only"),
    ("    volumes:\n      - /run/containerd:/h:ro\n", "auch nicht read-only"),
    ("    volumes:\n      - /:/host:ro,rslave\n", "auch nicht read-only"),
    ("    volumes:\n      - type: bind\n        source: /\n        target: /host\n        read_only: true\n", "auch nicht read-only"),
    # fehlende Pfad-Normalisierung
    ("    volumes:\n      - /home/../etc:/x\n", "'\\.\\.'"),
    ("    volumes:\n      - /srv/stacks/../../etc:/x\n", "'\\.\\.'"),
    ("    volumes:\n      - /opt/../var/lib/docker:/x\n", "'\\.\\.'"),
    ("    volumes:\n      - //etc:/x:ro\n", "ausserhalb"),
    ("    volumes:\n      - /var/./lib/docker:/x:rw\n", "read-only"),
    # kritische Host-Pfade read-write
    ("    volumes:\n      - /var/spool/cron:/c\n", "read-only"),
    ("    volumes:\n      - /var/spool/cron/crontabs:/c:rw\n", "read-only"),
    ("    volumes:\n      - /var/lib/portainer:/p\n", "read-only"),
    ("    volumes:\n      - /var/lib/containerd:/p\n", "read-only"),
    # weit gefasste Pfade: Allowlist "/opt" allein reicht nicht für read-write
    ("    volumes:\n      - /opt/app:/x\n", "unterhalb von /opt"),
    ("    volumes:\n      - /opt:/x:rw\n", "unterhalb von /opt"),
    # ausserhalb der Allowlist
    ("    volumes:\n      - /home:/h\n", "ausserhalb"),
    ("    volumes:\n      - /home/other:/h:ro\n", "ausserhalb"),
    ("    volumes:\n      - /srv/app/data:/data\n", "ausserhalb"),
    ("    volumes:\n      - /srv/stacksfoo:/data\n", "ausserhalb"),
    ("    volumes:\n      - /etc/localtime2:/x:ro\n", "ausserhalb"),
    ("    volumes:\n      - /etc/ssh:/x:ro\n", "ausserhalb"),
    # volumes_from, externe/fremde Volumes
    ("    volumes_from: [portainer]\n", "volumes_from"),
    ("    volumes:\n      - portainer_data:/data\nvolumes:\n  portainer_data:\n    external: true\n", "external"),
    ("    volumes:\n      - pd:/data\nvolumes:\n  pd:\n    name: portainer_data\n", "name"),
    ("    volumes:\n      - appdata:/data\n", "nicht im Top-level-Abschnitt"),
    ("    volumes:\n      - type: volume\n        source: appdata\n        target: /data\n", "nicht im Top-level-Abschnitt"),
    # versteckter Bind-Mount über driver_opts
    ("    volumes:\n      - etc:/x\nvolumes:\n  etc:\n    driver: local\n    driver_opts:\n      type: none\n      device: /etc\n      o: bind\n", "driver_opts"),
    ("    volumes:\n      - nfs:/x\nvolumes:\n  nfs:\n    driver: nfs-plugin\n", "driver"),
    # Namespace-Join auf fremde Container, cgroup
    ("    pid: container:npm\n", "pid"),
    ("    pid: 'service:other'\n", "pid"),
    ("    network_mode: container:portainer\n", "network_mode"),
    ("    ipc: container:abc\n", "ipc"),
    ("    cgroup: host\n", "cgroup"),
    ("    userns_mode: container:x\n", "userns_mode"),
    ("    cgroup_parent: /docker/other.slice\n", "cgroup_parent"),
    # sysctls / ulimits
    ("    sysctls:\n      kernel.msgmax: 65536\n", "sysctl"),
    ("    sysctls:\n      - fs.file-max=1\n", "sysctl"),
    ("    ulimits:\n      nofile: -1\n", "ulimit"),
    ("    ulimits:\n      memlock:\n        soft: -1\n        hard: -1\n", "ulimit"),
    ("    ulimits:\n      nproc: 1000000\n", "Maximum"),
    # Dateizugriffe ausserhalb des Projektverzeichnisses
    ("    volumes:\n      - ../other-stack:/x\n", "verlässt"),
    ("    volumes:\n      - ./a/../../x:/x\n", "verlässt"),
    ("    volumes:\n      - ~/.ssh:/x\n", "Home-Verzeichnis"),
    ("    env_file: /etc/shadow\n", "env_file"),
    ("    env_file: [../../x.env]\n", "env_file"),
    ("    extends:\n      file: ../../other.yml\n      service: x\n", "extends"),
    # Variablen würden die Prüfung erst beim Deploy aushebeln
    ("    privileged: ${PRIV}\n", "Variablen"),
    ("    pid: ${NS}\n", "Variablen"),
    ("    volumes:\n      - ${DATA}:/data\n", "Variablen"),
    ("    volumes:\n      - type: bind\n        source: $HOME\n        target: /data\n", "Variablen"),
])
def test_compose_review_bypasses_rejected(extra, match, bind_allowlist):
    with pytest.raises(GuardError, match=match):
        guard.validate_compose("services:\n  a:\n    image: x\n" + extra)


def test_compose_top_level_secret_file_rejected(bind_allowlist):
    with pytest.raises(GuardError, match="secrets 'db'"):
        guard.validate_compose("services:\n  a:\n    image: x\nsecrets:\n  db:\n    file: /data/portainer.db\n")
    with pytest.raises(GuardError, match="configs 'c'"):
        guard.validate_compose("services:\n  a:\n    image: x\nconfigs:\n  c:\n    file: ../x\n")
    assert guard.validate_compose("services:\n  a:\n    image: x\nsecrets:\n  db:\n    file: ./db.txt\n")


def test_compose_no_bind_mounts_without_allowlist():
    """Fail-safe: ohne BIND_MOUNT_ALLOWED_PREFIXES ist kein Host-Pfad erlaubt, auch nicht read-only."""
    assert not config.settings().bind_mount_allowed_prefixes
    for vol in ("/srv/stacks/app:/data", "/etc/localtime:/etc/localtime:ro", "/tmp/x:/x:ro"):
        with pytest.raises(GuardError, match="BIND_MOUNT_ALLOWED_PREFIXES ist leer"):
            guard.validate_compose(f"services:\n  a:\n    image: x\n    volumes:\n      - {vol}\n")
    assert guard.validate_compose("services:\n  a:\n    image: x\n    volumes:\n      - d:/data\nvolumes:\n  d:\n")


def test_compose_guarded_paths_need_explicit_prefix(monkeypatch):
    """/home, /opt, /srv read-write nur, wenn die Allowlist ein Verzeichnis darunter nennt."""
    compose = "services:\n  a:\n    image: x\n    volumes:\n      - /opt/app/data:/data\n"
    monkeypatch.setenv("BIND_MOUNT_ALLOWED_PREFIXES", "/opt/app")
    config.reset()
    assert guard.validate_compose(compose)
    monkeypatch.setenv("BIND_MOUNT_ALLOWED_PREFIXES", "/opt")
    config.reset()
    with pytest.raises(GuardError, match="unterhalb von /opt"):
        guard.validate_compose(compose)
    assert guard.validate_compose(compose.replace("/data\n", "/data:ro\n"))
    # Allowlist "/" wird verworfen (fail-safe) -> gar keine Bind-Mounts
    monkeypatch.setenv("BIND_MOUNT_ALLOWED_PREFIXES", "/, relative/path, /x/../..")
    config.reset()
    assert config.settings().bind_mount_allowed_prefixes == ()
    with pytest.raises(GuardError, match="BIND_MOUNT_ALLOWED_PREFIXES ist leer"):
        guard.validate_compose(compose)


def test_compose_allowlist_normalized(monkeypatch):
    monkeypatch.setenv("BIND_MOUNT_ALLOWED_PREFIXES", "/srv/stacks/,//srv//stacks/./app")
    config.reset()
    assert config.settings().bind_mount_allowed_prefixes == ("/srv/stacks", "/srv/stacks/app")


async def test_stack_create_preview_shows_compose_rejection(mock):
    """Auch die Vorschau ohne confirm lehnt ab, und Portainer wird nicht angefragt."""
    compose = "services:\n  a:\n    image: x\n    volumes:\n      - /var/run:/h:ro\n"
    with pytest.raises(GuardError, match="auch nicht read-only"):
        await tools_portainer.portainer_stack_create("new-stack", 1, compose)
    assert not written(mock)


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


# ---------------------------------------------------------------------------
# Git-Stacks ohne sichtbare GitConfig (Portainer 2.4x, kein Zugriff auf die GitOps-Source)
# ---------------------------------------------------------------------------


async def test_redeploy_workflow_stack_uses_git_endpoint_never_put(mock):
    mock.get(f"{PORTAINER_API}/stacks/11").respond(
        200, json={"Id": 11, "Name": "gitapp", "Type": 2, "EndpointId": 1, "GitConfig": None, "WorkflowID": 4, "Status": 1}
    )
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/json").respond(200, json=[])
    put = mock.put(f"{PORTAINER_API}/stacks/11").respond(200, json={})
    git = mock.put(f"{PORTAINER_API}/stacks/11/git/redeploy").respond(200, json={})
    prev = await tools_portainer.portainer_stack_redeploy(11)
    assert prev["method"] == "git_redeploy"
    assert prev["stack"]["git"]["workflow_id"] == 4
    out = await tools_portainer.portainer_stack_redeploy(11, confirm=True)
    assert out["method"] == "git_redeploy" and git.call_count == 1 and put.call_count == 0


async def test_redeploy_workflow_stack_without_source_access_explains(mock):
    mock.get(f"{PORTAINER_API}/stacks/12").respond(
        200, json={"Id": 12, "Name": "gitapp2", "Type": 2, "EndpointId": 1, "WorkflowID": 5}
    )
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/json").respond(200, json=[])
    put = mock.put(f"{PORTAINER_API}/stacks/12").respond(200, json={})
    mock.put(f"{PORTAINER_API}/stacks/12/git/redeploy").respond(400, json={"message": "Stack is not created from git"})
    from infra_mcp.errors import PortainerError

    with pytest.raises(PortainerError, match="GitOps-Source"):
        await tools_portainer.portainer_stack_redeploy(12, confirm=True)
    assert put.call_count == 0


async def test_stack_update_refuses_workflow_stack(mock):
    mock.get(f"{PORTAINER_API}/stacks/13").respond(
        200, json={"Id": 13, "Name": "gitapp3", "Type": 2, "EndpointId": 1, "WorkflowID": 6}
    )
    put = mock.put(f"{PORTAINER_API}/stacks/13").respond(200, json={})
    with pytest.raises(GuardError, match="Git"):
        await tools_portainer.portainer_stack_update(13, compose_content="services:\n  a:\n    image: x\n", confirm=True)
    assert put.call_count == 0


# ---------------------------------------------------------------------------
# portainer_stack_update auf Git-Stacks: nur env_set / env_unset
# ---------------------------------------------------------------------------

GIT_ENV = [
    {"name": "API_TOKEN", "value": "token-geheim-123"},
    {"name": "MODE", "value": "alt-wert-a"},
    {"name": "MCP_HOST_PORT", "value": "8424"},
]


def git_stack_json(env=None, status=1, **extra):
    s = {
        "Id": 30, "Name": "gitenv", "Type": 2, "EndpointId": 2, "Status": status, "WorkflowID": 7,
        "GitConfig": {"URL": "https://github.com/example/app", "ReferenceName": "refs/heads/release", "ConfigFilePath": "docker-compose.yml"},
        "Env": GIT_ENV if env is None else env,
    }
    s.update(extra)
    return s


@pytest.fixture
def gitupd(mock):
    """Git-Stack 30: der zweite GET liefert den Stand nach dem Deploy (Env wie geschickt)."""
    state = {"env": GIT_ENV}

    def stack_get(request):
        return httpx.Response(200, json=git_stack_json(state["env"]))

    def redeploy(request):
        state["env"] = json.loads(request.read())["Env"]
        return httpx.Response(200, json={"Id": 30})

    mock.get(f"{PORTAINER_API}/stacks/30").mock(side_effect=stack_get)
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    put = mock.put(f"{PORTAINER_API}/stacks/30").respond(200, json={})
    git = mock.put(f"{PORTAINER_API}/stacks/30/git/redeploy").mock(side_effect=redeploy)
    return {"put": put, "git": git, "router": mock}


async def test_git_stack_env_preview_marks_actions_and_hides_secrets(gitupd):
    prev = await tools_portainer.portainer_stack_update(
        30, env_set={"MODE": "neu-wert-b", "NEW_FLAG": "1", "DB_PASSWORD": "pw-neu-456"}, env_unset=["MCP_HOST_PORT"]
    )
    assert prev["preview"] is True and prev["executed"] is False
    assert written(gitupd["router"]) == []
    changes = {c["name"]: c for c in prev["env_changes"]}
    assert changes["MODE"] == {"name": "MODE", "aktion": "geändert", "wert": "neu-wert-b"}
    assert changes["NEW_FLAG"] == {"name": "NEW_FLAG", "aktion": "neu", "wert": "1"}
    assert changes["DB_PASSWORD"] == {"name": "DB_PASSWORD", "aktion": "neu", "wert": "***"}
    assert changes["MCP_HOST_PORT"] == {"name": "MCP_HOST_PORT", "aktion": "entfernt"}
    dumped = json.dumps(prev)
    # Bestehende Werte nie, neue Secret-Werte nie
    for v in ("token-geheim-123", "alt-wert-a", "pw-neu-456"):
        assert v not in dumped
    assert prev["reference"] == "refs/heads/release" and prev["prune"] is False


@pytest.mark.parametrize("name", ["SMTP_PASSWORD", "GITHUB_TOKEN", "API_KEY", "CLIENT_SECRET"])
async def test_git_stack_env_preview_masks_secret_names(gitupd, name):
    prev = await tools_portainer.portainer_stack_update(30, env_set={name: "sehr-geheim-789"})
    assert prev["env_changes"] == [{"name": name, "aktion": "neu", "wert": "***"}]
    assert "sehr-geheim-789" not in json.dumps(prev)


async def test_git_stack_env_execute_sends_full_env_and_keeps_reference(gitupd, capsys):
    out = await tools_portainer.portainer_stack_update(
        30, env_set={"MODE": "neu-wert-b", "MCP_BIND_ADDR": "192.0.2.10"}, pull_image=False, confirm=True
    )
    assert gitupd["put"].call_count == 0 and gitupd["git"].call_count == 1
    req = gitupd["git"].calls.last.request
    assert req.url.params["endpointId"] == "2"
    body = json.loads(req.read())
    assert body["Env"] == [
        {"name": "API_TOKEN", "value": "token-geheim-123"},
        {"name": "MODE", "value": "neu-wert-b"},
        {"name": "MCP_HOST_PORT", "value": "8424"},
        {"name": "MCP_BIND_ADDR", "value": "192.0.2.10"},
    ]
    assert body["RepositoryReferenceName"] == "refs/heads/release"
    assert body["Prune"] is False and body["PullImage"] is False and body["RepullImageAndRedeploy"] is False
    assert "StackFileContent" not in body
    assert out["executed"] is True and out["stack_status"] == "active"
    assert "token-geheim-123" not in json.dumps(out)
    # Audit: ein Eintrag pro Variable, ohne Werte
    events = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.startswith("{")]
    env_events = [e for e in events if e["event"] == "stack_env_change"]
    assert sorted((e["variable"], e["aktion"]) for e in env_events) == [("MCP_BIND_ADDR", "neu"), ("MODE", "geändert")]
    assert all(e["stack"] == "gitenv" and e["stack_id"] == 30 for e in env_events)
    assert "neu-wert-b" not in json.dumps(env_events) and "192.0.2.10" not in json.dumps(env_events)


async def test_git_stack_env_unset(gitupd):
    await tools_portainer.portainer_stack_update(30, env_unset=["MODE"], confirm=True)
    body = json.loads(gitupd["git"].calls.last.request.read())
    assert [e["name"] for e in body["Env"]] == ["API_TOKEN", "MCP_HOST_PORT"]
    assert body["PullImage"] is True


async def test_git_stack_compose_content_still_refused(gitupd):
    with pytest.raises(GuardError, match="compose_content ist hier gesperrt"):
        await tools_portainer.portainer_stack_update(30, compose_content=NEW_COMPOSE, env_set={"MODE": "b"}, confirm=True)
    assert written(gitupd["router"]) == []


async def test_git_stack_env_nothing_or_no_change(gitupd):
    with pytest.raises(GuardError, match="Nichts zu ändern"):
        await tools_portainer.portainer_stack_update(30, confirm=True)
    with pytest.raises(GuardError, match="Keine Änderung"):
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "alt-wert-a"}, confirm=True)
    with pytest.raises(GuardError, match="nicht im Stack"):
        await tools_portainer.portainer_stack_update(30, env_unset=["GIBTSNICHT"], confirm=True)
    with pytest.raises(GuardError, match="gleichzeitig"):
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "x"}, env_unset=["MODE"], confirm=True)
    assert written(gitupd["router"]) == []


async def test_git_stack_env_aborts_on_incomplete_env(mock):
    mock.get(f"{PORTAINER_API}/stacks/30").respond(200, json=git_stack_json([{"name": "API_TOKEN"}, {"name": "MODE", "value": "a"}]))
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    git = mock.put(f"{PORTAINER_API}/stacks/30/git/redeploy").respond(200, json={})
    with pytest.raises(GuardError, match="unvollständig"):
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "b"}, confirm=True)
    assert git.call_count == 0


async def test_git_stack_env_without_visible_reference_aborts(mock):
    mock.get(f"{PORTAINER_API}/stacks/31").respond(
        200, json={"Id": 31, "Name": "gitapp4", "Type": 2, "EndpointId": 1, "WorkflowID": 8, "GitConfig": None, "Env": []}
    )
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/json").respond(200, json=[])
    git = mock.put(f"{PORTAINER_API}/stacks/31/git/redeploy").respond(200, json={})
    put = mock.put(f"{PORTAINER_API}/stacks/31").respond(200, json={})
    with pytest.raises(GuardError, match="Git-Referenz"):
        await tools_portainer.portainer_stack_update(31, env_set={"MODE": "b"}, confirm=True)
    assert git.call_count == 0 and put.call_count == 0


async def test_git_stack_env_blocked_for_protected_stack(mock):
    mock.get(f"{PORTAINER_API}/stacks/32").respond(200, json=git_stack_json(Id=32, Name="core-git"))
    git = mock.put(f"{PORTAINER_API}/stacks/32/git/redeploy").respond(200, json={})
    with pytest.raises(GuardError, match="geschützt"):
        await tools_portainer.portainer_stack_update(32, env_set={"MODE": "b"})
    assert git.call_count == 0


async def test_git_stack_env_blocked_by_protected_container(mock):
    mock.get(f"{PORTAINER_API}/stacks/30").respond(200, json=git_stack_json())
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(
        200, json=[{"Id": "abc", "Names": ["/db-main"], "Labels": {"com.docker.compose.project": "gitenv"}}]
    )
    git = mock.put(f"{PORTAINER_API}/stacks/30/git/redeploy").respond(200, json={})
    with pytest.raises(GuardError, match="db-main"):
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "b"}, confirm=True)
    assert git.call_count == 0


async def test_git_stack_env_reports_deploy_error(mock):
    mock.get(f"{PORTAINER_API}/stacks/30").mock(side_effect=[
        httpx.Response(200, json=git_stack_json()),
        httpx.Response(200, json=git_stack_json(status=4, DeploymentStatus=[{"Message": "pull access denied"}])),
    ])
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    mock.put(f"{PORTAINER_API}/stacks/30/git/redeploy").respond(200, json={"Id": 30})
    from infra_mcp.errors import PortainerError

    with pytest.raises(PortainerError, match="pull access denied"):
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "b"}, confirm=True)


async def test_git_stack_env_detects_env_not_taken_over(mock):
    # Portainer meldet Erfolg, hat die Env aber nicht übernommen -> Fehler statt "ok"
    mock.get(f"{PORTAINER_API}/stacks/30").respond(200, json=git_stack_json())
    mock.get(f"{PORTAINER_API}/endpoints/2/docker/containers/json").respond(200, json=[])
    mock.put(f"{PORTAINER_API}/stacks/30/git/redeploy").respond(200, json={"Id": 30})
    from infra_mcp.errors import PortainerError

    with pytest.raises(PortainerError, match="nicht wie geschickt") as exc:
        await tools_portainer.portainer_stack_update(30, env_set={"MODE": "neu-wert-b"}, confirm=True)
    assert "MODE" in str(exc.value) and "neu-wert-b" not in str(exc.value)


def test_audit_params_hide_env_set_values():
    out = guard.redact_params({"stack_id": 30, "env_set": {"MODE": "klartext-wert"}, "env_unset": ["X"]})
    assert out["env_set"] == {"names": ["MODE"]}
    assert "klartext-wert" not in json.dumps(out)


# ---------------------------------------------------------------------------
# portainer_stack_create_git
# ---------------------------------------------------------------------------

GIT_COMPOSE = (
    "services:\n  app:\n    image: ghcr.io/example/app:latest\n    environment:\n"
    "      - API_KEY=${API_KEY}\n      - BASE_URL=${BASE_URL:-https://api.example.com}\n"
    "    ports:\n      - \"${MCP_HOST_PORT:-8424}:8000\"\n"
)
RAW = "https://raw.githubusercontent.com/example-org/app-mcp/main/docker-compose.yml"


@pytest.fixture
def gitmock(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    mock.get(RAW).respond(200, text=GIT_COMPOSE)
    create = mock.post(f"{PORTAINER_API}/stacks/create/standalone/repository").respond(200, json={"Id": 55})
    mock.get(f"{PORTAINER_API}/stacks/55").respond(200, json={"Id": 55, "Name": "app-mcp", "Type": 2, "Status": 1, "WorkflowID": 9})
    return create


async def test_create_git_preview_and_execute(gitmock):
    args = dict(name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp",
                env={"API_KEY": "geheimer-key-123", "MCP_HOST_PORT": "8424"})
    prev = await tools_portainer.portainer_stack_create_git(**args)
    assert prev["preview"] is True and gitmock.call_count == 0
    assert prev["env_missing_without_default"] == []
    assert "geheimer-key-123" not in json.dumps(prev)
    out = await tools_portainer.portainer_stack_create_git(**args, confirm=True)
    body = json.loads(gitmock.calls.last.request.read())
    assert body["RepositoryURL"] == "https://github.com/example-org/app-mcp"
    assert body["RepositoryReferenceName"] == "refs/heads/main" and body["ComposeFile"] == "docker-compose.yml"
    assert body["RepositoryAuthentication"] is False and "AutoUpdate" not in body
    assert {"name": "API_KEY", "value": "geheimer-key-123"} in body["Env"]
    assert gitmock.calls.last.request.url.params["endpointId"] == "3"
    assert out["stack_id"] == 55 and out["stack_status"] == "active"
    assert "geheimer-key-123" not in json.dumps(out)


async def test_create_git_reports_missing_env(gitmock):
    prev = await tools_portainer.portainer_stack_create_git(
        name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp.git"
    )
    assert prev["env_missing_without_default"] == ["API_KEY"]


async def test_create_git_auto_update(gitmock):
    await tools_portainer.portainer_stack_create_git(
        name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp",
        env={"API_KEY": "x"}, auto_update_interval="5m", confirm=True,
    )
    body = json.loads(gitmock.calls.last.request.read())
    assert body["AutoUpdate"] == {"Interval": "5m", "ForcePullImage": True, "ForceUpdate": False}


async def test_create_git_rejects_unsafe_compose_from_repo(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    mock.get(RAW).respond(200, text="services:\n  a:\n    image: x\n    privileged: true\n")
    create = mock.post(f"{PORTAINER_API}/stacks/create/standalone/repository").respond(200, json={"Id": 1})
    with pytest.raises(GuardError, match="privileged"):
        await tools_portainer.portainer_stack_create_git(
            name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp", confirm=True
        )
    assert create.call_count == 0


@pytest.mark.parametrize("url", [
    "http://github.com/example-org/app",
    "https://gitlab.com/example-org/app",
    "https://github.com/example-org",
    "https://github.com/example-org/app/../../x",
    "git@github.com:example-org/app.git",
])
async def test_create_git_rejects_bad_urls(mock, url):
    with pytest.raises(GuardError):
        await tools_portainer.portainer_stack_create_git(name="app-mcp", endpoint_id=3, repository_url=url)


@pytest.mark.parametrize("ref,path", [("main", "docker-compose.yml"), ("refs/heads/main", "../x.yml"), ("refs/heads/main", "/etc/x")])
async def test_create_git_rejects_bad_ref_or_path(mock, ref, path):
    with pytest.raises(GuardError):
        await tools_portainer.portainer_stack_create_git(
            name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app", reference=ref, compose_path=path
        )


async def test_create_git_allowed_prefixes(mock, monkeypatch):
    monkeypatch.setenv("GIT_ALLOWED_REPO_PREFIXES", "https://github.com/example-org")
    config.reset()
    with pytest.raises(GuardError, match="GIT_ALLOWED_REPO_PREFIXES"):
        await tools_portainer.portainer_stack_create_git(
            name="app-mcp", endpoint_id=3, repository_url="https://github.com/other-org/app"
        )


async def test_create_git_private_or_missing_file(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    mock.get(RAW).respond(404, text="404: Not Found")
    with pytest.raises(GuardError, match="privat"):
        await tools_portainer.portainer_stack_create_git(
            name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp"
        )


async def test_create_git_deploy_error(mock):
    mock.get(f"{PORTAINER_API}/stacks").respond(200, json=[])
    mock.get(RAW).respond(200, text=GIT_COMPOSE)
    mock.post(f"{PORTAINER_API}/stacks/create/standalone/repository").respond(200, json={"Id": 56})
    mock.get(f"{PORTAINER_API}/stacks/56").respond(
        200, json={"Id": 56, "Status": 4, "DeploymentStatus": [{"Message": "port is already allocated"}]}
    )
    from infra_mcp.errors import PortainerError

    with pytest.raises(PortainerError, match="already allocated"):
        await tools_portainer.portainer_stack_create_git(
            name="app-mcp", endpoint_id=3, repository_url="https://github.com/example-org/app-mcp",
            env={"API_KEY": "x"}, confirm=True,
        )

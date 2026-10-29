"""Custom Locations auf NPM-Proxy-Hosts: Zusammenführen, Prüfungen, nginx-Fehler und Wiederherstellung."""

import json

import httpx
import pytest
from conftest import NPM_API, NPM_NETWORK, PORTAINER_API, written

from infra_mcp import config, guard, tools_npm
from infra_mcp.errors import GuardError, NpmError, UnclearStateError

HOST_IP = "192.0.2.25"
DOMAIN = "mcp.example.com"
HOST_URL = f"{NPM_API}/nginx/proxy-hosts/12"
CONTAINER_LIST = f"{PORTAINER_API}/endpoints/1/docker/containers/json"

EXISTING = {"id": 1, "path": "/docs", "forward_scheme": "http", "forward_host": HOST_IP, "forward_port": 8440,
            "forward_path": "", "advanced_config": ""}
NEW = {"path": "/app", "forward_scheme": "http", "forward_host": HOST_IP, "forward_port": 8438}

SCHEMA_V2_12 = {"components": {"schemas": {"proxy-host": {"properties": {"locations": {"items": {"properties": {
    "id": {}, "path": {}, "forward_scheme": {}, "forward_host": {}, "forward_port": {}, "forward_path": {},
    "advanced_config": {}}}}, "access_list_id": {}}}}}}
SCHEMA_V2_16 = {"components": {"schemas": {"proxy-host": {"properties": {"locations": {"items": {"properties": {
    "id": {}, "path": {}, "forward_scheme": {}, "forward_host": {}, "forward_port": {}, "forward_path": {},
    "advanced_config": {}, "access_list_id": {}}}}, "access_list_id": {}}}}}}


def proxy_host(locations, online=True, err=None, enabled=True):
    meta = {"nginx_online": online, "nginx_err": err}
    return {
        "id": 12, "domain_names": [DOMAIN], "forward_scheme": "http", "forward_host": HOST_IP, "forward_port": 8435,
        "enabled": enabled, "certificate_id": 0, "ssl_forced": False, "advanced_config": "", "meta": meta,
        "allow_websocket_upgrade": False, "block_exploits": True, "http2_support": False, "hsts_enabled": False,
        "access_list_id": 0, "certificate": None, "locations": [dict(x) for x in locations],
    }


def container(name="app-web-1", ports=(8438, 8440)):
    return {"Id": "abcabcabcabc0001", "Names": [f"/{name}"], "State": "running", "Image": "img", "Labels": {},
            "Ports": [{"IP": "0.0.0.0", "PrivatePort": 8000, "PublicPort": p, "Type": "tcp"} for p in ports]}


def puts(router):
    return [json.loads(r.read()) for r in written(router) if r.method == "PUT"]


@pytest.fixture
def loc_env(npm_login, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST_IP", HOST_IP)
    config.reset()
    m = npm_login
    m.get(f"{PORTAINER_API}/endpoints").respond(200, json=[{"Id": 1}])
    m.get(CONTAINER_LIST).respond(200, json=[container()])
    m.put(HOST_URL).respond(200, json={"id": 12})
    return m


def host_reads(router, *hosts):
    router.get(HOST_URL).mock(side_effect=[httpx.Response(200, json=h) for h in hosts])


# ---------------------------------------------------------------------------
# Zusammenführen und Schreiben
# ---------------------------------------------------------------------------


async def test_add_location_preview_then_put_only_locations(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW])
    assert out["preview"] is True
    assert out["locations"] == [{"pfad": "/app", "aktion": "neu", "ziel": f"http://{HOST_IP}:8438", "advanced_config": ""}]
    assert written(loc_env) == []

    expected = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(expected))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert out["ok"] is True, out
    assert puts(loc_env) == [{"locations": expected}]


async def test_replace_and_remove_by_path(loc_env):
    other = {"id": 2, "path": "/old", "forward_scheme": "http", "forward_host": HOST_IP, "forward_port": 8438,
             "forward_path": "", "advanced_config": ""}
    replaced = {"path": "/docs", "forward_scheme": "http", "forward_host": HOST_IP, "forward_port": 8438,
                "forward_path": "/v2", "advanced_config": "proxy_read_timeout 120s;"}
    expected = [{"id": 1, **replaced}]
    host_reads(loc_env, proxy_host([EXISTING, other]), proxy_host([EXISTING, other]), proxy_host(expected))

    preview = await tools_npm.npm_proxy_host_update(12, locations_set=[replaced], locations_remove=["/old"])
    actions = {c["pfad"]: c["aktion"] for c in preview["locations"]}
    assert actions == {"/docs": "geändert", "/old": "entfernt"}
    assert written(loc_env) == []

    out = await tools_npm.npm_proxy_host_update(12, locations_set=[replaced], locations_remove=["/old"], confirm=True)
    assert out["ok"] is True, out
    assert puts(loc_env) == [{"locations": expected}]


async def test_unchanged_location_is_no_change(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]))
    same = {k: v for k, v in EXISTING.items() if k != "id"}
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[same], confirm=True)
    assert out["executed"] is False and out["note"] == "Keine Änderung."
    assert written(loc_env) == []


async def test_remove_unknown_path(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]))
    with pytest.raises(GuardError, match="keine Location"):
        await tools_npm.npm_proxy_host_update(12, locations_remove=["/nope"], confirm=True)
    assert written(loc_env) == []


async def test_locations_not_combined_with_other_fields(loc_env):
    with pytest.raises(GuardError, match="eigenen Aufruf"):
        await tools_npm.npm_proxy_host_update(12, forward_port=8439, locations_set=[NEW], confirm=True)
    assert loc_env.calls.call_count == 0


async def test_locations_blocked_for_protected_domain(loc_env):
    h = proxy_host([])
    h["domain_names"] = ["npm.example.com"]
    host_reads(loc_env, h)
    with pytest.raises(GuardError, match="geschützt"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert written(loc_env) == []


async def test_max_locations(loc_env):
    many = [{**EXISTING, "id": i, "path": f"/p{i}"} for i in range(20)]
    host_reads(loc_env, proxy_host(many))
    with pytest.raises(GuardError, match="Höchstens 20"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert written(loc_env) == []


# ---------------------------------------------------------------------------
# Prüfungen ohne Request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/../x", "/a/../b", "~ /x", "= /x", "^~ /x", "/a b", "/x{", "/x;", "/x$1",
                                  "x", "", "//x", "/" + "a" * 100])
async def test_invalid_path_rejected_without_request(loc_env, path):
    with pytest.raises(GuardError):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "path": path}])
    assert loc_env.calls.call_count == 0


async def test_invalid_remove_path_rejected(loc_env):
    with pytest.raises(GuardError):
        await tools_npm.npm_proxy_host_update(12, locations_remove=["/x;"])
    assert loc_env.calls.call_count == 0


async def test_duplicate_path_rejected(loc_env):
    with pytest.raises(GuardError, match="mehrfach"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW, {**NEW, "forward_port": 8440}])
    with pytest.raises(GuardError, match="zugleich"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], locations_remove=["/app"])
    assert loc_env.calls.call_count == 0


@pytest.mark.parametrize("change, match", [
    ({"forward_host": "127.0.0.1"}, "127.0.0.1"),
    ({"forward_host": "localhost"}, "localhost"),
    ({"forward_host": "0.0.0.0"}, "0.0.0.0"),
    ({"forward_host": "::1"}, "forward_host"),
    ({"forward_port": 81}, "NPM-Admin-API"),
    ({"forward_port": 9000}, "Portainer"),
    ({"forward_port": 9443}, "Portainer"),
    ({"forward_host": f"{HOST_IP}/admin"}, "forward_host"),
    ({"forward_scheme": "ftp"}, "forward_scheme"),
    ({"forward_path": "/a b"}, "forward_path"),
    ({"advanced_config": "proxy_pass http://127.0.0.1:81;"}, "proxy_pass"),
    ({"advanced_config": "location /x { }"}, "Blöcke"),
    ({"id": 5}, "unbekannte Felder"),
])
async def test_forbidden_location_values_without_request(loc_env, change, match):
    with pytest.raises(GuardError, match=match):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, **change}], confirm=True)
    assert loc_env.calls.call_count == 0


async def test_port_not_published_by_visible_container(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]))
    with pytest.raises(GuardError, match="Port 8499.*keinem"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "forward_port": 8499}], confirm=True)
    assert written(loc_env) == []


async def test_foreign_ip_rejected(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]))
    loc_env.get(CONTAINER_LIST).respond(200, json=[])
    with pytest.raises(GuardError, match="weder DOCKER_HOST_IP"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "forward_host": "198.51.100.7"}], confirm=True)
    assert written(loc_env) == []


async def test_foreign_ip_rejected_without_npm_network(loc_env, monkeypatch):
    monkeypatch.delenv("NPM_DOCKER_NETWORK")
    config.reset()
    host_reads(loc_env, proxy_host([EXISTING]))
    with pytest.raises(GuardError, match="nur DOCKER_HOST_IP"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "forward_host": "198.51.100.7"}], confirm=True)
    assert written(loc_env) == []


async def test_container_in_npm_network_allowed(loc_env):
    loc_env.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/json").respond(
        200, json={"NetworkSettings": {"Networks": {NPM_NETWORK: {}}}})
    host_reads(loc_env, proxy_host([]))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "forward_host": "app-web-1", "forward_port": 8000}])
    assert out["locations"][0]["ziel"] == "http://app-web-1:8000"


async def test_container_outside_npm_network_rejected(loc_env):
    loc_env.get(f"{PORTAINER_API}/endpoints/1/docker/containers/app-web-1/json").respond(
        200, json={"NetworkSettings": {"Networks": {"bridge": {}}}})
    host_reads(loc_env, proxy_host([]))
    with pytest.raises(GuardError, match="nicht im NPM-Netz"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "forward_host": "app-web-1", "forward_port": 8000}])
    assert written(loc_env) == []


# ---------------------------------------------------------------------------
# access_list_id je nach Schema der Instanz
# ---------------------------------------------------------------------------


async def test_access_list_id_dropped_on_v2_12(loc_env):
    loc_env.get(f"{NPM_API}/schema").respond(200, json=SCHEMA_V2_12)
    sent = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(sent))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "access_list_id": 3}], confirm=True)
    assert out["ok"] is True and "hinweis" in out
    assert puts(loc_env) == [{"locations": sent}]


async def test_access_list_id_sent_on_v2_16_only_when_given(loc_env):
    loc_env.get(f"{NPM_API}/schema").respond(200, json=SCHEMA_V2_16)
    sent = [EXISTING, {**NEW, "forward_path": "", "advanced_config": "", "access_list_id": 3}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(sent))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[{**NEW, "access_list_id": 3}], confirm=True)
    assert out["ok"] is True, out
    assert puts(loc_env) == [{"locations": sent}]

    schema = loc_env.get(f"{NPM_API}/schema")
    calls_before = schema.call_count
    plain = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(plain))
    await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert "access_list_id" not in puts(loc_env)[-1]["locations"][1]
    assert schema.call_count == calls_before  # ohne access_list_id kein Schema-Abruf


async def test_schema_detection():
    from infra_mcp.npm_client import NpmClient

    for schema, expected in ((SCHEMA_V2_12, False), (SCHEMA_V2_16, True)):
        transport = httpx.MockTransport(lambda req, s=schema: httpx.Response(
            200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"} if req.url.path.endswith("/tokens") else s))
        client = NpmClient(NPM_API, "u@example.com", "pw", transport=transport)
        assert await client.location_access_list_supported() is expected
        await client.aclose()


# ---------------------------------------------------------------------------
# nginx-Fehler, Abweichungen, Timeout
# ---------------------------------------------------------------------------


async def test_nginx_offline_restores_previous_locations(loc_env):
    new_list = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]),
               proxy_host(new_list, online=False, err="nginx: [emerg] host not found in upstream " + "x" * 800),
               proxy_host([EXISTING]), proxy_host([EXISTING]))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert out["ok"] is False
    assert "nginx-Test" in out["error"]
    assert out["nginx_err"].startswith("nginx: [emerg]") and len(out["nginx_err"]) == tools_npm.NGINX_ERR_MAX_CHARS
    assert out["restore"]["ok"] is True and "warnung" not in out
    assert puts(loc_env) == [{"locations": new_list}, {"locations": [EXISTING]}]


async def test_nginx_offline_and_restore_fails(loc_env):
    new_list = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(new_list, online=False, err="bad"),
               proxy_host([EXISTING], online=False, err="still bad"), proxy_host([EXISTING], online=False))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert out["restore"]["ok"] is False
    assert "OFFLINE" in out["warnung"]
    assert len(puts(loc_env)) == 2


async def test_stored_locations_differ(loc_env):
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host([EXISTING]))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert out["ok"] is False and "weichen" in out["error"]
    assert len(puts(loc_env)) == 1


async def test_put_error_without_change_raises(loc_env):
    loc_env.put(HOST_URL).respond(400, json={"error": {"message": "data/locations/1 must NOT have additional properties"}})
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host([EXISTING]))
    with pytest.raises(NpmError, match="nicht geändert.*additional properties"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)


async def test_put_timeout_is_unclear_and_not_retried(loc_env):
    loc_env.put(HOST_URL).mock(side_effect=httpx.ReadTimeout("t"))
    host_reads(loc_env, proxy_host([EXISTING]))
    with pytest.raises(UnclearStateError, match="unklar"):
        await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert len([r for r in written(loc_env) if r.method == "PUT"]) == 1


async def test_disabled_host_skips_nginx_check(loc_env):
    new_list = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING], enabled=False), proxy_host(new_list, online=False, enabled=False))
    out = await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    assert out["ok"] is True and "deaktiviert" in out["note"]
    assert len(puts(loc_env)) == 1


# ---------------------------------------------------------------------------
# Audit und Log
# ---------------------------------------------------------------------------


async def test_audit_entries_per_location(loc_env, capsys):
    other = {**EXISTING, "id": 2, "path": "/old"}
    new_list = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING, other]), proxy_host(new_list))
    await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], locations_remove=["/old"], confirm=True)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    changes = [e for e in events if e["event"] == "proxy_host_location_change"]
    assert {(e["pfad"], e["aktion"]) for e in changes} == {("/app", "neu"), ("/old", "entfernt")}
    assert all(e["proxy_host_id"] == 12 and e["domain_names"] == [DOMAIN] for e in changes)


async def test_audit_entry_for_restore(loc_env, capsys):
    new_list = [EXISTING, {**NEW, "forward_path": "", "advanced_config": ""}]
    host_reads(loc_env, proxy_host([EXISTING]), proxy_host(new_list, online=False, err="bad"),
               proxy_host([EXISTING]), proxy_host([EXISTING]))
    await tools_npm.npm_proxy_host_update(12, locations_set=[NEW], confirm=True)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    restore = [e for e in events if e["event"] == "proxy_host_location_restore"]
    assert len(restore) == 1 and restore[0]["ok"] is True


def test_tool_log_shows_only_paths_and_targets():
    params = guard.redact_params({"locations_set": [{**NEW, "advanced_config": "add_header X-Secret-Thing abc;"}],
                                  "locations_remove": ["/old"]})
    assert params["locations_set"] == [{"path": "/app", "target": f"http://{HOST_IP}:8438",
                                        "advanced_config": {"chars": 30}}]
    assert params["locations_remove"] == ["/old"]


# ---------------------------------------------------------------------------
# npm_proxy_host_create mit locations
# ---------------------------------------------------------------------------


@pytest.fixture
def create_env(loc_env):
    loc_env.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    loc_env.get(f"{NPM_API}/nginx/redirection-hosts").respond(200, json=[])
    loc_env.post(f"{NPM_API}/nginx/proxy-hosts").respond(201, json={"id": 50})
    loc_env.get(f"{NPM_API}/nginx/proxy-hosts/50").respond(200, json={**proxy_host([NEW]), "id": 50})
    return loc_env


async def create(**kw):
    args = dict(domain_names=["app.example.com"], forward_scheme="http", forward_host=HOST_IP, forward_port=8440, ssl=False)
    args.update(kw)
    return await tools_npm.npm_proxy_host_create(**args)


async def test_create_with_locations(create_env):
    out = await create(locations=[{**NEW, "advanced_config": "add_header X-Token-Info abc;"}])
    assert out["preview"] is True
    assert out["payload"]["locations"][0]["advanced_config"] == "add_header ***;"
    assert written(create_env) == []

    await create(locations=[NEW], confirm=True)
    body = json.loads(written(create_env)[0].read())
    assert body["locations"] == [{**NEW, "forward_path": "", "advanced_config": ""}]


@pytest.mark.parametrize("loc, match", [
    ({**NEW, "path": "/"}, "nicht erlaubt"),
    ({**NEW, "forward_port": 81}, "NPM-Admin-API"),
    ({**NEW, "forward_host": "127.0.0.1"}, "127.0.0.1"),
    ({**NEW, "advanced_config": "include /etc/passwd;"}, "include"),
])
async def test_create_rejects_bad_locations(create_env, loc, match):
    with pytest.raises(GuardError, match=match):
        await create(locations=[loc], confirm=True)
    assert create_env.calls.call_count == 0


async def test_create_rejects_unpublished_port(create_env):
    with pytest.raises(GuardError, match="keinem"):
        await create(locations=[{**NEW, "forward_port": 8499}], confirm=True)
    assert written(create_env) == []


async def test_create_duplicate_location_paths(create_env):
    with pytest.raises(GuardError, match="mehrfach"):
        await create(locations=[NEW, NEW])
    assert create_env.calls.call_count == 0

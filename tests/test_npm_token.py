"""NPM-Token: Cache, Erneuerung vor Ablauf, einmaliger Re-Login bei 401, 2FA."""

import datetime

import httpx
import pytest
from conftest import NPM_API, NPM_PASSWORD

from infra_mcp.errors import NpmError
from infra_mcp.npm_client import NpmClient


def iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")


class Clock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def client(clock=None):
    return NpmClient(NPM_API, "mcp@example.com", NPM_PASSWORD, clock=clock or Clock())


async def test_login_once_and_cache(mock):
    clock = Clock()
    login = mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "jwt-1", "expires": iso(clock.now + 86400)})
    hosts = mock.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    c = client(clock)
    await c.proxy_hosts()
    await c.proxy_hosts()
    assert login.call_count == 1
    assert hosts.calls[0].request.headers["Authorization"] == "Bearer jwt-1"
    body = login.calls[0].request.read()
    assert b'"identity"' in body and b'"secret"' in body


async def test_refresh_before_expiry(mock):
    clock = Clock()
    login = mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "jwt-1", "expires": iso(clock.now + 86400)})
    refresh = mock.get(f"{NPM_API}/tokens").respond(200, json={"token": "jwt-2", "expires": iso(clock.now + 2 * 86400)})
    hosts = mock.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    c = client(clock)
    await c.proxy_hosts()
    clock.now += 86400 - 600  # 10 Minuten vor Ablauf
    await c.proxy_hosts()
    assert login.call_count == 1
    assert refresh.call_count == 1
    assert refresh.calls[0].request.headers["Authorization"] == "Bearer jwt-1"
    assert hosts.calls[-1].request.headers["Authorization"] == "Bearer jwt-2"


async def test_refresh_failure_falls_back_to_login(mock):
    clock = Clock()
    login = mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "jwt-x", "expires": iso(clock.now + 86400)})
    mock.get(f"{NPM_API}/tokens").respond(401, json={"error": {"message": "expired"}})
    mock.get(f"{NPM_API}/nginx/proxy-hosts").respond(200, json=[])
    c = client(clock)
    await c.proxy_hosts()
    clock.now += 86400 - 60
    await c.proxy_hosts()
    assert login.call_count == 2


async def test_401_relogin_once_and_retry(mock):
    login = mock.post(f"{NPM_API}/tokens").mock(
        side_effect=[
            httpx.Response(200, json={"token": "old", "expires": "2999-01-01T00:00:00Z"}),
            httpx.Response(200, json={"token": "new", "expires": "2999-01-01T00:00:00Z"}),
        ]
    )
    hosts = mock.get(f"{NPM_API}/nginx/proxy-hosts").mock(
        side_effect=[httpx.Response(401, json={"error": {"message": "Token expired"}}), httpx.Response(200, json=[{"id": 1}])]
    )
    c = client()
    assert await c.proxy_hosts() == [{"id": 1}]
    assert login.call_count == 2
    assert hosts.calls[1].request.headers["Authorization"] == "Bearer new"


async def test_401_twice_gives_error_no_endless_loop(mock):
    login = mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"})
    hosts = mock.get(f"{NPM_API}/nginx/proxy-hosts").respond(401, json={"error": {"message": "nope"}})
    with pytest.raises(NpmError, match="401"):
        await client().proxy_hosts()
    assert login.call_count == 2
    assert hosts.call_count == 2


async def test_login_failure_message_without_password(mock):
    mock.post(f"{NPM_API}/tokens").respond(401, json={"error": {"message": f"Invalid password {NPM_PASSWORD}"}})
    with pytest.raises(NpmError) as exc:
        await client().proxy_hosts()
    assert NPM_PASSWORD not in str(exc.value)
    assert "HTTP 401" in str(exc.value)


async def test_2fa_is_reported(mock):
    mock.post(f"{NPM_API}/tokens").respond(200, json={"requires_2fa": True, "challenge_token": "c"})
    with pytest.raises(NpmError, match="2FA"):
        await client().proxy_hosts()


async def test_write_timeout_is_unclear_state(mock):
    from infra_mcp.errors import UnclearStateError

    mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"})
    route = mock.post(f"{NPM_API}/nginx/proxy-hosts").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(UnclearStateError, match="unklar"):
        await client().create_proxy_host({"domain_names": ["app.example.com"], "certificate_id": "new"})
    assert route.call_count == 1  # nicht automatisch wiederholt


async def test_legacy_schema_detection(mock):
    mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"})
    mock.get(f"{NPM_API}/schema").respond(200, json={"x": {"letsencrypt_email": {"type": "string"}}})
    assert await client().legacy_letsencrypt_meta() is True


async def test_schema_detection_not_cached(mock):
    """Nach einem NPM-Update muss die neue Variante ohne Neustart erkannt werden."""
    mock.post(f"{NPM_API}/tokens").respond(200, json={"token": "t", "expires": "2999-01-01T00:00:00Z"})
    mock.get(f"{NPM_API}/schema").mock(
        side_effect=[httpx.Response(200, json={"letsencrypt_email": {}}), httpx.Response(200, json={"dns_challenge": {}})]
    )
    c = client()
    assert await c.legacy_letsencrypt_meta() is True
    assert await c.legacy_letsencrypt_meta() is False

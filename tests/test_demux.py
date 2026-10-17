"""Docker-Log-Demultiplexing (8-Byte-Header) und Log-Tool."""

import json

from conftest import PORTAINER_API

from infra_mcp import tools_portainer
from infra_mcp.portainer_client import demux_docker_stream


def frame(stream: int, payload: bytes) -> bytes:
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


def test_demux_stdout_and_stderr_in_order():
    data = frame(1, b"line one\n") + frame(2, b"error: boom\n") + frame(1, b"line three\n")
    assert demux_docker_stream(data) == "line one\nerror: boom\nline three\n"


def test_demux_large_frame_and_utf8():
    payload = ("Grüsse " * 5000 + "\n").encode()
    assert demux_docker_stream(frame(1, payload)) == payload.decode()


def test_demux_raw_tty_stream_unchanged():
    raw = b"plain tty output\nsecond line\n"
    assert demux_docker_stream(raw) == raw.decode()


def test_demux_truncated_frame_keeps_available_bytes():
    data = frame(1, b"complete\n") + bytes([1, 0, 0, 0, 0, 0, 0, 50]) + b"partial"
    assert demux_docker_stream(data) == "complete\npartial"


def test_demux_empty():
    assert demux_docker_stream(b"") == ""


async def test_logs_tool_demuxes_greps_and_redacts(mock):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/web/json").respond(
        200, json={"Id": "abc123def4567890", "Name": "/web", "Config": {"Tty": False}}
    )
    body = frame(1, b"2026-01-01T00:00:00Z ok\n") + frame(2, b"2026-01-01T00:00:01Z ERROR key ptr_test-portainer-key-value\n")
    route = mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/abc123def4567890/logs").respond(200, content=body)
    out = await tools_portainer.portainer_container_logs(1, "web", tail=50, grep="error")
    assert out["lines"] == 1
    assert "ERROR key ***" in out["logs"]
    assert "ptr_test" not in out["logs"]
    params = route.calls.last.request.url.params
    assert params["tail"] == "50" and params["stdout"] == "1" and params["stderr"] == "1"


async def test_logs_tool_tty_container_not_demuxed(mock):
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/tty/json").respond(
        200, json={"Id": "ttyid", "Name": "/tty", "Config": {"Tty": True}}
    )
    raw = bytes([1, 0, 0, 0]) + b"looks like header but tty"
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/ttyid/logs").respond(200, content=raw)
    out = await tools_portainer.portainer_container_logs(1, "tty")
    assert out["logs"].endswith("looks like header but tty")


async def test_logs_tool_truncates_keeping_newest(mock, monkeypatch):
    monkeypatch.setattr(tools_portainer, "LOG_OUTPUT_MAX_CHARS", 100)
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/web/json").respond(
        200, json={"Id": "wid", "Name": "/web", "Config": {"Tty": False}}
    )
    body = b"".join(frame(1, f"line {i:03d}\n".encode()) for i in range(100))
    mock.get(f"{PORTAINER_API}/endpoints/1/docker/containers/wid/logs").respond(200, content=body)
    out = await tools_portainer.portainer_container_logs(1, "web")
    assert out["truncated"] is True
    assert out["logs"].endswith("line 099")
    assert "line 000" not in out["logs"]


def test_parse_since_relative():
    import time

    ts = tools_portainer.parse_since("2h")
    assert abs(ts - (time.time() - 7200)) < 5
    assert tools_portainer.parse_since("1700000000") == 1700000000
    assert tools_portainer.parse_since("2026-01-01T00:00:00Z") == 1767225600
    assert tools_portainer.parse_since(None) is None


def test_stats_summary():
    from infra_mcp.portainer_client import summarize_stats

    raw = {
        "cpu_stats": {"cpu_usage": {"total_usage": 2_000_000}, "system_cpu_usage": 20_000_000, "online_cpus": 2},
        "precpu_stats": {"cpu_usage": {"total_usage": 1_000_000}, "system_cpu_usage": 10_000_000},
        "memory_stats": {"usage": 200 * 1048576, "limit": 1024 * 1048576, "stats": {"inactive_file": 50 * 1048576}},
        "networks": {"eth0": {"rx_bytes": 100, "tx_bytes": 50}, "eth1": {"rx_bytes": 1, "tx_bytes": 2}},
    }
    s = summarize_stats(raw)
    assert s["cpu_percent"] == 20.0
    assert s["memory_used_mib"] == 150.0
    assert s["memory_percent"] == round(150 / 1024 * 100, 2)
    assert s["network_rx_bytes"] == 101 and s["network_tx_bytes"] == 52
    json.dumps(s)

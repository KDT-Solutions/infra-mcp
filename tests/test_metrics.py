"""Host-Ressourcen (node-exporter) und 24-h-Verlauf."""

import json

import httpx
import pytest

from infra_mcp import config, metrics, tools_workflow
from infra_mcp.errors import InfraError

NE_URL = "http://infra-mcp-node-exporter:9100/metrics"


def exposition(idle0=900.0, user0=100.0, mem_avail=6 * 1073741824):
    return f"""# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{{cpu="0",mode="idle"}} {idle0}
node_cpu_seconds_total{{cpu="0",mode="iowait"}} 0
node_cpu_seconds_total{{cpu="0",mode="user"}} {user0}
node_cpu_seconds_total{{cpu="1",mode="idle"}} {idle0}
node_cpu_seconds_total{{cpu="1",mode="user"}} {user0}
node_memory_MemTotal_bytes 8.589934592e+09
node_memory_MemAvailable_bytes {mem_avail}
node_memory_SwapTotal_bytes 1073741824
node_memory_SwapFree_bytes 536870912
node_load1 0.5
node_load5 0.4
node_load15 0.3
node_boot_time_seconds 1.7e+09
node_time_seconds 1.7000036e+09
node_filesystem_size_bytes{{device="/dev/sda1",fstype="ext4",mountpoint="/"}} 107374182400
node_filesystem_avail_bytes{{device="/dev/sda1",fstype="ext4",mountpoint="/"}} 10737418240
node_filesystem_readonly{{device="/dev/sda1",fstype="ext4",mountpoint="/"}} 0
node_filesystem_size_bytes{{device="/dev/sda1",fstype="ext4",mountpoint="/etc/hostname"}} 107374182400
node_filesystem_avail_bytes{{device="/dev/sda1",fstype="ext4",mountpoint="/etc/hostname"}} 10737418240
node_filesystem_size_bytes{{device="/dev/sdb1",fstype="xfs",mountpoint="/srv"}} 214748364800
node_filesystem_avail_bytes{{device="/dev/sdb1",fstype="xfs",mountpoint="/srv"}} 107374182400
node_filesystem_size_bytes{{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/0"}} 1000
node_filesystem_avail_bytes{{device="tmpfs",fstype="tmpfs",mountpoint="/run/user/0"}} 1000
"""


@pytest.fixture
def ne(monkeypatch):
    monkeypatch.setenv("NODE_EXPORTER_URL", NE_URL)
    config.reset()
    metrics.reset()
    yield
    metrics.reset()


def test_parse_and_compute():
    data = metrics.parse_prometheus(exposition(), metrics._WANTED)
    assert metrics.cpu_count(data) == 2
    busy, total = metrics.cpu_totals(data)
    assert busy == 200.0 and total == 2000.0
    mem = metrics.memory(data)
    assert mem["total_mib"] == 8192 and mem["used_mib"] == 2048 and mem["used_percent"] == 25.0
    assert mem["swap_used_mib"] == 512


def test_disks_filter_and_warning():
    disks = metrics.disks(metrics.parse_prometheus(exposition(), metrics._WANTED))
    assert [d["mountpoint"] for d in disks] == ["/", "/srv"]  # tmpfs und Bind-Mount des gleichen Geräts weg
    root = disks[0]
    assert root["used_percent"] == 90.0 and root["warning"] is True and root["free_gib"] == 10.0
    assert disks[1]["warning"] is False


def test_cpu_percent():
    assert metrics.cpu_percent((100.0, 1000.0), (150.0, 1100.0)) == 50.0
    assert metrics.cpu_percent((100.0, 1000.0), (100.0, 1000.0)) is None


async def test_host_resources_tool(ne, mock, monkeypatch):
    async def no_sleep(_):
        return None

    monkeypatch.setattr(metrics.asyncio, "sleep", no_sleep)
    mock.get(NE_URL).mock(
        side_effect=[
            httpx.Response(200, text=exposition(idle0=900, user0=100)),
            httpx.Response(200, text=exposition(idle0=930, user0=110)),
        ]
    )
    out = await tools_workflow.infra_host_resources()
    # Delta: busy 2*10=20, total 2*40=80 -> 25 %
    assert out["cpu"]["percent"] == 25.0
    assert out["cpu"]["cores"] == 2 and out["cpu"]["load1"] == 0.5
    assert out["memory"]["used_percent"] == 25.0
    assert out["disk_warnings"] == ["/"]
    assert out["uptime_hours"] == 1.0


async def test_host_resources_not_configured():
    with pytest.raises(InfraError, match="NODE_EXPORTER_URL"):
        await tools_workflow.infra_host_resources()


async def test_node_exporter_unreachable(ne, mock):
    mock.get(NE_URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(InfraError, match="nicht erreichbar"):
        await metrics.scrape()


async def test_sample_once_records_after_second_scrape(ne, mock):
    mock.get(NE_URL).mock(
        side_effect=[httpx.Response(200, text=exposition()), httpx.Response(200, text=exposition(idle0=910, user0=110))]
    )
    prev = await metrics.sample_once(None)
    assert len(metrics.history().samples) == 0  # erste Messung nur als Basis für CPU-Delta
    await metrics.sample_once(prev)
    s = metrics.history().samples[-1]
    assert s["cpu_percent"] == 50.0 and s["mem_used_percent"] == 25.0 and s["load1"] == 0.5


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def test_history_retention_persistence_and_summary(tmp_path, ne):
    path = str(tmp_path / "m.jsonl")
    clock = Clock(1_800_000_000.0)
    h = metrics.History(path, clock=clock)
    start = clock.now - 25 * 3600
    for i in range(0, 25 * 60, 1):  # 25 h, jede Minute
        clock.now = start + i * 60
        h.add({"ts": clock.now, "cpu_percent": 10.0 + (i % 60), "mem_used_percent": 40.0, "load1": 0.2})
    assert h.samples[0]["ts"] >= clock.now - 24 * 3600  # älter als 24 h verworfen
    # Neustart: aus Datei laden, nur die letzten 24 h
    h2 = metrics.History(path, clock=clock)
    h2.load()
    assert len(h2.samples) == len(h.samples)
    summary = h2.summary(hours=24, bucket_minutes=60)
    assert summary["persisted"] is True
    assert summary["cpu_percent"]["max"] == 69.0
    assert summary["mem_used_percent"]["avg"] == 40.0
    assert 24 <= len(summary["buckets"]) <= 25
    assert "gaps" not in summary
    with open(path, encoding="utf-8") as f:
        assert all(json.loads(line)["ts"] >= start for line in f)


def test_history_gap_detection(ne):
    clock = Clock(1_800_000_000.0)
    h = metrics.History("", clock=clock)
    for t in (clock.now - 3600, clock.now - 3540, clock.now - 600, clock.now - 540):
        h.add({"ts": t, "cpu_percent": 5.0, "mem_used_percent": 30.0, "load1": 0.1})
    s = h.summary(hours=2)
    assert s["persisted"] is False
    assert len(s["gaps"]) == 1


def test_history_unwritable_file_falls_back_to_memory(tmp_path, ne):
    h = metrics.History(str(tmp_path / "missing-dir" / "m.jsonl"))
    h.add({"ts": h.clock(), "cpu_percent": 1.0, "mem_used_percent": 2.0, "load1": 0.0})
    assert len(h.samples) == 1 and h.summary()["persisted"] is False


def test_history_tool_empty(ne):
    out = tools_workflow.infra_host_history()
    assert out["samples"] == 0 and "note" in out


def test_history_tool_not_configured():
    with pytest.raises(InfraError, match="NODE_EXPORTER_URL"):
        tools_workflow.infra_host_history()

"""Host-Ressourcen über node-exporter (Sidecar im selben Stack) und 24-h-Verlauf.

node-exporter liest /proc und die Dateisysteme des Hosts (read-only gemountet)
und liefert sie als Prometheus-Text unter NODE_EXPORTER_URL. infra-mcp selbst
bekommt weder Host-Mounts noch den Docker-Socket.

Der Sampler fragt alle METRICS_INTERVAL Sekunden CPU und RAM ab und hält die
letzten 24 h im Speicher. Ist METRICS_FILE beschreibbar (Volume), werden die
Werte dort als JSON-Zeilen abgelegt und überstehen einen Neustart.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
import time
from collections import deque
from typing import Any

import httpx

from .config import settings
from .errors import InfraError

logger = logging.getLogger("infra_mcp.metrics")

RETENTION_SECONDS = 24 * 3600
SCRAPE_TIMEOUT = httpx.Timeout(10.0, connect=10.0)
DISK_WARN_PERCENT = 85.0

# Zusätzlich zu den node-exporter-Standardausschlüssen: flüchtige Dateisysteme
_SKIP_FSTYPES = {"tmpfs", "ramfs", "devtmpfs", "overlay", "squashfs", "nsfs", "fuse.lxcfs"}
_SKIP_MOUNT_RE = re.compile(r"^/(run|var/lib/docker|var/lib/containers|snap)(/|$)")

_LINE_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)")
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


class MetricsError(InfraError):
    pass


def parse_prometheus(text: str, wanted: tuple[str, ...]) -> dict[str, list[tuple[dict[str, str], float]]]:
    """Prometheus-Textformat -> {metrik: [(labels, wert), ...]}, nur gewünschte Metriken."""
    out: dict[str, list[tuple[dict[str, str], float]]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m or m.group(1) not in wanted:
            continue
        try:
            value = float(m.group(4))
        except ValueError:
            continue
        labels = dict(_LABEL_RE.findall(m.group(3) or ""))
        out.setdefault(m.group(1), []).append((labels, value))
    return out


_WANTED = (
    "node_cpu_seconds_total",
    "node_memory_MemTotal_bytes",
    "node_memory_MemAvailable_bytes",
    "node_memory_SwapTotal_bytes",
    "node_memory_SwapFree_bytes",
    "node_load1",
    "node_load5",
    "node_load15",
    "node_filesystem_size_bytes",
    "node_filesystem_avail_bytes",
    "node_filesystem_readonly",
    "node_boot_time_seconds",
    "node_time_seconds",
)


def _single(data: dict, name: str) -> float | None:
    vals = data.get(name) or []
    return vals[0][1] if vals else None


def cpu_totals(data: dict) -> tuple[float, float]:
    """(busy, total) Sekunden über alle CPUs; busy = alles ausser idle und iowait."""
    total = idle = 0.0
    for labels, value in data.get("node_cpu_seconds_total") or []:
        total += value
        if labels.get("mode") in ("idle", "iowait"):
            idle += value
    return total - idle, total


def cpu_percent(prev: tuple[float, float], cur: tuple[float, float]) -> float | None:
    d_busy, d_total = cur[0] - prev[0], cur[1] - prev[1]
    if d_total <= 0:
        return None
    return round(max(0.0, min(100.0, d_busy / d_total * 100.0)), 1)


def cpu_count(data: dict) -> int:
    return len({labels.get("cpu") for labels, _ in data.get("node_cpu_seconds_total") or []})


def memory(data: dict) -> dict[str, Any]:
    total = _single(data, "node_memory_MemTotal_bytes") or 0
    avail = _single(data, "node_memory_MemAvailable_bytes") or 0
    used = max(total - avail, 0)
    swap_total = _single(data, "node_memory_SwapTotal_bytes") or 0
    swap_used = max(swap_total - (_single(data, "node_memory_SwapFree_bytes") or 0), 0)
    return {
        "total_mib": round(total / 1048576),
        "used_mib": round(used / 1048576),
        "available_mib": round(avail / 1048576),
        "used_percent": round(used / total * 100, 1) if total else None,
        "swap_total_mib": round(swap_total / 1048576),
        "swap_used_mib": round(swap_used / 1048576),
    }


def disks(data: dict) -> list[dict[str, Any]]:
    sizes = {(lb.get("device"), lb.get("mountpoint"), lb.get("fstype")): v for lb, v in data.get("node_filesystem_size_bytes") or []}
    avails = {(lb.get("device"), lb.get("mountpoint"), lb.get("fstype")): v for lb, v in data.get("node_filesystem_avail_bytes") or []}
    ro = {(lb.get("device"), lb.get("mountpoint"), lb.get("fstype")): v for lb, v in data.get("node_filesystem_readonly") or []}
    out: list[dict[str, Any]] = []
    seen_devices: set[str] = set()
    for key in sorted(sizes, key=lambda k: len(k[1] or "")):
        device, mount, fstype = key
        size = sizes[key]
        if not size or fstype in _SKIP_FSTYPES or _SKIP_MOUNT_RE.match(mount or ""):
            continue
        if device in seen_devices:  # gleiches Gerät mehrfach gemountet (Bind-Mounts)
            continue
        seen_devices.add(device)
        avail = avails.get(key, 0)
        # Belegt wie df: Grösse minus für Benutzer verfügbar
        used_pct = round((size - avail) / size * 100, 1)
        out.append(
            {
                "mountpoint": mount,
                "device": device,
                "fstype": fstype,
                "size_gib": round(size / 1073741824, 1),
                "free_gib": round(avail / 1073741824, 1),
                "used_percent": used_pct,
                "warning": used_pct >= DISK_WARN_PERCENT,
                "readonly": bool(ro.get(key)),
            }
        )
    return out


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat(timespec="seconds")


async def scrape(client: httpx.AsyncClient | None = None) -> dict:
    url = settings().node_exporter_url
    if not url:
        raise MetricsError("NODE_EXPORTER_URL ist nicht gesetzt (node-exporter-Sidecar im Stack, siehe README).")
    try:
        if client is None:
            async with httpx.AsyncClient(timeout=SCRAPE_TIMEOUT) as c:
                resp = await c.get(url)
        else:
            resp = await client.get(url, timeout=SCRAPE_TIMEOUT)
    except httpx.HTTPError as exc:
        raise MetricsError(f"node-exporter nicht erreichbar ({type(exc).__name__}).") from None
    if resp.status_code != 200:
        raise MetricsError(f"node-exporter: HTTP {resp.status_code}.")
    return parse_prometheus(resp.text, _WANTED)


async def current_resources(sample_seconds: float = 1.0) -> dict[str, Any]:
    """Aktueller Stand: CPU-% (über sample_seconds gemessen), Load, RAM, Swap, Dateisysteme."""
    first = await scrape()
    await asyncio.sleep(sample_seconds)
    data = await scrape()
    boot, now = _single(data, "node_boot_time_seconds"), _single(data, "node_time_seconds")
    fs = disks(data)
    return {
        "cpu": {
            "percent": cpu_percent(cpu_totals(first), cpu_totals(data)),
            "cores": cpu_count(data),
            "load1": _single(data, "node_load1"),
            "load5": _single(data, "node_load5"),
            "load15": _single(data, "node_load15"),
        },
        "memory": memory(data),
        "disks": fs,
        "disk_warnings": [d["mountpoint"] for d in fs if d["warning"]],
        "uptime_hours": round((now - boot) / 3600, 1) if boot and now else None,
    }


# ---------------------------------------------------------------------------
# 24-h-Verlauf
# ---------------------------------------------------------------------------


class History:
    def __init__(self, path: str = "", retention: float = RETENTION_SECONDS, clock=time.time):
        self.path = path
        self.retention = retention
        self.clock = clock
        self.samples: deque[dict[str, Any]] = deque()
        self._persist = bool(path)
        self._appended = 0

    def load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        cutoff = self.clock() - self.retention
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    try:
                        s = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(s, dict) and isinstance(s.get("ts"), (int, float)) and s["ts"] >= cutoff:
                        self.samples.append(s)
        except OSError as exc:
            logger.warning("Metrik-Verlauf nicht lesbar (%s), starte leer.", type(exc).__name__)

    def add(self, sample: dict[str, Any]) -> None:
        self.samples.append(sample)
        cutoff = self.clock() - self.retention
        while self.samples and self.samples[0]["ts"] < cutoff:
            self.samples.popleft()
        if not self._persist:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sample) + "\n")
            self._appended += 1
            # Datei regelmässig auf 24 h kürzen
            if self._appended >= 360:
                self._rewrite()
        except OSError as exc:
            self._persist = False
            logger.warning("Metrik-Verlauf nicht schreibbar (%s), nur im Speicher.", type(exc).__name__)

    def _rewrite(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for s in self.samples:
                f.write(json.dumps(s) + "\n")
        os.replace(tmp, self.path)
        self._appended = 0

    def summary(self, hours: float = 24, bucket_minutes: int = 60) -> dict[str, Any]:
        now = self.clock()
        start = now - hours * 3600
        rows = [s for s in self.samples if s["ts"] >= start]
        out: dict[str, Any] = {
            "hours": hours,
            "samples": len(rows),
            "persisted": self._persist,
        }
        if not rows:
            out["note"] = "Noch keine Messwerte im Zeitraum."
            return out
        out["from"] = _iso(rows[0]["ts"])
        out["to"] = _iso(rows[-1]["ts"])
        for key in ("cpu_percent", "mem_used_percent", "load1"):
            vals = [(s[key], s["ts"]) for s in rows if s.get(key) is not None]
            if vals:
                peak = max(vals)
                out[key] = {
                    "avg": round(sum(v for v, _ in vals) / len(vals), 1),
                    "max": peak[0],
                    "max_at": _iso(peak[1]),
                    "last": vals[-1][0],
                }
        width = max(1, int(bucket_minutes)) * 60
        buckets: dict[int, list[dict[str, Any]]] = {}
        for s in rows:
            buckets.setdefault(int(s["ts"] // width) * width, []).append(s)
        series = []
        for b in sorted(buckets):
            group = buckets[b]
            entry: dict[str, Any] = {"from": _iso(b), "samples": len(group)}
            for key in ("cpu_percent", "mem_used_percent"):
                vals = [s[key] for s in group if s.get(key) is not None]
                if vals:
                    entry[key.replace("_percent", "") + "_avg"] = round(sum(vals) / len(vals), 1)
                    entry[key.replace("_percent", "") + "_max"] = max(vals)
            series.append(entry)
        out["buckets"] = series
        # Lücken > 3 Intervalle (z.B. Neustart, node-exporter nicht erreichbar)
        interval = settings().metrics_interval
        gaps = [
            {"from": _iso(a["ts"]), "to": _iso(b["ts"])}
            for a, b in zip(rows, rows[1:])
            if b["ts"] - a["ts"] > 3 * interval
        ]
        if gaps:
            out["gaps"] = gaps
        return out


_history: History | None = None


def history() -> History:
    global _history
    if _history is None:
        _history = History(settings().metrics_file)
        _history.load()
    return _history


def reset() -> None:
    """Nur für Tests."""
    global _history
    _history = None


async def sample_once(prev: tuple[float, float] | None, client: httpx.AsyncClient | None = None) -> tuple[float, float]:
    data = await scrape(client)
    cur = cpu_totals(data)
    mem = memory(data)
    sample = {
        "ts": round(time.time(), 1),
        "cpu_percent": cpu_percent(prev, cur) if prev else None,
        "mem_used_percent": mem["used_percent"],
        "mem_used_mib": mem["used_mib"],
        "load1": _single(data, "node_load1"),
    }
    if prev is not None:
        history().add(sample)
    return cur


async def sampler_loop() -> None:
    """Läuft im Hintergrund, solange der Server läuft. Fehler werden geloggt, nicht abgebrochen."""
    interval = settings().metrics_interval
    prev: tuple[float, float] | None = None
    warned = False
    async with httpx.AsyncClient(timeout=SCRAPE_TIMEOUT) as client:
        while True:
            try:
                prev = await sample_once(prev, client)
                warned = False
            except MetricsError as exc:
                prev = None
                if not warned:
                    logger.warning("Metrik-Abfrage fehlgeschlagen: %s", exc)
                    warned = True
            except Exception:  # noqa: BLE001 - Sampler darf den Server nie beenden
                logger.exception("Unerwarteter Fehler im Metrik-Sampler")
            await asyncio.sleep(interval)

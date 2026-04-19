"""
Elasticsearch sink — bulk-indexes agent-shipped attack events into the
T-Pot logstash-* index so the existing attack map picks them up unchanged.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import httpx

from schemas import AttackEvent

log = logging.getLogger("honeypot-mgmt.es")

ES_URL = "http://127.0.0.1:64298"
GEOIP_DB_CANDIDATES = [
    Path("/data/elk/logstash/GeoLite2-City.mmdb"),
    Path("/data/geoip/GeoLite2-City.mmdb"),
]

_geoip_reader = None


def _load_geoip():
    global _geoip_reader
    if _geoip_reader is not None:
        return _geoip_reader
    try:
        import geoip2.database  # type: ignore
    except ImportError:
        log.warning("geoip2 not installed; events will lack geo data")
        return None
    for p in GEOIP_DB_CANDIDATES:
        if p.exists():
            _geoip_reader = geoip2.database.Reader(str(p))
            log.info("GeoIP DB loaded from %s", p)
            return _geoip_reader
    log.warning("No GeoLite2-City.mmdb found in %s", GEOIP_DB_CANDIDATES)
    return None


def _enrich_geoip(doc: dict, src_ip: str) -> None:
    reader = _load_geoip()
    if reader is None or not src_ip:
        return
    try:
        r = reader.city(src_ip)
        doc["geoip"] = {
            "ip": src_ip,
            "country_name": r.country.name,
            "country_code2": r.country.iso_code,
            "city_name": r.city.name,
            "location": {
                "lat": r.location.latitude,
                "lon": r.location.longitude,
            } if r.location.latitude is not None else None,
        }
    except Exception:
        # Private/unknown IPs raise AddressNotFoundError — quietly skip.
        pass


def _to_logstash_doc(ev: AttackEvent, node_label: str) -> dict:
    doc = {
        "@timestamp": ev.ts,
        "type": ev.honeypot,                # e.g. "beelzebub" — recognised by map_data
        "src_ip": ev.src_ip,
        "src_port": ev.src_port,
        "dest_port": ev.dst_port,
        "protocol": ev.protocol,
        "username": ev.username,
        "password": ev.password,
        "input": ev.command,
        "message": ev.raw,
        "t-pot_hostname": node_label,
        "t-pot_source": "remote-agent",
    }
    _enrich_geoip(doc, ev.src_ip)
    return doc


def _index_for(ts: str) -> str:
    # logstash daily index pattern.
    try:
        day = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        day = datetime.now(timezone.utc)
    return day.strftime("logstash-%Y.%m.%d")


async def index_events(
    events: Iterable[AttackEvent],
    node_label: str,
    client: httpx.AsyncClient,
) -> tuple[int, int]:
    """Bulk-index events. Returns (indexed, failed)."""
    lines: list[str] = []
    for ev in events:
        lines.append(json.dumps({"index": {"_index": _index_for(ev.ts)}}))
        lines.append(json.dumps(_to_logstash_doc(ev, node_label)))
    if not lines:
        return 0, 0
    body = "\n".join(lines) + "\n"
    try:
        r = await client.post(
            f"{ES_URL}/_bulk",
            content=body,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        log.error("ES bulk request failed: %s", exc)
        return 0, len(lines) // 2
    if r.status_code >= 300:
        log.error("ES bulk %d: %s", r.status_code, r.text[:200])
        return 0, len(lines) // 2
    data = r.json()
    items = data.get("items", [])
    failed = sum(1 for it in items if next(iter(it.values())).get("status", 500) >= 300)
    return len(items) - failed, failed

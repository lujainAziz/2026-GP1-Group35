#!/usr/bin/env python3
"""Read-only FastAPI backend exposing the ASSAS device inventory.

Reads the same SQLite `devices` table that discovery.py writes, opening the
connection in mode=ro so this process can never write to it. discovery.py
runs in WAL journal mode, so concurrent reads while it writes are safe.
"""
import os
import sqlite3
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.getenv("ASSAS_DB_PATH", "/home/assas/assas/assas.db")

# Above this many seconds without a daemon write, /healthz flags the daemon stale.
HEARTBEAT_STALE_SECONDS = int(os.getenv("ASSAS_HEARTBEAT_STALE_SECONDS", "120"))

# Matches http/https on localhost or 127.0.0.1 at any port (e.g. the port the
# Flutter Web dev server picks). Anchored so lookalikes like
# "http://localhost.evil.com" do not match.
DEV_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"

app = FastAPI(title="ASSAS Device Inventory API", version="1.0")

# CORS for local Flutter Web development only. The API serves no cookies, so
# credentials stay disabled; a matched origin is echoed back (never "*").
# Authorization is allowed now so a future Bearer scheme works without a
# second preflight round-trip.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=DEV_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_connection():
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        yield conn
    finally:
        conn.close()


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if ":" not in mac and "-" not in mac and len(mac) == 12:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac.replace("-", ":")


def _is_locally_administered_mac(mac) -> bool:
    """True if the MAC's locally-administered bit (randomized MAC) is set.

    Kept as a local one-liner so this read-only API stays import-free of
    discovery.py; mirrors discovery.is_locally_administered_mac().
    """
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def _effective_vendor_source(mac, vendor, vendor_source):
    """Treat any vendor on a randomized MAC as inferred, not OUI-derived.

    An OUI never yields a vendor for a locally-administered MAC, so a
    non-null vendor there is inference/self-report -- including legacy rows
    stored before vendor_source existed (vendor_source IS NULL). Surfacing
    it as "inferred: ..." lets consumers (which key off
    vendor_source.startswith("inferred")) avoid presenting a guess as fact.
    The stored DB value is untouched.
    """
    if vendor_source:
        return vendor_source
    if vendor and _is_locally_administered_mac(mac):
        return "inferred: private MAC"
    return vendor_source


class DeviceSummary(BaseModel):
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    vendor: Optional[str] = None
    vendor_source: Optional[str] = None
    status: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class Classification(BaseModel):
    # Explains why a device got its type/vendor. Every field is a stored
    # "needle" (a short reason or matched token), never a full query name or
    # per-flow data.
    device_type: Optional[str] = None
    class_source: Optional[str] = None
    class_score: Optional[int] = None
    model: Optional[str] = None
    model_source: Optional[str] = None
    model_score: Optional[int] = None
    vendor: Optional[str] = None
    vendor_source: Optional[str] = None


class DeviceDetail(DeviceSummary):
    dhcp_signature: Optional[str] = None
    vendor_class: Optional[str] = None
    upnp_location: Optional[str] = None
    is_ap_client: bool = False
    ap_associated: bool = False
    last_ap_seen: Optional[str] = None
    membership_source: Optional[str] = None
    discovered_current: bool = False
    last_discovery_seen: Optional[str] = None
    traffic_seen: bool = False
    session_seen: bool = False
    last_traffic_seen: Optional[str] = None
    class_source: Optional[str] = None
    # Grouped explanation of the classification (same needles, one place).
    classification: Optional[Classification] = None


class StatusCount(BaseModel):
    status: Optional[str]
    count: int


class DeviceTypeCount(BaseModel):
    device_type: str
    count: int


class SummaryStats(BaseModel):
    total_known: int
    current_subnet: int
    traffic_runtime: int
    traffic_inventory: int
    traffic_only_hidden: int
    ap_current: int
    historical: int
    by_status: list[StatusCount]
    by_device_type: list[DeviceTypeCount]


SUMMARY_COLUMNS = (
    "mac, ip, hostname, device_type, model, vendor, vendor_source, "
    "status, first_seen, last_seen"
)

DETAIL_COLUMNS = SUMMARY_COLUMNS + (
    ", class_score, model_source, model_score, "
    "dhcp_signature, vendor_class, upnp_location, "
    "COALESCE(is_ap_client,0) AS is_ap_client, "
    "COALESCE(ap_associated,0) AS ap_associated, "
    "last_ap_seen, membership_source, "
    "COALESCE(discovered_current,0) AS discovered_current, "
    "last_discovery_seen, "
    "COALESCE(traffic_seen,0) AS traffic_seen, "
    "COALESCE(session_seen,0) AS session_seen, "
    "last_traffic_seen, class_source"
)


def row_to_summary(row) -> DeviceSummary:
    data = {k: row[k] for k in DeviceSummary.model_fields}
    data["vendor_source"] = _effective_vendor_source(
        data.get("mac"), data.get("vendor"), data.get("vendor_source")
    )
    return DeviceSummary(**data)


def row_to_detail(row) -> DeviceDetail:
    data = dict(row)
    for flag in (
        "is_ap_client", "ap_associated", "discovered_current",
        "traffic_seen", "session_seen",
    ):
        data[flag] = bool(data[flag])
    data["vendor_source"] = _effective_vendor_source(
        data.get("mac"), data.get("vendor"), data.get("vendor_source")
    )
    # Same needles, grouped so the app can explain the classification.
    data["classification"] = Classification(
        device_type=data.get("device_type"),
        class_source=data.get("class_source"),
        class_score=data.get("class_score"),
        model=data.get("model"),
        model_source=data.get("model_source"),
        model_score=data.get("model_score"),
        vendor=data.get("vendor"),
        vendor_source=data.get("vendor_source"),
    )
    return DeviceDetail(**data)


@app.get("/healthz")
def healthz(conn: sqlite3.Connection = Depends(get_connection)):
    # last_write = newest timestamp the daemon has written. Lets the app tell
    # "API up but daemon stopped" (old last_write) from live data. All
    # timestamps are server-local naive ISO-8601; staleness uses the same clock.
    row = conn.execute(
        "SELECT MAX(last_seen) AS ls, MAX(last_discovery_seen) AS lds, "
        "MAX(last_traffic_seen) AS lts FROM devices"
    ).fetchone()
    last_write = max([t for t in (row["ls"], row["lds"], row["lts"]) if t], default=None)

    seconds_since_write = None
    if last_write:
        try:
            seconds_since_write = int(
                (datetime.now() - datetime.fromisoformat(last_write)).total_seconds()
            )
        except ValueError:
            last_write = None

    daemon_stale = (
        seconds_since_write is None or seconds_since_write > HEARTBEAT_STALE_SECONDS
    )
    return {
        "status": "ok",
        "db_available": True,
        "last_write": last_write,
        "seconds_since_write": seconds_since_write,
        "daemon_stale": daemon_stale,
    }


@app.get("/devices", response_model=list[DeviceSummary])
def list_devices(
    conn: sqlite3.Connection = Depends(get_connection),
    status: Optional[str] = None,
    device_type: Optional[str] = None,
    online_only: bool = False,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    clauses = []
    params: list = []

    if online_only:
        # Filter on the status column so the API can never disagree with the
        # 'status' each device reports. 'online' is written by the daemon
        # exactly when discovered_current=1 OR ap_associated=1.
        clauses.append("status = 'online'")
    if status:
        clauses.append("status = ?")
        params.append(status)
    if device_type:
        clauses.append("device_type = ?")
        params.append(device_type)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])

    rows = conn.execute(
        f"SELECT {SUMMARY_COLUMNS} FROM devices {where} "
        "ORDER BY mac LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return [row_to_summary(r) for r in rows]


@app.get("/devices/{mac}", response_model=DeviceDetail)
def get_device(mac: str, conn: sqlite3.Connection = Depends(get_connection)):
    mac = normalize_mac(mac)
    row = conn.execute(
        f"SELECT {DETAIL_COLUMNS} FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No device with mac {mac}")
    return row_to_detail(row)


@app.get("/summary", response_model=SummaryStats)
def summary(conn: sqlite3.Connection = Depends(get_connection)):
    def count(where: str, params: tuple = ()) -> int:
        return conn.execute(f"SELECT COUNT(*) FROM devices WHERE {where}", params).fetchone()[0]

    total_known = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    current_subnet = count("COALESCE(discovered_current,0)=1")
    traffic_runtime = count("COALESCE(session_seen,0)=1")
    traffic_inventory = count(
        "COALESCE(session_seen,0)=1 AND "
        "(COALESCE(discovered_current,0)=1 OR COALESCE(ap_associated,0)=1)"
    )
    traffic_only_hidden = count(
        "COALESCE(session_seen,0)=1 AND "
        "COALESCE(discovered_current,0)=0 AND COALESCE(ap_associated,0)=0"
    )
    ap_current = count("COALESCE(ap_associated,0)=1")
    historical = count(
        "COALESCE(discovered_current,0)=0 AND COALESCE(ap_associated,0)=0"
    )

    by_status = [
        StatusCount(status=row["status"], count=row["n"])
        for row in conn.execute(
            "SELECT status, COUNT(*) AS n FROM devices GROUP BY status"
        ).fetchall()
    ]
    by_device_type = [
        DeviceTypeCount(device_type=row["dtype"], count=row["n"])
        for row in conn.execute(
            "SELECT COALESCE(device_type, 'Generic / Unknown') AS dtype, COUNT(*) AS n "
            "FROM devices GROUP BY dtype"
        ).fetchall()
    ]

    return SummaryStats(
        total_known=total_known,
        current_subnet=current_subnet,
        traffic_runtime=traffic_runtime,
        traffic_inventory=traffic_inventory,
        traffic_only_hidden=traffic_only_hidden,
        ap_current=ap_current,
        historical=historical,
        by_status=by_status,
        by_device_type=by_device_type,
    )

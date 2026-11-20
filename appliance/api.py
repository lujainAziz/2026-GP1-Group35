#!/usr/bin/env python3
"""FastAPI backend exposing the ASSAS device inventory and Threat Alerts.

Reads the same SQLite database that discovery.py and the alert ingester
(alerts.py) write. Ordinary reads use a mode=ro connection; the few writes
(pairing sessions, device trust and name, settings, an alert's state) go through
_open_writable(). The daemons run in WAL journal mode, so concurrent reads while
they write are safe.
"""
import os
import hashlib
import ipaddress
import re
import secrets
import threading
import sqlite3
import uuid
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, StrictBool, field_validator, model_validator

import model_db
from alert_text import alert_text

DB_PATH = os.getenv("ASSAS_DB_PATH", "/home/assas/assas/assas.db")

# Above this many seconds without a daemon write, /healthz flags the daemon stale.
HEARTBEAT_STALE_SECONDS = int(os.getenv("ASSAS_HEARTBEAT_STALE_SECONDS", "120"))

# A device counts as monitored only if unicast traffic from it was seen on the
# mirrored port within this many seconds (same default as the presence window).
MONITORED_WINDOW_SECONDS = int(os.getenv("ASSAS_MONITORED_WINDOW_SECONDS", "120"))

# Matches http/https on localhost or 127.0.0.1 at any port (e.g. the port the
# Flutter Web dev server picks). Anchored so lookalikes like
# "http://localhost.evil.com" do not match.
DEV_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"

def _open_writable() -> sqlite3.Connection:
    """Open the devices DB read-write WITHOUT creating it (mode=rw, not rwc).

    This is the only writable door into the DB. It is used for (1) the additive
    schema guards below (run at startup) and (2) explicit user actions: pairing
    and unpairing, device trust and name, settings, and an alert's state
    (PATCH /alerts/{alert_id}). Ordinary API reads keep using the mode=ro
    connection in get_connection().
    Raises sqlite3.OperationalError if the DB file does not exist yet.
    """
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=rw", uri=True, timeout=5.0)
    # Discovery is a concurrent WAL writer; wait rather than fail on its lock.
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def ensure_trusted_column() -> None:
    """Deployment safety: guarantee devices.trusted exists before any endpoint
    reads it, without waiting for discovery.py to be restarted.

    The API may boot against a DB written by an older discovery.py that predates
    the `trusted` column, whose canonical migration (discovery.init_db) has not
    run yet. Without this, GET /devices would fail with "no such column". This
    mirrors ONLY the single `trusted` column -- all other schema evolution stays
    owned by discovery.py's migration set; we deliberately do not duplicate it.
    Idempotent and a no-op if the DB or devices table does not exist yet.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError:
        return  # DB not created yet; discovery.init_db() will build it fresh.
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        # Empty cols => devices table absent; nothing to migrate (discovery owns
        # table creation). Only add the column when the table exists without it.
        if cols and "trusted" not in cols:
            conn.execute(
                "ALTER TABLE devices ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0"
            )
            conn.commit()
    finally:
        conn.close()


def ensure_user_name_column() -> None:
    """Deployment safety: guarantee devices.user_name exists before any endpoint
    reads it, without waiting for discovery.py to be restarted.

    The API owns this column (set via PUT /devices/{mac}/name); discovery.py does
    not know about it and never writes it, exactly like `trusted`. Mirrors ONLY
    this single column; all other schema evolution stays owned by discovery.py.
    Idempotent and a no-op if the DB or devices table does not exist yet.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError:
        return  # DB not created yet; discovery.init_db() will build it fresh.
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        # Empty cols => devices table absent; nothing to migrate (discovery owns
        # table creation). Only add the column when the table exists without it.
        if cols and "user_name" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN user_name TEXT")
            conn.commit()
    finally:
        conn.close()


# Per-family IP columns owned by discovery.py (see its migrations dict). Unlike
# `trusted`/`user_name`, these are NOT API-owned; this guard only mirrors their
# shape so a SELECT cannot fail with "no such column" when the API boots against
# a DB written by an older discovery.py that has not been restarted yet. Values
# are always written by discovery; the API only reads them.
_IP_FAMILY_COLUMNS = ("last_ipv4", "last_ipv6_global", "last_ipv6_ll")


def ensure_ip_columns() -> None:
    """Deployment safety: guarantee the per-family IP columns exist before any
    endpoint SELECTs them, without waiting for discovery.py to be restarted.

    Idempotent and a no-op if the DB or devices table does not exist yet. Adds
    only the columns that are missing, each as plain TEXT (matching discovery's
    migration), so an already-migrated DB is left untouched.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError:
        return  # DB not created yet; discovery.init_db() will build it fresh.
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        if not cols:
            return  # devices table absent; discovery owns table creation.
        for column in _IP_FAMILY_COLUMNS:
            if column not in cols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} TEXT")
        for mac, ip in conn.execute("SELECT mac, ip FROM devices WHERE ip IS NOT NULL").fetchall():
            family = _classify_ip(ip)
            column = {'ipv4': 'last_ipv4', 'ipv6_global': 'last_ipv6_global', 'ipv6_ll': 'last_ipv6_ll'}.get(family)
            if column:
                conn.execute(f"UPDATE devices SET {column}=COALESCE({column}, ?) WHERE mac=?", (ip, mac))
        conn.commit()
    finally:
        conn.close()


def ensure_last_monitored_seen_column() -> None:
    """Deployment safety: guarantee devices.last_monitored_seen exists before any
    endpoint SELECTs it, without waiting for discovery.py to be restarted.

    Discovery owns and writes this column; this guard only mirrors its shape
    (plain TEXT). Idempotent and a no-op if the DB or devices table is absent.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError:
        return  # DB not created yet; discovery.init_db() will build it fresh.
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
        if cols and "last_monitored_seen" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN last_monitored_seen TEXT")
            conn.commit()
    finally:
        conn.close()


# Kept textually identical to discovery.init_db()'s app_settings DDL so the two
# processes never create diverging schemas for the same table.
_APP_SETTINGS_DDL = (
    "CREATE TABLE IF NOT EXISTS app_settings ("
    " id INTEGER PRIMARY KEY CHECK (id = 1),"
    " active_probes INTEGER NOT NULL DEFAULT 0"
    ")"
)


def ensure_settings_table() -> None:
    """Deployment safety: guarantee app_settings exists so GET/PUT /settings work
    even if the API starts before discovery.py has (re)started to run its
    canonical init_db migration.

    Mirrors ONLY the table shape, and deliberately does NOT seed a row: the
    initial value is env-seeded by discovery.init_db, and a GET before any seed
    reads the default (false). This keeps a single authoritative config source.
    Idempotent and a no-op if the DB file does not exist yet.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError:
        return  # DB not created yet; discovery.init_db() will build it fresh.
    try:
        conn.execute(_APP_SETTINGS_DDL)
        conn.commit()
    finally:
        conn.close()


@asynccontextmanager
async def lifespan(_app: "FastAPI"):
    # Runs once on startup (uvicorn drives the ASGI lifespan protocol) before any
    # request is served, so the trusted column and settings table are present.
    ensure_trusted_column()
    ensure_user_name_column()
    ensure_ip_columns()
    ensure_last_monitored_seen_column()
    ensure_settings_table()
    yield



def require_auth(request: Request) -> None:
    """Gate for every endpoint (PBI-08); the pairing section is further down.

    Defined here because FastAPI needs it when the app is created. Lets through
    the appliance itself (localhost, e.g. the 7-inch display), the public
    endpoints, and phones that send a valid paired token.
    """
    if request.url.path in PUBLIC_PATHS or _is_local_request(request):
        return
    token = _bearer_token(request)
    if token is None or not _session_exists(token):
        raise HTTPException(
            status_code=401,
            detail="Pairing required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


app = FastAPI(
    title="ASSAS Device Inventory API",
    version="1.0",
    lifespan=lifespan,
    dependencies=[Depends(require_auth)],
    description=(
        "**Authentication (PBI-08).** Phones on the LAN must pair first: read "
        "the code on the Assas screen, send it to `POST /pair`, then send the "
        "returned token as `Authorization: Bearer <token>` on every request. "
        "The Assas device itself (the 7-inch display) and `/healthz`, `/pair` "
        "and `/pairing/code` need no token. Any other request without a valid "
        "token gets **401**."
    ),
)




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
                # FastAPI may open, use and close this connection on different
        # worker threads within one request (never at the same time), so the
        # same-thread check must be off or concurrent requests fail with 500.
        conn = sqlite3.connect(
            f"file:{DB_PATH}?mode=ro", uri=True, timeout=5.0, check_same_thread=False
        )
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


def appliance_identity(source=None):
    """Persistent public identifier; never a session credential."""
    path = source.execute("PRAGMA database_list").fetchone()[2] if source is not None else DB_PATH
    conn = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=5)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS appliance_identity (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)")
        conn.execute("INSERT OR IGNORE INTO appliance_identity VALUES (1, ?)", (str(uuid.uuid4()),))
        conn.commit()
        return conn.execute("SELECT value FROM appliance_identity WHERE id=1").fetchone()[0]
    finally:
        conn.close()


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if ":" not in mac and "-" not in mac and len(mac) == 12:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac.replace("-", ":")


def _is_locally_administered_mac(mac) -> bool:
    """True if the MAC's locally-administered bit (randomized MAC) is set.

    Kept as a local one-liner so this API stays import-free of
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
    # User-facing presence includes fresh online/observed records; stale,
    # candidate and offline records are shown as offline.
    # (matches the Flutter client contract). status itself is left unchanged.
    presence: str = "offline"
    # Recent SPAN coverage: unicast traffic seen on the mirrored port within
    # MONITORED_WINDOW_SECONDS (derived from last_monitored_seen).
    monitored: bool = False
    # User recognition state, independent of classification/monitoring. Stored
    # as 0/1; surfaced here as a real JSON boolean. Old rows default to false.
    trusted: bool = False
    # User-chosen display label. API-owned: set via PUT /devices/{mac}/name,
    # never written by discovery. Null when unset.
    user_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class TrustState(BaseModel):
    mac: str
    trusted: bool


class TrustUpdate(BaseModel):
    # StrictBool so only JSON true/false is accepted: a missing, non-boolean,
    # or coercible value (1, 0, "true") yields 422 before any DB access, so a
    # malformed body can never change stored state.
    trusted: StrictBool


class NameState(BaseModel):
    mac: str
    user_name: Optional[str] = None


MAX_USER_NAME_LENGTH = 40


class NameUpdate(BaseModel):
    # The user-chosen label. The field must be present (missing -> 422, like
    # TrustUpdate) so a malformed body can never silently clear a name; an
    # explicit null, or a value empty after trimming, clears it. The 40-char cap
    # is measured on the trimmed value (<=40 ok, >40 -> 422) before any DB write.
    name: Optional[str]

    @field_validator("name")
    @classmethod
    def _trim_and_limit(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if len(v) > MAX_USER_NAME_LENGTH:
            raise ValueError(f"name must be at most {MAX_USER_NAME_LENGTH} characters")
        return v


class SettingsState(BaseModel):
    # The single user-facing appliance setting (matches the Flutter contract
    # {"active_probes": bool}): the master switch for the active identification
    # probes (unicast mDNS, NBNS name query, limited nmap). Off disables only
    # those optional probes; network monitoring and basic device discovery
    # (ARP, inventory) continue, and SSDP/UPnP M-SEARCH is out of scope.
    active_probes: bool


class SettingsUpdate(BaseModel):
    # StrictBool, same rationale as TrustUpdate: missing / 1 / "true" -> 422.
    active_probes: StrictBool


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
    # Known IPv6 addresses for this device (global first, link-local fe80:: last),
    # or null when none are known. The `ip` field already prefers IPv4, then a
    # global IPv6, then a link-local address; this exposes the IPv6 forms without
    # changing device identity (MAC).
    ipv6: Optional[list[str]] = None
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


class AlertOut(BaseModel):
    """Threat Alert as the mobile app's SecurityAlert contract expects it.

    String casing is locked to what SecurityAlert.fromApi matches: kind
    "threat", state "new" or "resolved", severity one of high/medium/low (all
    lowercase). The anomaly fields are null this sprint.
    """
    id: str
    kind: str = "threat"
    title: str  # the original Suricata rule name (unchanged)
    device_mac: Optional[str] = None
    device_name: str
    time: Optional[str] = None  # = last_event_time (app orders/display by this)
    severity: str
    state: str
    # Sprint 2 additive fields (Part D reads these).
    first_event_time: Optional[str] = None
    last_event_time: Optional[str] = None
    occurrence_count: int = 1
    rule_id: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    # Plain-language text per classtype (alert_text.py; fallback when unknown).
    display_title: Optional[str] = None
    explanation: Optional[str] = None
    classtype: Optional[str] = None
    category: Optional[str] = None
    # "source" (device started the activity) / "target" / null (no line).
    device_role: Optional[str] = None
    # Hidden this sprint; sent explicitly as null so the contract is stable.
    model_version: Optional[str] = None
    anomaly_score: Optional[float] = None
    threshold: Optional[float] = None


class OpenAlertCount(BaseModel):
    """DB aggregate for the Alerts screen hero (not the loaded-page length)."""
    open: int


class AlertStateUpdate(BaseModel):
    state: str


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
    "status, last_monitored_seen, trusted, user_name, first_seen, last_seen")

# Additive: also fetch the per-family IP columns so row_to_summary/row_to_detail
# can resolve one stable display address (see _resolve_display_ip) and expose
# the IPv6 addresses. Appended here so every existing SELECT that uses
# SUMMARY_COLUMNS / DETAIL_COLUMNS picks them up without touching the queries.
SUMMARY_COLUMNS = SUMMARY_COLUMNS + (
    ", last_ipv4, last_ipv6_global, last_ipv6_ll")

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


def _presence_from_status(status, last_seen=None, now=None) -> str:
    """Recent passive observations count as online; expire at 120 seconds."""
    if status not in ("online", "observed"):
        return "offline"
    if last_seen:
        try:
            seen = datetime.fromisoformat(last_seen).astimezone()
            current = now or datetime.now().astimezone()
            if (current - seen).total_seconds() > 120:
                return "offline"
        except ValueError:
            return "offline"
    # Legacy records without a timestamp retain their stored presence.
    return "online"


def _is_monitored(last_monitored_seen, status=None, last_seen=None, now=None) -> bool:
    """Monitored only if unicast SPAN traffic was seen within the window.

    discovery writes server-local naive ISO-8601; like _presence_from_status,
    both sides are read as local time. No timestamp (or an unparsable one) is
    not monitored. An Offline device (same rule as _presence_from_status) is
    measured from its last_seen instead of now, so it keeps the state it had
    when it left (PBI-04); without a usable last_seen it falls back to now.
    """
    if not last_monitored_seen:
        return False
    try:
        seen = datetime.fromisoformat(last_monitored_seen).astimezone()
    except ValueError:
        return False
    current = now or datetime.now().astimezone()
    if last_seen and _presence_from_status(status, last_seen, current) == "offline":
        try:
            current = datetime.fromisoformat(last_seen).astimezone()
        except ValueError:
            pass
    return (current - seen).total_seconds() <= MONITORED_WINDOW_SECONDS


def _shown_model(model):
    """Read-time marketing-name fallback for a stored model value.

    When model_db recognizes the raw code, show "Marketing Name (CODE)"
    (e.g. "J720AP" -> "iPad Pro 13-inch (M4) (J720AP)"); otherwise return the
    stored value unchanged. Purely a display transform -- nothing is written
    back to the DB, and an empty/None value is left as-is.
    """
    if not model:
        return model
    return model_db.display_model(model) or model


def _classify_ip(value):
    """Return 'ipv4', 'ipv6_global', 'ipv6_ll', or None for a stored address.

    Any IPv6 zone suffix (e.g. "%eth0") is stripped before parsing. Mirrors
    discovery._ip_family_column so the read side folds the legacy single `ip`
    column into the same families the writer records.
    """
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None
    if addr.version == 4:
        return "ipv4"
    if addr.is_link_local:
        return "ipv6_ll"
    return "ipv6_global"


def _best_addresses(last_ipv4, ipv6_global, ipv6_ll, legacy_ip):
    """Resolve the best-known address of each family for a device.

    Prefers the dedicated per-family columns, then folds the legacy `ip` column
    into whichever family it belongs to so rows written before those columns
    existed (or by an older discovery.py) still resolve correctly. Returns the
    tuple (ipv4, ipv6_global, ipv6_link_local), any of which may be None.
    """
    v4, g, ll = last_ipv4, ipv6_global, ipv6_ll
    fam = _classify_ip(legacy_ip)
    if fam == "ipv4" and not v4:
        v4 = legacy_ip
    elif fam == "ipv6_global" and not g:
        g = legacy_ip
    elif fam == "ipv6_ll" and not ll:
        ll = legacy_ip
    return v4, g, ll


def _resolve_display_ip(last_ipv4, ipv6_global, ipv6_ll, legacy_ip):
    """The single address shown to the app: IPv4 if known, else a global IPv6,
    else a link-local fe80:: address only as a last resort. Stops the same card
    from flipping between address families."""
    v4, g, ll = _best_addresses(last_ipv4, ipv6_global, ipv6_ll, legacy_ip)
    return v4 or g or ll


def _resolve_ipv6(last_ipv4, ipv6_global, ipv6_ll, legacy_ip):
    """The device's known IPv6 addresses (global first, link-local last), or None
    when there are none. Surfaced in the optional `ipv6` response field."""
    _, g, ll = _best_addresses(last_ipv4, ipv6_global, ipv6_ll, legacy_ip)
    addrs = [a for a in (g, ll) if a]
    return addrs or None


def row_to_summary(row, now=None) -> DeviceSummary:
    # presence and monitored are not SQL columns; they are derived below.
    data = {k: row[k] for k in DeviceSummary.model_fields
            if k not in ("presence", "monitored")}
    # Replace the flip-prone legacy `ip` with one stable resolved address.
    data["ip"] = _resolve_display_ip(
        row["last_ipv4"], row["last_ipv6_global"], row["last_ipv6_ll"], row["ip"]
    )
    data["model"] = _shown_model(data.get("model"))
    data["vendor_source"] = _effective_vendor_source(
        data.get("mac"), data.get("vendor"), data.get("vendor_source")
    )
    data["monitored"] = _is_monitored(row["last_monitored_seen"], row["status"],
                                      row["last_seen"], now)
    data["trusted"] = bool(data["trusted"])
    data["presence"] = _presence_from_status(data.get("status"), data.get("last_seen"), now)
    for key in ("first_seen", "last_seen"):
        if data.get(key):
            try:
                data[key] = datetime.fromisoformat(data[key]).astimezone().isoformat(timespec="seconds")
            except ValueError:
                data[key] = None
    return DeviceSummary(**data)


def row_to_detail(row) -> DeviceDetail:
    data = dict(row)
    legacy_ip = data.get("ip")
    # Replace the flip-prone legacy `ip` with one stable resolved address, and
    # surface the known IPv6 addresses in the optional `ipv6` field.
    data["ip"] = _resolve_display_ip(
        data.get("last_ipv4"), data.get("last_ipv6_global"),
        data.get("last_ipv6_ll"), data.get("ip"),
    )
    data["ipv6"] = _resolve_ipv6(
        data.get("last_ipv4"), data.get("last_ipv6_global"),
        data.get("last_ipv6_ll"), legacy_ip,
    )
    data["model"] = _shown_model(data.get("model"))
    for flag in (
        "is_ap_client", "ap_associated", "discovered_current",
    "traffic_seen", "session_seen", "trusted",    ):
        data[flag] = bool(data[flag])
    data["monitored"] = _is_monitored(data.get("last_monitored_seen"), data.get("status"),
                                      data.get("last_seen"))
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
    data["presence"] = _presence_from_status(data.get("status"), data.get("last_seen"))
    for key in ("first_seen", "last_seen"):
        if data.get(key):
            try:
                data[key] = datetime.fromisoformat(data[key]).astimezone().isoformat(timespec="seconds")
            except ValueError:
                data[key] = None
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
                (datetime.now().astimezone() - datetime.fromisoformat(last_write).astimezone()).total_seconds()
            )
        except ValueError:
            last_write = None

    # A running capture service writes this even when no devices send traffic.
    try:
        beat = conn.execute("SELECT updated_at FROM daemon_heartbeat WHERE id=1").fetchone()
    except sqlite3.OperationalError:
        beat = None  # Compatibility with an older discovery service.
    heartbeat_age = max(0, time.time() - beat[0]) if beat else seconds_since_write
    daemon_stale = heartbeat_age is None or heartbeat_age > HEARTBEAT_STALE_SECONDS
    return {
        "status": "ok",
        "appliance_id": appliance_identity(conn),
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
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    clauses = []
    params: list = []
    now = datetime.now().astimezone()

    if online_only:
        # Share the displayed presence rules and filter before pagination.
        conn.create_function('assas_presence', 2,
                             lambda state, seen: _presence_from_status(state, seen, now))
        clauses.append("assas_presence(status, last_seen) = 'online'")
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
    return [row_to_summary(r, now) for r in rows]


@app.get('/activity')
def activity(conn: sqlite3.Connection = Depends(get_connection)):
    from live_activity import read_activity
    return read_activity(conn)


@app.get("/devices/{mac}", response_model=DeviceDetail)
def get_device(mac: str, conn: sqlite3.Connection = Depends(get_connection)):
    mac = normalize_mac(mac)
    row = conn.execute(
        f"SELECT {DETAIL_COLUMNS} FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No device with mac {mac}")
    return row_to_detail(row)


@app.put("/devices/{mac}/trust", response_model=TrustState)
def set_device_trust(mac: str, body: TrustUpdate):
    """Set the user recognition state for one existing device.

    The only write the API performs on device rows. It touches a single column
    (`trusted`) of a single existing row and creates nothing: a MAC that is not
    already known returns 404. It never affects discovery, classification,
    traffic capture, monitoring, or status.
    """
    mac = normalize_mac(mac)
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        cur = conn.execute(
            "UPDATE devices SET trusted = ? WHERE mac = ?", (int(body.trusted), mac)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"No device with mac {mac}")
        conn.commit()
    finally:
        conn.close()
    return TrustState(mac=mac, trusted=body.trusted)


@app.put("/devices/{mac}/name", response_model=NameState)
def set_device_name(mac: str, body: NameUpdate):
    """Set (or clear) the user-chosen display name for one existing device.

    Like /trust, this touches a single column (`user_name`) of a single existing
    row and creates nothing: an unknown MAC returns 404. The name is trimmed;
    null or empty-after-trim clears it (stores NULL); a value longer than 40
    characters is rejected (422) before any write. It never affects discovery,
    classification, traffic capture, monitoring, status, or trust.
    """
    mac = normalize_mac(mac)
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        cur = conn.execute(
            "UPDATE devices SET user_name = ? WHERE mac = ?", (body.name, mac)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"No device with mac {mac}")
        conn.commit()
    finally:
        conn.close()
    return NameState(mac=mac, user_name=body.name)


# --------------------------------------------------------------------------- #
# Threat alerts (PBI-14). The ingester (appliance/alerts.py) owns the `alerts`
# table and its schema; the API only reads it, except PATCH /alerts/{alert_id},
# which writes the `state` column of one alert (New -> Resolved). A missing
# table (ingester never ran) reads as "no alerts".
# --------------------------------------------------------------------------- #
_ALERT_SELECT = (
    "SELECT a.alert_id, a.device_mac, a.title, a.rule_id, a.event_time, "
    "a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.severity, a.state, "
    "a.occurrence_count, a.last_event_time, a.explanation, {added}, "
    "d.user_name, d.hostname, d.model "
    "FROM alerts a LEFT JOIN devices d ON d.mac = a.device_mac "
)

# Columns the ingester adds to existing tables (alerts.ADDED_ALERT_COLUMNS).
# The API may run before the ingester has migrated, so a missing one reads as
# NULL instead of failing the query; the API never alters the alerts table.
_ALERT_ADDED_COLUMNS = ("category", "classtype", "device_role")


def _alert_select(conn) -> str:
    have = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    added = ", ".join(
        f"a.{c}" if c in have else f"NULL AS {c}" for c in _ALERT_ADDED_COLUMNS
    )
    return _ALERT_SELECT.format(added=added)

_SEVERITIES = ("high", "medium", "low")
_STATES = ("new", "resolved")


_MACHINE_ID_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _looks_like_machine_id(s: str) -> bool:
    """Opaque machine identifier (UUID / long hex / long vowel-less token).

    Mirrors the app's Device.detectedName rule so the alert's device name and
    the device-details name come from the same precedence.
    """
    if " " in s:
        return False
    if _MACHINE_ID_UUID_RE.match(s):
        return True
    if len(s) >= 24 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return True
    if len(s) >= 24 and "-" not in s and "." not in s:
        vowels = sum(ch in "AEIOUaeiou" for ch in s)
        if vowels / len(s) < 0.1:
            return True
    return False


def _alert_device_name(user_name, hostname, model) -> str:
    """Same precedence the app shows on device details: user name, then a
    human-readable hostname (opaque machine identifiers are skipped), then the
    model, then 'Unknown device'. Inventory data only — never a guess."""
    user = (str(user_name).strip() if user_name else "")
    if user:
        return user
    host = (str(hostname).strip() if hostname else "")
    if host and not _looks_like_machine_id(host):
        return host
    m = (str(model).strip() if model else "")
    if m:
        return m
    return "Unknown device"


def _severity_api(value) -> str:
    v = (value or "").strip().lower()
    if v == "critical":
        # Safety net: Critical no longer exists; the ingester converts stored
        # rows once (alerts.migrate_release1), priority 1 is now High.
        return "high"
    return v if v in _SEVERITIES else "low"


def _state_api(value) -> str:
    # Anything not Resolved (including a retired 'Reviewed') is open: New.
    v = (value or "").strip().lower()
    return v if v in _STATES else "new"


# Canonical stored casing (the ingester writes 'New'); the API always emits
# lowercase via _state_api.
_STATE_DB = {"new": "New", "resolved": "Resolved"}

# Allowed transition (a user action; never auto-reverted and never walked
# backwards): New -> Resolved only, and Resolved is terminal. Expressed as the
# set of source states from which each target is reachable, so the change can be
# done as one atomic guarded UPDATE (... WHERE state IN <allowed sources>) with
# no read-then-write race between two phones.
_ALLOWED_SOURCES = {
    "resolved": ("new",),   # New -> Resolved
    "new": (),              # nothing transitions *to* New
}


def row_to_alert(row) -> AlertOut:
    # The rule ID stays in the response (rule_id) but is never put in user text.
    display_title, explanation = alert_text(row["classtype"], row["title"])
    role = row["device_role"] if row["device_mac"] else None
    return AlertOut(
        id=str(row["alert_id"]),
        kind="threat",
        title=row["title"],
        device_mac=row["device_mac"],
        device_name=_alert_device_name(row["user_name"], row["hostname"], row["model"]),
        time=row["last_event_time"],
        severity=_severity_api(row["severity"]),
        state=_state_api(row["state"]),
        first_event_time=row["event_time"],
        last_event_time=row["last_event_time"],
        occurrence_count=row["occurrence_count"],
        rule_id=row["rule_id"],
        source_ip=row["src_ip"],
        destination_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        display_title=display_title,
        # A stored explanation (none written today) wins over the classtype text.
        explanation=row["explanation"] or explanation,
        classtype=row["classtype"],
        category=row["category"],
        device_role=role if role in ("source", "target") else None,
    )


def _query_alerts(conn, where: str, args: tuple, limit: int, offset: int = 0):
    # Stable order (last_event_time, then the monotonic alert_id) so paging with
    # LIMIT/OFFSET is deterministic even when timestamps tie.
    try:
        sql = (
            _alert_select(conn) + "WHERE a.alert_type = 'Threat' AND " + where
            + " ORDER BY a.last_event_time DESC, a.alert_id DESC LIMIT ? OFFSET ?"
        )
        return conn.execute(sql, (*args, limit, offset)).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return []
        raise


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    conn: sqlite3.Connection = Depends(get_connection),
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Threat Alerts, newest first by last event time; LIMIT/OFFSET paginated."""
    return [row_to_alert(r) for r in _query_alerts(conn, "1=1", (), limit, offset)]


@app.get("/alerts/open_count", response_model=OpenAlertCount)
def open_alert_count(conn: sqlite3.Connection = Depends(get_connection)):
    """Count of OPEN (unresolved, state New) Threat Alerts across the whole DB.

    This is the Alerts-screen hero figure: it must be the true total, not the
    length of a paginated page. Declared BEFORE /alerts/{alert_id} so the literal
    path 'open_count' is matched here and never parsed as an int id.
    """
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE alert_type='Threat' AND LOWER(state) = 'new'"
        ).fetchone()
        return OpenAlertCount(open=row[0])
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return OpenAlertCount(open=0)
        raise


@app.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, conn: sqlite3.Connection = Depends(get_connection)):
    rows = _query_alerts(conn, "a.alert_id = ?", (alert_id,), 1)
    if not rows:
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    return row_to_alert(rows[0])


@app.patch("/alerts/{alert_id}", response_model=AlertOut)
def set_alert_state(alert_id: int, body: AlertStateUpdate):
    """Change one alert's state (PBI-22). Authenticated (global require_auth).

    A deliberate user action — it never implies ASSAS auto-handled the threat,
    and only the `state` column of one existing alert is written. The only move
    is New->Resolved (Resolved is terminal). The ingester's dedup never touches
    `state`, so occurrence updates do not revert a resolved alert to New.
    """
    target = (body.state or "").strip().lower()
    if target not in _STATES:
        raise HTTPException(status_code=422, detail=f"Unknown alert state {body.state!r}")
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(status_code=503, detail=f"Device database is not available yet: {exc}")
    conn.row_factory = sqlite3.Row  # row_to_alert / row["state"] need key access
    try:
        allowed = _ALLOWED_SOURCES.get(target, ())
        try:
            changed = 0
            if allowed:
                # ATOMIC transition: only flip the row if it is still in an
                # allowed source state. If a concurrent phone already moved it
                # (e.g. to Resolved), this matches 0 rows and the move is
                # rejected below.
                placeholders = ",".join("?" * len(allowed))
                cur = conn.execute(
                    f"UPDATE alerts SET state=? "
                    f"WHERE alert_id=? AND alert_type='Threat' "
                    f"AND LOWER(state) IN ({placeholders})",
                    (_STATE_DB[target], alert_id, *allowed),
                )
                conn.commit()
                changed = cur.rowcount
            if changed == 0:
                # No transition happened: classify why (not a second write).
                row = conn.execute(
                    "SELECT state FROM alerts WHERE alert_id=? AND alert_type='Threat'",
                    (alert_id,),
                ).fetchone()
                if row is None:
                    raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
                current = _state_api(row["state"])
                if current != target:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Cannot change alert state from {current} to {target}",
                    )
                # current == target: idempotent no-op, fall through and return it.
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
            raise
        rows = _query_alerts(conn, "a.alert_id = ?", (alert_id,), 1)
    finally:
        conn.close()
    return row_to_alert(rows[0])


@app.get("/devices/{mac}/alerts", response_model=list[AlertOut])
def list_device_alerts(
    mac: str,
    conn: sqlite3.Connection = Depends(get_connection),
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Alerts linked to one device, newest first; LIMIT/OFFSET paginated."""
    mac = normalize_mac(mac)
    return [row_to_alert(r) for r in _query_alerts(conn, "a.device_mac = ?", (mac,), limit, offset)]


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


@app.get("/settings", response_model=SettingsState)
def get_settings(conn: sqlite3.Connection = Depends(get_connection)):
    """Return the persisted appliance setting. A missing table or row (not seeded
    yet) reads as the default, so this never 404s once the API is up."""
    try:
        row = conn.execute(
            "SELECT active_probes FROM app_settings WHERE id = 1"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table: app_settings' not in str(exc):
            raise HTTPException(status_code=503, detail="Settings database is unavailable.") from exc
        row = None  # table not created yet -> default
    active = bool(row["active_probes"]) if row is not None else False
    return SettingsState(active_probes=active)


@app.put("/settings", response_model=SettingsState)
def put_settings(body: SettingsUpdate):
    """Persist the single appliance setting (idempotent upsert of the one row).

    Discovery re-reads this value on its own schedule and applies it to the
    active-probe gates; this endpoint only writes app_settings and never touches
    device rows, discovery state, or classification.
    """
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        # Guarantee the target exists even if lifespan startup did not run.
        conn.execute(_APP_SETTINGS_DDL)
        conn.execute(
            "INSERT INTO app_settings (id, active_probes) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET active_probes = excluded.active_probes",
            (int(body.active_probes),),
        )
        conn.commit()
    finally:
        conn.close()
    return SettingsState(active_probes=body.active_probes)


# ---------------------------------------------------------------------------
# Pairing (PBI-08)
#
# The 7-inch display shows a short code that changes every minute. A phone that
# sends the current code gets a token (added in the next step). The code lives
# only in memory: it is short-lived, so it never needs to survive a restart.
# ---------------------------------------------------------------------------

# Letters and digits that are easy to read on a screen: no 0/O, no 1/I/L.
PAIRING_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
PAIRING_CODE_LENGTH = 6
PAIRING_CODE_TTL_SECONDS = int(os.getenv("ASSAS_PAIRING_CODE_TTL_SECONDS", "60"))

# Only the appliance itself (the display) may read the current code.
LOCAL_HOSTS = {"127.0.0.1", "::1"}

_pairing_lock = threading.Lock()
_pairing_code: Optional[str] = None
_pairing_expires_at: Optional[datetime] = None
_pairing_failed_attempts = 0
MAX_FAILED_PAIRING_ATTEMPTS = 5

# A correct code sent to /pair/verify buys a short-lived, single-use ticket that
# /pair then accepts with the phone name. Only its hash is kept, in memory.
PAIRING_TICKET_TTL_SECONDS = int(os.getenv("ASSAS_PAIRING_TICKET_TTL_SECONDS", "180"))
_pairing_ticket_hash: Optional[str] = None
_pairing_ticket_expires_at: Optional[datetime] = None


def _new_pairing_code() -> str:
    return "".join(
        secrets.choice(PAIRING_CODE_ALPHABET) for _ in range(PAIRING_CODE_LENGTH)
    )


def current_pairing_code() -> tuple[str, datetime]:
    """Return the current code, making a new one when the old one has expired."""
    global _pairing_code, _pairing_expires_at, _pairing_failed_attempts
    with _pairing_lock:
        now = datetime.now()
        if _pairing_code is None or now >= _pairing_expires_at:
            _pairing_code = _new_pairing_code()
            _pairing_expires_at = now + timedelta(seconds=PAIRING_CODE_TTL_SECONDS)
            _pairing_failed_attempts = 0
        return _pairing_code, _pairing_expires_at


def _is_local_request(request: Request) -> bool:
    return request.client is not None and request.client.host in LOCAL_HOSTS


class PairingCodeOut(BaseModel):
    code: str
    expires_at: str


@app.get(
    "/pairing/code",
    response_model=PairingCodeOut,
    responses={403: {"description": "Only the Assas device itself can read the code."}},
)
def get_pairing_code(request: Request):
    if not _is_local_request(request):
        raise HTTPException(
            status_code=403,
            detail="The pairing code is only shown on the Assas device itself.",
        )
    code, expires_at = current_pairing_code()
    return PairingCodeOut(
        code=code, expires_at=expires_at.astimezone().isoformat(timespec="seconds")
    )

# ---------------------------------------------------------------------------
# Pairing sessions (PBI-08)
#
# A phone that sends the current code gets a random token. Only a SHA-256 hash
# of the token is stored, so a copy of the database cannot be used to log in.
# Like app_settings, the table is created on first write; reads treat a
# missing table as "no sessions".
# ---------------------------------------------------------------------------

_SESSIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS paired_sessions ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " token_hash TEXT NOT NULL UNIQUE,"
    " created_at TEXT NOT NULL,"
    " device_name TEXT NOT NULL DEFAULT 'Unnamed phone'"
    ")"
)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _check_pairing_code(code: str, consume: bool = False) -> bool:
    """True if code matches the current, unexpired code.

    Every wrong guess counts; after MAX_FAILED_PAIRING_ATTEMPTS the code is
    dropped, so the display fetches a new one and guessing becomes useless.
    With consume=True a matching code is dropped too, so it works only once.
    """
    global _pairing_code, _pairing_failed_attempts
    with _pairing_lock:
        valid = (
            _pairing_code is not None
            and datetime.now() < _pairing_expires_at
            and secrets.compare_digest(code.encode(), _pairing_code.encode())
        )
        if valid and consume:
            _pairing_code = None
        if not valid and _pairing_code is not None:
            _pairing_failed_attempts += 1
            if _pairing_failed_attempts >= MAX_FAILED_PAIRING_ATTEMPTS:
                _pairing_code = None
        return valid


def _issue_pairing_ticket() -> tuple[str, datetime]:
    """Make a new ticket; it replaces any older one."""
    global _pairing_ticket_hash, _pairing_ticket_expires_at
    ticket = secrets.token_urlsafe(32)
    with _pairing_lock:
        _pairing_ticket_hash = _hash_token(ticket)
        _pairing_ticket_expires_at = datetime.now() + timedelta(
            seconds=PAIRING_TICKET_TTL_SECONDS
        )
        return ticket, _pairing_ticket_expires_at


def _consume_pairing_ticket(ticket: str) -> bool:
    """True (and the ticket is used up) if ticket is the current, unexpired one.

    A bad ticket does not count toward MAX_FAILED_PAIRING_ATTEMPTS: tickets are
    long random strings, so guessing them is not a concern.
    """
    global _pairing_ticket_hash, _pairing_ticket_expires_at
    with _pairing_lock:
        valid = (
            _pairing_ticket_hash is not None
            and datetime.now() < _pairing_ticket_expires_at
            and secrets.compare_digest(
                _hash_token(ticket).encode(), _pairing_ticket_hash.encode()
            )
        )
        if valid:
            _pairing_ticket_hash = None
            _pairing_ticket_expires_at = None
        return valid


class PairVerifyRequest(BaseModel):
    code: str


class PairVerifyResponse(BaseModel):
    ticket: str
    expires_at: str


@app.post(
    "/pair/verify",
    response_model=PairVerifyResponse,
    responses={401: {"description": "Invalid or expired pairing code."}},
)
def pair_verify(body: PairVerifyRequest):
    """Step 1 of pairing: check the code before the app asks for a phone name."""
    code = body.code.strip().upper()
    if not _check_pairing_code(code, consume=True):
        raise HTTPException(status_code=401, detail="Invalid or expired pairing code.")
    ticket, expires_at = _issue_pairing_ticket()
    return PairVerifyResponse(
        ticket=ticket, expires_at=expires_at.astimezone().isoformat(timespec="seconds")
    )


class PairRequest(BaseModel):
    code: Optional[str] = None
    ticket: Optional[str] = None
    device_name: Optional[str] = None

    @model_validator(mode="after")
    def _code_or_ticket(self):
        if (self.code is None) == (self.ticket is None):
            raise ValueError("Send exactly one of 'code' or 'ticket'.")
        return self

    @field_validator("device_name")
    @classmethod
    def _clean_device_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if len(value) > 40:
            raise ValueError("Phone name must be at most 40 characters.")
        return value or None


class PairResponse(BaseModel):
    token: str
    appliance_id: str


class PairedPhone(BaseModel):
    id: int
    device_name: str
    created_at: str


@app.get("/sessions", response_model=list[PairedPhone])
def list_sessions(request: Request, conn: sqlite3.Connection = Depends(get_connection)):
    """Appliance display only; never return token hashes to a caller."""
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Available only on the Assas device.")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(paired_sessions)")}
    if not columns:
        return []
    name = "device_name" if "device_name" in columns else "'Unnamed phone'"
    rows = conn.execute(
        f"SELECT id, {name} AS device_name, created_at FROM paired_sessions ORDER BY id"
    ).fetchall()
    return [PairedPhone(**dict(row)) for row in rows]


@app.post(
    "/pair",
    response_model=PairResponse,
    responses={
        401: {"description": "Invalid or expired pairing code or ticket."},
        503: {"description": "Device database is not available yet."},
    },
)
def pair(body: PairRequest):
    if body.ticket is not None:
        if not _consume_pairing_ticket(body.ticket):
            raise HTTPException(
                status_code=401,
                detail="Pairing ticket is invalid or expired. Start pairing again.",
            )
    else:
        code = body.code.strip().upper()
        if not _check_pairing_code(code, consume=True):
            raise HTTPException(status_code=401, detail="Invalid or expired pairing code.")

    token = secrets.token_urlsafe(32)
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        conn.execute(_SESSIONS_DDL)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(paired_sessions)")}
        if "device_name" not in columns:
            conn.execute("ALTER TABLE paired_sessions ADD COLUMN device_name TEXT NOT NULL DEFAULT 'Unnamed phone'")
        conn.execute(
            "INSERT INTO paired_sessions (token_hash, created_at, device_name) VALUES (?, ?, ?)",
            (_hash_token(token), datetime.now().isoformat(timespec="seconds"), body.device_name or "Unnamed phone"),
        )
        conn.commit()
    finally:
        conn.close()
    return PairResponse(token=token, appliance_id=appliance_identity())


# ---------------------------------------------------------------------------
# Authentication (PBI-08)
# ---------------------------------------------------------------------------

# Reachable without a token. /pairing/code is listed because it guards itself:
# it only answers the appliance (403 for everyone else, paired or not).
PUBLIC_PATHS = {"/healthz", "/pair", "/pair/verify", "/pairing/code"}


def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _session_exists(token: str) -> bool:
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        row = conn.execute(
            "SELECT 1 FROM paired_sessions WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table: paired_sessions' in str(exc):
            row = None  # no sessions table yet -> nobody is paired
        else:
            # A temporary storage failure must not revoke a valid phone session.
            raise HTTPException(status_code=503, detail="Session database is unavailable.") from exc
    finally:
        conn.close()
    return row is not None


@app.post(
    "/unpair",
    status_code=204,
    responses={503: {"description": "Device database is not available yet."}},
)
def unpair(request: Request) -> None:
    """End this phone's session. Its token stops working immediately."""
    token = _bearer_token(request)
    if token is None:
        return  # the appliance itself has no session to end
    try:
        conn = _open_writable()
    except sqlite3.OperationalError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Device database is not available yet: {exc}",
        )
    try:
        conn.execute(
            "DELETE FROM paired_sessions WHERE token_hash = ?",
            (_hash_token(token),),
        )
        conn.commit()
    except sqlite3.OperationalError as exc:
        raise HTTPException(status_code=503, detail="Could not revoke session.") from exc
    finally:
        conn.close()

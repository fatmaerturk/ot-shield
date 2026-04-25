#!/usr/bin/env python3
"""
OTShield Tripwire HMI
=====================

A minimal industrial-protocol tripwire honeypot. Designed to live INSIDE an
OT/SCADA subnet, masquerading as a real HMI. Any inbound TCP connection is
treated as a high-confidence intrusion signal: a meaningful banner is sent
back so the attacker thinks they hit a real device, the connection is logged,
and the event is forwarded to the OTShield backend ingest endpoint.

This is intentionally NOT a full protocol simulator (use Conpot for that).
The point is alarm fidelity: a single packet to a Tripwire HMI is, by design,
a CRITICAL incident — no legitimate user has any reason to talk to it.

Configuration (env vars):
    HMI_TYPE             SUBSTATION | WATER_TREATMENT | REFINERY | MANUFACTURING
    HMI_PROTOCOL         MODBUS | S7COMM | IEC104 | HTTP
    HMI_PORT             TCP port to listen on (e.g. 502)
    HMI_VENDOR           SIEMENS | ROCKWELL | SCHNEIDER | ABB | GENERIC
    HMI_SITE_TAG         Free-form site identifier shown in alarms (e.g. "PLANT-A-NORTH")
    INGEST_URL           https://your-backend/api/honeypot/ingest
    INGEST_TOKEN         Bearer token expected by the backend
    BIND_HOST            (optional) defaults to 0.0.0.0
    LOG_LEVEL            (optional) DEBUG | INFO | WARNING (default INFO)
"""
import os
import sys
import json
import time
import socket
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ────────────────────────────────────────────────────────────────────────────────
# Config
# ────────────────────────────────────────────────────────────────────────────────
HMI_TYPE     = os.environ.get("HMI_TYPE", "SUBSTATION").upper()
HMI_PROTOCOL = os.environ.get("HMI_PROTOCOL", "MODBUS").upper()
HMI_PORT     = int(os.environ.get("HMI_PORT", "502"))
HMI_VENDOR   = os.environ.get("HMI_VENDOR", "SIEMENS").upper()
HMI_SITE_TAG = os.environ.get("HMI_SITE_TAG", "OT-SUBNET")
BIND_HOST    = os.environ.get("BIND_HOST", "0.0.0.0")
INGEST_URL   = os.environ.get("INGEST_URL", "").rstrip("/")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
LOG_LEVEL    = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] tripwire-%(name)s: %(message)s",
)
log = logging.getLogger(HMI_TYPE.lower())

if not INGEST_URL or not INGEST_TOKEN:
    log.warning("INGEST_URL or INGEST_TOKEN not set — alarms will be logged locally only")

# ────────────────────────────────────────────────────────────────────────────────
# Protocol banners — what the tripwire returns to keep the attacker engaged for
# a few extra seconds. Just enough to look real, not enough to be a target.
# ────────────────────────────────────────────────────────────────────────────────
def modbus_banner() -> bytes:
    """A minimal Modbus TCP MBAP-style "device busy" exception response."""
    # Trans ID 0x0001, Proto 0, Length 3, Unit 1, Function 0x83 (read+exception),
    # Exception code 0x06 (Slave Device Busy)
    return bytes.fromhex("000100000003018306")

def s7_banner() -> bytes:
    """S7Comm TPKT/COTP CR-style ack — looks like a Siemens PLC alive."""
    return bytes.fromhex("0300001611d00001000400c0010ac1020100c2020102")

def iec104_banner() -> bytes:
    """IEC104 STARTDT confirm (control byte 0x0B)."""
    return bytes.fromhex("680403000000")

def http_banner() -> bytes:
    body = (
        f"<html><head><title>{HMI_VENDOR} {HMI_TYPE} HMI</title></head>"
        f"<body><h1>Login</h1><form>...</form></body></html>"
    ).encode()
    headers = (
        "HTTP/1.1 401 Unauthorized\r\n"
        f'WWW-Authenticate: Basic realm="HMI"\r\n'
        "Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    return headers + body

BANNERS = {
    "MODBUS":  modbus_banner,
    "S7COMM":  s7_banner,
    "IEC104":  iec104_banner,
    "HTTP":    http_banner,
}

# Hint text shown in alarm description for each HMI type
HMI_DESCRIPTION = {
    "SUBSTATION":      "33 kV substation HMI",
    "WATER_TREATMENT": "Drinking water treatment HMI",
    "REFINERY":        "Oil & gas pipeline HMI",
    "MANUFACTURING":   "Assembly line / OEE HMI",
}

# ────────────────────────────────────────────────────────────────────────────────
# Alarm forwarder
# ────────────────────────────────────────────────────────────────────────────────
def post_alarm(source_ip: str, source_port: int, payload_hex: str) -> None:
    """Forward an intrusion event to the OTShield backend ingest endpoint."""
    if not INGEST_URL or not INGEST_TOKEN:
        return

    # Build a log line the existing Conpot parser will recognise. We re-use the
    # well-known "New <Protocol> connection from <ip>:<port>." shape so the
    # backend's processLogLine path picks it up without changes.
    proto_label = HMI_PROTOCOL.title() if HMI_PROTOCOL != "IEC104" else "IEC104"
    line = (
        f"[INTERNAL-DECOY] [{HMI_SITE_TAG}] "
        f"New {proto_label} connection from {source_ip}:{source_port}. "
        f"Tripwire HMI '{HMI_TYPE}' on port {HMI_PORT} "
        f"hit by lateral-movement actor "
        f"(payload first bytes: {payload_hex[:32] or '-'})"
    )

    body = json.dumps({"line": line}).encode("utf-8")
    req = urllib.request.Request(
        INGEST_URL + "/api/honeypot/ingest",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + INGEST_TOKEN,
            "X-Decoy-Source": "internal-decoy",
            "X-HMI-Type": HMI_TYPE,
            "X-HMI-Vendor": HMI_VENDOR,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status >= 300:
                log.warning("ingest HTTP %s", resp.status)
    except urllib.error.HTTPError as e:
        log.warning("ingest HTTP %s: %s", e.code, e.read()[:200].decode("utf-8", "ignore"))
    except Exception as e:  # pylint: disable=broad-except
        log.warning("ingest error: %s", e)

# ────────────────────────────────────────────────────────────────────────────────
# Connection handler
# ────────────────────────────────────────────────────────────────────────────────
def handle(conn: socket.socket, addr) -> None:
    src_ip, src_port = addr
    ts = datetime.now(timezone.utc).isoformat()
    payload_hex = ""
    try:
        conn.settimeout(2.0)
        # Read whatever the attacker sent first (max 256B, just for the log)
        try:
            data = conn.recv(256)
            payload_hex = data.hex()
        except socket.timeout:
            data = b""

        log.info(
            "INTRUSION src=%s:%s payload=%dB hmi=%s proto=%s port=%d ts=%s",
            src_ip, src_port, len(data), HMI_TYPE, HMI_PROTOCOL, HMI_PORT, ts,
        )

        # Send a banner so the attacker thinks they hit a device
        banner_fn = BANNERS.get(HMI_PROTOCOL)
        if banner_fn:
            try:
                conn.sendall(banner_fn())
            except Exception:  # pylint: disable=broad-except
                pass

        # Forward alarm to backend (in a thread so the socket can close immediately)
        threading.Thread(
            target=post_alarm,
            args=(src_ip, src_port, payload_hex),
            daemon=True,
        ).start()
    finally:
        try:
            conn.close()
        except Exception:  # pylint: disable=broad-except
            pass

# ────────────────────────────────────────────────────────────────────────────────
# Main loop
# ────────────────────────────────────────────────────────────────────────────────
def main() -> None:
    desc = HMI_DESCRIPTION.get(HMI_TYPE, HMI_TYPE)
    log.info(
        "Tripwire HMI starting | type=%s vendor=%s protocol=%s port=%d site=%s desc='%s'",
        HMI_TYPE, HMI_VENDOR, HMI_PROTOCOL, HMI_PORT, HMI_SITE_TAG, desc,
    )

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((BIND_HOST, HMI_PORT))
    except PermissionError:
        log.error("Permission denied binding to port %d (use a >1024 port or run as root)", HMI_PORT)
        sys.exit(1)
    srv.listen(50)
    log.info("Listening on %s:%d", BIND_HOST, HMI_PORT)

    try:
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                break
            except Exception as e:  # pylint: disable=broad-except
                log.warning("accept error: %s", e)
                time.sleep(0.5)
    finally:
        srv.close()
        log.info("Tripwire HMI shutting down")

if __name__ == "__main__":
    main()

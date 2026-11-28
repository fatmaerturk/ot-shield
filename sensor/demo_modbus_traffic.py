#!/usr/bin/env python3
"""
Demo Modbus TCP traffic generator - for LOCAL SPAN-sensor testing only.
=====================================================================
Starts a tiny Modbus TCP server on 127.0.0.1:502 and a client that polls it,
so the SPAN sensor (capturing the loopback adapter with the default ICS BPF)
sees REAL Modbus frames - function codes 0x03 read-holding-registers,
0x01 read-coils and 0x06 write-single-register. The captured pcap then runs
the normal backend pipeline, which classifies the protocol as Modbus and
discovers the endpoint as an asset. That exercises the whole automatic SPAN
loop end to end, with no fabricated data anywhere.

Dependency-free (stdlib only). Not for production - this is a test fixture.

Usage (this script needs NO admin; the SENSOR needs admin for packet capture):
    py -3 sensor/demo_modbus_traffic.py                 # ~90s on 127.0.0.1:502
    py -3 sensor/demo_modbus_traffic.py --seconds 120
"""
import argparse
import socket
import struct
import sys
import threading
import time


def _mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    """Wrap a PDU in a Modbus TCP MBAP header (protocol id 0)."""
    length = 1 + len(pdu)  # unit id + PDU
    return struct.pack(">HHHB", tid, 0, length, unit) + pdu


def _serve_conn(conn: socket.socket, stop: threading.Event) -> None:
    conn.settimeout(1.0)
    buf = b""
    while not stop.is_set():
        try:
            chunk = conn.recv(1024)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        # Parse as many complete frames as we have.
        while len(buf) >= 8:
            tid, _pid, length, unit, fc = struct.unpack(">HHHBB", buf[:8])
            total = 6 + length  # tid+pid+length are the first 6 bytes
            if len(buf) < total:
                break
            body = buf[8:total]
            buf = buf[total:]
            try:
                if fc == 0x03 and len(body) >= 4:  # read holding registers
                    _start, qty = struct.unpack(">HH", body[:4])
                    data = bytes((i * 3) % 256 for i in range(2 * qty))
                    conn.sendall(_mbap(tid, unit, struct.pack(">BB", 0x03, 2 * qty) + data))
                elif fc == 0x01 and len(body) >= 4:  # read coils
                    _start, qty = struct.unpack(">HH", body[:4])
                    nbytes = (qty + 7) // 8
                    conn.sendall(_mbap(tid, unit, struct.pack(">BB", 0x01, nbytes) + b"\xaa" * nbytes))
                elif fc == 0x06 and len(body) >= 4:  # write single register (echo)
                    addr, val = struct.unpack(">HH", body[:4])
                    conn.sendall(_mbap(tid, unit, struct.pack(">BHH", 0x06, addr, val)))
            except OSError:
                return
    try:
        conn.close()
    except OSError:
        pass


def _server(host: str, port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        print(f"[demo] ERROR binding {host}:{port}: {e}\n"
              f"[demo] Is something already using port {port}? Close it and retry.",
              file=sys.stderr)
        stop.set()
        return
    srv.listen(5)
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_serve_conn, args=(conn, stop), daemon=True).start()
    try:
        srv.close()
    except OSError:
        pass


def _client(host: str, port: int, stop: threading.Event) -> None:
    tid = 0
    sent = 0
    # Three representative polls; rotate them so the capture carries variety.
    def req(t: int, fc: int, a: int, b: int) -> bytes:
        return struct.pack(">HHHBBHH", t, 0, 6, 1, fc, a, b)

    while not stop.is_set():
        try:
            s = socket.create_connection((host, port), timeout=2.0)
        except OSError:
            time.sleep(1.0)
            continue
        try:
            while not stop.is_set():
                tid = (tid + 1) & 0xFFFF
                reqs = [req(tid, 0x03, 0, 10), req(tid, 0x01, 0, 16), req(tid, 0x06, 5, 1234)]
                try:
                    s.sendall(reqs[tid % 3])
                    s.recv(1024)
                except OSError:
                    break
                sent += 1
                if sent % 25 == 0:
                    print(f"[demo] {sent} Modbus polls sent...")
                time.sleep(0.25)
        finally:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(0.5)


def main() -> int:
    ap = argparse.ArgumentParser(description="Local Modbus TCP traffic for SPAN-sensor testing")
    ap.add_argument("--host", default="127.0.0.1", help="bind/connect host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=502, help="Modbus TCP port (default 502)")
    ap.add_argument("--seconds", type=int, default=90, help="how long to generate traffic")
    a = ap.parse_args()

    stop = threading.Event()
    threading.Thread(target=_server, args=(a.host, a.port, stop), daemon=True).start()
    time.sleep(0.5)
    if stop.is_set():
        return 1  # server failed to bind
    threading.Thread(target=_client, args=(a.host, a.port, stop), daemon=True).start()

    print(f"[demo] Modbus server + client running on {a.host}:{a.port} for {a.seconds}s "
          f"(Ctrl+C to stop early).")
    try:
        time.sleep(a.seconds)
    except KeyboardInterrupt:
        print("\n[demo] interrupted.")
    stop.set()
    time.sleep(1.0)
    print("[demo] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

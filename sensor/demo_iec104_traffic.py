#!/usr/bin/env python3
"""
Demo IEC 60870-5-104 traffic generator - for LOCAL SPAN-sensor testing only.
===========================================================================
Starts a tiny IEC-104 server on 127.0.0.1:2404 and a client that drives a
realistic session, so the SPAN sensor (capturing the loopback adapter with the
default ICS BPF, which includes tcp/2404) sees REAL IEC-104 frames:

    - STARTDT act / con handshake (U-format)
    - General Interrogation (C_IC_NA_1) act -> act-con -> interrogated values
      (M_ME_NC_1 short floats, M_SP_NA_1 single points) -> act-termination
    - spontaneous monitoring values (COT = spontaneous)
    - a single command (C_SC_NA_1) control, with act-con
    - TESTFR act / con keepalive

The captured pcap runs the backend's IEC104 dissector, which classifies each
PDU and populates the decoded fields (type id, cause of transmission, common
address, IOA, command vs monitoring) shown in the Decoded-packets panel.

Dependency-free (stdlib only). Not for production - this is a test fixture.

Usage (this script needs NO admin; the SENSOR needs admin for packet capture):
    py -3 sensor/demo_iec104_traffic.py                 # ~90s on 127.0.0.1:2404
    py -3 sensor/demo_iec104_traffic.py --seconds 120
"""
import argparse
import socket
import struct
import sys
import threading
import time

START = 0x68
COMMON_ADDRESS = 1


# ---- APCI frame builders ---------------------------------------------------
def u_frame(c0: int) -> bytes:
    return bytes([START, 0x04, c0, 0x00, 0x00, 0x00])


STARTDT_ACT = u_frame(0x07)
STARTDT_CON = u_frame(0x0B)
TESTFR_ACT = u_frame(0x43)
TESTFR_CON = u_frame(0x83)


def s_frame(nr: int) -> bytes:
    return bytes([START, 0x04, 0x01, 0x00, (nr << 1) & 0xFF, (nr >> 7) & 0xFF])


def i_frame(ns: int, nr: int, asdu: bytes) -> bytes:
    control = bytes([(ns << 1) & 0xFF, (ns >> 7) & 0xFF, (nr << 1) & 0xFF, (nr >> 7) & 0xFF])
    body = control + asdu
    return bytes([START, len(body) & 0xFF]) + body


def asdu(type_id: int, cot: int, ioa: int, elements: bytes = b"", num: int = 1,
         sq: bool = False, orig: int = 0, ca: int = COMMON_ADDRESS) -> bytes:
    vsq = (num & 0x7F) | (0x80 if sq else 0)
    hdr = bytes([type_id, vsq, cot & 0x3F, orig]) + struct.pack("<H", ca)
    ioa3 = bytes([ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF])
    return hdr + ioa3 + elements


# ---- element encoders ------------------------------------------------------
def siq(on: bool) -> bytes:
    return bytes([0x01 if on else 0x00])  # SIQ: bit0 = SPI


def short_float(v: float) -> bytes:
    return struct.pack("<f", v) + bytes([0x00])  # value + QDS


def sco(on: bool) -> bytes:
    return bytes([0x01 if on else 0x00])  # SCO: bit0 = SCS


def qoi_station() -> bytes:
    return bytes([0x14])  # QOI = 20 (station interrogation)


# ---- framed reader ---------------------------------------------------------
def read_frames(sock: socket.socket, buf: bytearray):
    """Pull complete APDUs out of a growing buffer; yields raw frame bytes."""
    out = []
    while len(buf) >= 2:
        if buf[0] != START:
            buf.pop(0)
            continue
        length = buf[1]
        total = 2 + length
        if len(buf) < total:
            break
        out.append(bytes(buf[:total]))
        del buf[:total]
    return out


# ---- server ----------------------------------------------------------------
def _serve_conn(conn: socket.socket, stop: threading.Event):
    conn.settimeout(1.0)
    buf = bytearray()
    ns = 0   # server send sequence
    nr = 0   # server receive sequence (I-frames seen)
    last_spont = 0.0
    val = 21.5
    while not stop.is_set():
        try:
            chunk = conn.recv(2048)
            if chunk == b"":
                break  # peer closed the connection
            buf.extend(chunk)
        except socket.timeout:
            pass  # idle tick - still emit spontaneous values below
        except OSError:
            break

        for frame in read_frames(conn, buf):
            c0 = frame[2]
            try:
                if (c0 & 0x03) == 0x03:  # U-format
                    if c0 == 0x07:       # STARTDT act
                        conn.sendall(STARTDT_CON)
                    elif c0 == 0x43:     # TESTFR act
                        conn.sendall(TESTFR_CON)
                elif (c0 & 0x03) == 0x01:  # S-format ack -> ignore
                    pass
                else:                      # I-format
                    nr += 1
                    type_id = frame[6]
                    cot = frame[8] & 0x3F
                    if type_id == 100 and cot == 6:   # C_IC activation (GI)
                        conn.sendall(i_frame(ns, nr, asdu(100, 7, 0, qoi_station()))); ns += 1
                        for k in range(3):
                            conn.sendall(i_frame(ns, nr, asdu(13, 20, 4000 + k, short_float(val + k)))); ns += 1
                        conn.sendall(i_frame(ns, nr, asdu(1, 20, 5000, siq(True)))); ns += 1
                        conn.sendall(i_frame(ns, nr, asdu(100, 10, 0, qoi_station()))); ns += 1  # act termination
                    elif type_id == 45 and cot == 6:  # C_SC single command
                        conn.sendall(i_frame(ns, nr, asdu(45, 7, frame[12] | (frame[13] << 8), sco(True)))); ns += 1
            except OSError:
                return

        # spontaneous monitoring values every ~3s
        now = time.time()
        if now - last_spont >= 3.0:
            last_spont = now
            val += 0.3
            try:
                conn.sendall(i_frame(ns, nr, asdu(13, 3, 4001, short_float(val)))); ns += 1
                conn.sendall(i_frame(ns, nr, asdu(1, 3, 5001, siq(int(val) % 2 == 0)))); ns += 1
            except OSError:
                break
    try:
        conn.close()
    except OSError:
        pass


def _server(host: str, port: int, stop: threading.Event):
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


# ---- client ----------------------------------------------------------------
def _client(host: str, port: int, stop: threading.Event):
    sent = 0
    while not stop.is_set():
        try:
            s = socket.create_connection((host, port), timeout=2.0)
        except OSError:
            time.sleep(1.0)
            continue
        s.settimeout(1.0)
        buf = bytearray()
        ns = 0
        nr = 0
        try:
            s.sendall(STARTDT_ACT)
            s.sendall(i_frame(ns, nr, asdu(100, 6, 0, qoi_station()))); ns += 1  # general interrogation
            last_test = time.time()
            last_cmd = time.time()
            cmd_on = True
            while not stop.is_set():
                try:
                    chunk = s.recv(2048)
                    if chunk == b"":
                        break  # server closed
                    buf.extend(chunk)
                    for _ in read_frames(s, buf):
                        nr += 1
                except socket.timeout:
                    pass
                except OSError:
                    break

                now = time.time()
                if now - last_test >= 2.0:      # keepalive
                    last_test = now
                    s.sendall(TESTFR_ACT)
                if now - last_cmd >= 4.0:        # periodic single command
                    last_cmd = now
                    s.sendall(i_frame(ns, nr, asdu(45, 6, 6000, sco(cmd_on)))); ns += 1
                    cmd_on = not cmd_on
                    sent += 1
                    if sent % 5 == 0:
                        print(f"[demo] {sent} IEC-104 commands sent...")
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(0.5)


# ---- pcap writer (offline mode: no admin / no capture needed) --------------
def _ip_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | (hdr[i + 1] if i + 1 < len(hdr) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _eth_ip_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                seq: int, ack: int, payload: bytes) -> bytes:
    def ipb(ip):
        return bytes(int(x) for x in ip.split("."))
    eth = bytes([0x02, 0, 0, 0, 0, 0x02]) + bytes([0x02, 0, 0, 0, 0, 0x01]) + b"\x08\x00"
    total = 20 + 20 + len(payload)
    ip = bytearray([0x45, 0x00, (total >> 8) & 0xFF, total & 0xFF,
                    0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]) + ipb(src_ip) + ipb(dst_ip)
    cs = _ip_checksum(bytes(ip))
    ip[10] = (cs >> 8) & 0xFF
    ip[11] = cs & 0xFF
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), 0x18, 8192, 0, 0)
    return eth + bytes(ip) + tcp + payload


def write_pcap(path: str) -> int:
    master_ip, rtu_ip = "10.10.2.50", "10.20.0.60"
    mport = 50000
    ns_m = ns_r = nr_m = nr_r = 0
    # (direction, apdu) - 'm' master->rtu, 'r' rtu->master
    seq_frames = []

    def m(apdu): seq_frames.append(("m", apdu))
    def r(apdu): seq_frames.append(("r", apdu))

    m(STARTDT_ACT); r(STARTDT_CON)
    m(i_frame(ns_m, nr_m, asdu(100, 6, 0, qoi_station()))); ns_m += 1          # GI act
    r(i_frame(ns_r, ns_m, asdu(100, 7, 0, qoi_station()))); ns_r += 1          # GI con
    for k in range(3):
        r(i_frame(ns_r, ns_m, asdu(13, 20, 4000 + k, short_float(21.5 + k)))); ns_r += 1
    r(i_frame(ns_r, ns_m, asdu(1, 20, 5000, siq(True)))); ns_r += 1
    r(i_frame(ns_r, ns_m, asdu(100, 10, 0, qoi_station()))); ns_r += 1         # GI termination
    r(i_frame(ns_r, ns_m, asdu(13, 3, 4001, short_float(22.1)))); ns_r += 1    # spontaneous
    r(i_frame(ns_r, ns_m, asdu(1, 3, 5001, siq(False)))); ns_r += 1
    m(i_frame(ns_m, ns_r, asdu(45, 6, 6000, sco(True)))); ns_m += 1            # C_SC command
    r(i_frame(ns_r, ns_m, asdu(45, 7, 6000, sco(True)))); ns_r += 1           # C_SC con
    m(TESTFR_ACT); r(TESTFR_CON)

    seq_m = seq_r = 1
    ack_m = ack_r = 1
    recs = []
    ts = int(time.time())
    for i, (direction, apdu) in enumerate(seq_frames):
        if direction == "m":
            pkt = _eth_ip_tcp(master_ip, rtu_ip, mport, 2404, seq_m, ack_m, apdu)
            seq_m += len(apdu); ack_r = seq_m
        else:
            pkt = _eth_ip_tcp(rtu_ip, master_ip, 2404, mport, seq_r, ack_r, apdu)
            seq_r += len(apdu); ack_m = seq_r
        recs.append((ts, i * 1000, pkt))

    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # global header, Ethernet
        for sec, usec, pkt in recs:
            fh.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
            fh.write(pkt)
    print(f"[demo] wrote {len(recs)} IEC-104 packets to {path} "
          f"({master_ip} <-> {rtu_ip}:2404). Upload it:")
    print(f"[demo]   py -3 sensor/span_sensor.py --once {path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Local IEC 60870-5-104 traffic for SPAN-sensor testing")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2404)
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--pcap", metavar="FILE", help="Write an IEC-104 pcap and exit (no admin/capture needed)")
    a = ap.parse_args()

    if a.pcap:
        return write_pcap(a.pcap)

    stop = threading.Event()
    threading.Thread(target=_server, args=(a.host, a.port, stop), daemon=True).start()
    time.sleep(0.5)
    if stop.is_set():
        return 1
    threading.Thread(target=_client, args=(a.host, a.port, stop), daemon=True).start()

    print(f"[demo] IEC-104 server + client on {a.host}:{a.port} for {a.seconds}s "
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

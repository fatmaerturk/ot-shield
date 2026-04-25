"""
Scenario 01 — Modbus Address-Space Scan (reconnaissance)
========================================================

Generates a pcap that reproduces a burst Modbus scan:
an attacker at 10.20.0.50 (L3, engineering workstation) reads holding
registers (FC 0x03) across a range of addresses on PLC 10.10.2.20 (L1).
The PLC replies with Illegal Data Address (exception code 0x02) for every
probe, exceeding OTShield's ExceptionResponseRule.BURST_THRESHOLD (=5)
and firing a MEDIUM-severity anomaly.

This script depends ONLY on the Python standard library — no scapy needed.
It writes a libpcap-format file (magic 0xa1b2c3d4, nanosec=False so
Wireshark and OTShield's kaitai/pcap4j parsers both accept it).

Usage:
    python3 scenario01_modbus_address_scan.py            # default: burst (200 probes)
    python3 scenario01_modbus_address_scan.py --mode stealth --pps 0.03
    python3 scenario01_modbus_address_scan.py --out /tmp/custom.pcap

Modes:
    burst    — 200 probes @ 100 pps  (triggers the rule → demo "catch")
    stealth  — 20 probes spaced 30s  (stays sub-threshold → demo "gap")
"""
from __future__ import annotations

import argparse
import os
import struct
import time

# --- Lab topology (matches the seeded OTShield assets) -----------------------
ATTACKER_IP = "10.20.0.50"     # engineering workstation, Purdue L3
ATTACKER_MAC = "02:00:00:20:00:50"
PLC_IP = "10.10.2.20"          # Siemens / Modbus PLC, Purdue L1
PLC_MAC = "02:00:00:10:02:20"
MODBUS_PORT = 502
ATTACKER_PORT_BASE = 49152     # ephemeral range start


# --- Packet builders --------------------------------------------------------

def _eth(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype)


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _ip(src_ip: str, dst_ip: str, payload: bytes, ident: int, proto: int = 6) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000   # Don't Fragment
    ttl = 64
    checksum = 0
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ident, flags_frag,
        ttl, proto, checksum,
        _ip_bytes(src_ip), _ip_bytes(dst_ip),
    )
    checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ident, flags_frag,
        ttl, proto, checksum,
        _ip_bytes(src_ip), _ip_bytes(dst_ip),
    )
    return header + payload


def _ip_bytes(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int,
         payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    # Data offset = 5 (20 bytes, no options), window = 65535
    offset_reserved = (5 << 4)
    window = 65535
    checksum = 0
    urg = 0
    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, ack,
        offset_reserved, flags, window,
        checksum, urg,
    )
    # Compute TCP checksum over pseudo-header + header + payload
    pseudo = _ip_bytes(src_ip) + _ip_bytes(dst_ip) + b"\x00\x06" + \
        struct.pack("!H", len(header) + len(payload))
    checksum = _checksum(pseudo + header + payload)
    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        seq, ack,
        offset_reserved, flags, window,
        checksum, urg,
    )
    return header + payload


def _modbus_request(tx_id: int, unit_id: int, fc: int, start_addr: int, qty: int) -> bytes:
    """Modbus TCP request — FC 0x03 Read Holding Registers (6-byte PDU)."""
    pdu = struct.pack("!BHH", fc, start_addr, qty)
    # MBAP header: TxId(2), ProtoId(2)=0, Length(2)=UnitId+PDU, UnitId(1)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _modbus_exception(tx_id: int, unit_id: int, fc: int, exception_code: int) -> bytes:
    """Modbus TCP exception response — FC has high bit set (fc | 0x80)."""
    pdu = struct.pack("!BB", fc | 0x80, exception_code)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


# --- pcap writer ------------------------------------------------------------

def write_pcap(packets: list[tuple[float, bytes]], out_path: str) -> None:
    """Write (timestamp_seconds, ethernet_bytes) tuples to a libpcap file."""
    with open(out_path, "wb") as f:
        # Global header — magic 0xa1b2c3d4 (microsec), LINKTYPE_ETHERNET=1
        f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("!IIII", sec, usec, len(pkt), len(pkt)))
            f.write(pkt)


# --- Scenario builder -------------------------------------------------------

def build_scenario(mode: str, pps: float, probes: int, start_addr: int,
                   include_handshake: bool = True) -> list[tuple[float, bytes]]:
    """Build a packet list (time, eth_frame) for the scan.

    The scan walks holding-register offsets starting at `start_addr`. For each
    probe we emit:
      1. attacker → PLC : Modbus request (FC 0x03, qty=1)
      2. PLC → attacker : Modbus exception 0x02 (Illegal Data Address)

    A minimal SYN/SYN-ACK/ACK handshake is prepended so the pcap looks realistic
    to parsers that care about TCP stream state.
    """
    pkts: list[tuple[float, bytes]] = []
    t0 = time.time() - (probes / pps if pps > 0 else 0)
    src_port = ATTACKER_PORT_BASE + (start_addr & 0x1FFF)
    seq_a = 0x10000000
    seq_p = 0x20000000

    eth_a2p = _eth(ATTACKER_MAC, PLC_MAC)
    eth_p2a = _eth(PLC_MAC, ATTACKER_MAC)

    def ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload, ident):
        tcp = _tcp(sport, dport, seq, ack, flags, payload, src_ip, dst_ip)
        return _ip(src_ip, dst_ip, tcp, ident)

    ident = 1000

    # --- TCP handshake ---
    if include_handshake:
        pkts.append((t0,
                     eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, src_port, MODBUS_PORT,
                                       seq_a, 0, 0x02, b"", ident)))
        ident += 1
        pkts.append((t0 + 0.001,
                     eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP, MODBUS_PORT, src_port,
                                       seq_p, seq_a + 1, 0x12, b"", ident)))
        ident += 1
        pkts.append((t0 + 0.002,
                     eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, src_port, MODBUS_PORT,
                                       seq_a + 1, seq_p + 1, 0x10, b"", ident)))
        ident += 1
        seq_a += 1
        seq_p += 1

    # --- Probe loop ---
    for i in range(probes):
        tx_id = (i + 1) & 0xFFFF
        addr = (start_addr + i) & 0xFFFF
        req = _modbus_request(tx_id=tx_id, unit_id=1, fc=0x03, start_addr=addr, qty=1)
        resp = _modbus_exception(tx_id=tx_id, unit_id=1, fc=0x03, exception_code=0x02)

        t_req = t0 + 0.010 + (i / pps if pps > 0 else i * 0.005)
        t_resp = t_req + 0.0008

        pkts.append((t_req,
                     eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, src_port, MODBUS_PORT,
                                       seq_a, seq_p, 0x18, req, ident)))
        ident += 1
        seq_a += len(req)
        pkts.append((t_resp,
                     eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP, MODBUS_PORT, src_port,
                                       seq_p, seq_a, 0x18, resp, ident)))
        ident += 1
        seq_p += len(resp)

    return pkts


def main() -> None:
    ap = argparse.ArgumentParser(description="Scenario 01 — Modbus Address-Space Scan pcap generator")
    ap.add_argument("--mode", choices=["burst", "stealth"], default="burst",
                    help="burst = 200 probes @ 100 pps (triggers rule); stealth = 20 probes @ 0.03 pps")
    ap.add_argument("--pps", type=float, default=None, help="probes per second (override)")
    ap.add_argument("--probes", type=int, default=None, help="number of probes (override)")
    ap.add_argument("--start-addr", type=int, default=0x0000, help="first register address")
    ap.add_argument("--out", default=None, help="output pcap path")
    args = ap.parse_args()

    if args.mode == "burst":
        pps = args.pps if args.pps is not None else 100.0
        probes = args.probes if args.probes is not None else 200
        default_name = "scenario01_modbus_scan_burst.pcap"
    else:
        pps = args.pps if args.pps is not None else 0.03
        probes = args.probes if args.probes is not None else 20
        default_name = "scenario01_modbus_scan_stealth.pcap"

    out = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   default_name)
    pkts = build_scenario(mode=args.mode, pps=pps, probes=probes,
                          start_addr=args.start_addr)
    write_pcap(pkts, out)
    size = os.path.getsize(out)
    dur = pkts[-1][0] - pkts[0][0] if len(pkts) > 1 else 0
    print(f"wrote {out}")
    print(f"  mode     = {args.mode}")
    print(f"  probes   = {probes}")
    print(f"  pps      = {pps}")
    print(f"  packets  = {len(pkts)}  (handshake + 2×probes)")
    print(f"  duration = {dur:.2f}s")
    print(f"  size     = {size} bytes")
    print(f"  src      = {ATTACKER_IP}:{ATTACKER_PORT_BASE}")
    print(f"  dst      = {PLC_IP}:{MODBUS_PORT}")
    print(f"  fc       = 0x03 (Read Holding Registers)")
    print(f"  exc      = 0x02 (Illegal Data Address) on every response")


if __name__ == "__main__":
    main()

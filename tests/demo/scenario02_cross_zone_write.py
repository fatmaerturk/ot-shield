"""
Scenario 02 — Cross-Zone Unauthorized Write (IT → PLC)
=======================================================

An attacker at 10.20.0.50 (Purdue L3, engineering workstation) pushes a Modbus
Write Single Register (FC 0x06) into PLC 10.10.2.20 (Purdue L1). A write that
crosses two Purdue levels is the canonical "this is very bad" ICS attack — it
tampers with a setpoint (pump speed, valve position, motor torque) from outside
the control zone, bypassing both the HMI operator and the zone firewall.

Expected OTShield detection:
  • Rule     : dpi.unauthorized_write
  • Severity : CRITICAL   (srcLvl ≥ 3 AND dstLvl ≤ 1 branch)
  • MITRE    : T0855 (Unauthorized Command Message)
  • Evidence : 1 (or N) write PDU(s) from L3 host → L1 host, FC 0x06
  • Indicators: rule:dpi.unauthorized_write, src_level:L3, dst_level:L1,
                write_count:N
  • Topology : 10.20.0.50 → 10.10.2.20 edge flips RED with MODBUS label

Usage:
    python3 scenario02_cross_zone_write.py                # default: 1 write
    python3 scenario02_cross_zone_write.py --writes 5     # 5 repeated writes
    python3 scenario02_cross_zone_write.py --fc 0x10      # use Write Multiple
    python3 scenario02_cross_zone_write.py --reg 40001 --value 9999

Standard library only — no scapy dependency (proxy blocks installs).
"""
from __future__ import annotations

import argparse
import os
import struct
import time

# --- Lab topology (matches seeded OTShield assets) --------------------------
ATTACKER_IP = "10.20.0.50"     # engineering workstation, Purdue L3
ATTACKER_MAC = "02:00:00:20:00:50"
PLC_IP = "10.10.2.20"          # PLC, Purdue L1
PLC_MAC = "02:00:00:10:02:20"
MODBUS_PORT = 502
ATTACKER_PORT = 51820


# --- Ethernet / IP / TCP helpers --------------------------------------------

def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _eth(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype)


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


def _ip(src_ip: str, dst_ip: str, payload: bytes, ident: int, proto: int = 6) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len,
        ident, 0x4000,
        64, proto, 0,
        _ip_bytes(src_ip), _ip_bytes(dst_ip),
    )
    csum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len,
        ident, 0x4000,
        64, proto, csum,
        _ip_bytes(src_ip), _ip_bytes(dst_ip),
    )
    return header + payload


def _tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int,
         payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        0x50, flags, 65535, 0, 0,
    )
    pseudo = (_ip_bytes(src_ip) + _ip_bytes(dst_ip)
              + b"\x00\x06" + struct.pack("!H", len(header) + len(payload)))
    csum = _checksum(pseudo + header + payload)
    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack,
        0x50, flags, 65535, csum, 0,
    )
    return header + payload


# --- Modbus PDUs ------------------------------------------------------------

def _modbus_write_single_register_req(tx_id: int, unit_id: int, addr: int, val: int) -> bytes:
    """FC 0x06 — Write Single Register (6-byte PDU)."""
    pdu = struct.pack("!BHH", 0x06, addr & 0xFFFF, val & 0xFFFF)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _modbus_write_single_register_resp(tx_id: int, unit_id: int, addr: int, val: int) -> bytes:
    """FC 0x06 — echo of request on success."""
    return _modbus_write_single_register_req(tx_id, unit_id, addr, val)


def _modbus_write_multiple_registers_req(tx_id: int, unit_id: int, addr: int, values: list[int]) -> bytes:
    """FC 0x10 — Write Multiple Registers."""
    qty = len(values)
    byte_count = qty * 2
    pdu = struct.pack("!BHHB", 0x10, addr & 0xFFFF, qty, byte_count)
    for v in values:
        pdu += struct.pack("!H", v & 0xFFFF)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _modbus_write_multiple_registers_resp(tx_id: int, unit_id: int, addr: int, qty: int) -> bytes:
    """FC 0x10 response — echoes address + quantity only."""
    pdu = struct.pack("!BHH", 0x10, addr & 0xFFFF, qty & 0xFFFF)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


# --- pcap writer ------------------------------------------------------------

def write_pcap(packets: list[tuple[float, bytes]], out_path: str) -> None:
    with open(out_path, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("!IIII", sec, usec, len(pkt), len(pkt)))
            f.write(pkt)


# --- Scenario builder -------------------------------------------------------

def build_scenario(fc: int, writes: int, reg: int, value: int,
                   values: list[int] | None) -> list[tuple[float, bytes]]:
    """Construct the full packet sequence: TCP handshake, N write PDUs + echoes."""
    pkts: list[tuple[float, bytes]] = []
    t0 = time.time() - 5.0   # place packets slightly in the past for determinism
    eth_a2p = _eth(ATTACKER_MAC, PLC_MAC)
    eth_p2a = _eth(PLC_MAC, ATTACKER_MAC)

    seq_a = 0x30000000
    seq_p = 0x40000000
    ident = 2000

    def ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload, ident_):
        return _ip(src_ip, dst_ip, _tcp(sport, dport, seq, ack, flags, payload, src_ip, dst_ip), ident_)

    # --- TCP handshake ---
    pkts.append((t0,
                 eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, ATTACKER_PORT, MODBUS_PORT,
                                  seq_a, 0, 0x02, b"", ident)))
    ident += 1
    pkts.append((t0 + 0.0008,
                 eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP, MODBUS_PORT, ATTACKER_PORT,
                                  seq_p, seq_a + 1, 0x12, b"", ident)))
    ident += 1
    pkts.append((t0 + 0.0016,
                 eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, ATTACKER_PORT, MODBUS_PORT,
                                  seq_a + 1, seq_p + 1, 0x10, b"", ident)))
    ident += 1
    seq_a += 1
    seq_p += 1

    # --- Write loop ---
    for i in range(writes):
        tx_id = (i + 1) & 0xFFFF
        if fc == 0x06:
            req = _modbus_write_single_register_req(tx_id, 1, reg, value)
            resp = _modbus_write_single_register_resp(tx_id, 1, reg, value)
        elif fc == 0x10:
            vals = values or [value] * 4
            req = _modbus_write_multiple_registers_req(tx_id, 1, reg, vals)
            resp = _modbus_write_multiple_registers_resp(tx_id, 1, reg, len(vals))
        else:
            raise SystemExit(f"unsupported FC {fc:#04x} (use 0x06 or 0x10)")

        t_req = t0 + 0.010 + i * 0.200     # 200 ms between writes — very visible, not a burst
        t_resp = t_req + 0.0008

        pkts.append((t_req,
                     eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP, ATTACKER_PORT, MODBUS_PORT,
                                      seq_a, seq_p, 0x18, req, ident)))
        ident += 1
        seq_a += len(req)
        pkts.append((t_resp,
                     eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP, MODBUS_PORT, ATTACKER_PORT,
                                      seq_p, seq_a, 0x18, resp, ident)))
        ident += 1
        seq_p += len(resp)

    return pkts


def _parse_hex_int(s: str) -> int:
    return int(s, 0)  # accepts 0x06, 6, 0b0110 etc.


def main() -> None:
    ap = argparse.ArgumentParser(description="Scenario 02 — Cross-Zone Unauthorized Write pcap generator")
    ap.add_argument("--fc", type=_parse_hex_int, default=0x06,
                    help="function code (0x06 Write Single Register or 0x10 Write Multiple Registers)")
    ap.add_argument("--writes", type=int, default=1,
                    help="number of write PDUs (default 1 — a single unambiguous write is enough)")
    ap.add_argument("--reg", type=int, default=40001,
                    help="register address to write (default 40001 — canonical holding register)")
    ap.add_argument("--value", type=int, default=9999,
                    help="value to write (default 9999 — obvious tampered setpoint)")
    ap.add_argument("--values", type=str, default=None,
                    help="comma-separated values for FC 0x10 (e.g. '9999,1,0,4242')")
    ap.add_argument("--out", default=None, help="output pcap path")
    args = ap.parse_args()

    values = None
    if args.values:
        values = [int(x.strip(), 0) for x in args.values.split(",")]

    if args.fc not in (0x06, 0x10):
        raise SystemExit(f"unsupported --fc {args.fc:#04x}; use 0x06 or 0x10")

    default_name = f"scenario02_cross_zone_write_fc{args.fc:02x}.pcap"
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), default_name)

    pkts = build_scenario(fc=args.fc, writes=args.writes, reg=args.reg,
                          value=args.value, values=values)
    write_pcap(pkts, out)
    size = os.path.getsize(out)
    dur = pkts[-1][0] - pkts[0][0] if len(pkts) > 1 else 0
    fc_name = {0x06: "Write Single Register", 0x10: "Write Multiple Registers"}[args.fc]
    print(f"wrote {out}")
    print(f"  src      = {ATTACKER_IP}:{ATTACKER_PORT}  (L3, engineering workstation)")
    print(f"  dst      = {PLC_IP}:{MODBUS_PORT}  (L1, PLC)")
    print(f"  fc       = {args.fc:#04x} ({fc_name})")
    print(f"  reg      = {args.reg}")
    if args.fc == 0x06:
        print(f"  value    = {args.value}")
    else:
        print(f"  values   = {values or [args.value] * 4}")
    print(f"  writes   = {args.writes}")
    print(f"  packets  = {len(pkts)}  (handshake + 2×writes)")
    print(f"  duration = {dur:.3f}s")
    print(f"  size     = {size} bytes")
    print(f"  expected : dpi.unauthorized_write CRITICAL (L3 → L1)")


if __name__ == "__main__":
    main()

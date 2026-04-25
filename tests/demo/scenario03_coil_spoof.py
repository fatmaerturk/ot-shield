"""
Scenario 03 — Coil-Spoof to Falsify Safety State
================================================

An attacker that has already lived-off-the-land on an HMI at 10.10.1.10
(Purdue L2) issues Modbus Force Single Coil (FC 0x05) writes into PLC
10.10.2.20 (Purdue L1). Two coils are flipped:

    coil 17  — safety interlock (should be 0 while door open)
    coil 33  — "pump running" HMI status indicator

The result is a desync between operator view and field state: the HMI
reports a happy, running, interlocked process while the actual machinery
disagrees. This is the "Manipulation of View" class of attack famously
used in the 2015 Ukraine grid incident.

Unlike scenario 02 (cross-zone L3 → L1 register write), scenario 03 is
an *in-zone-ish* L2 → L1 write — the attacker is already inside the
control zone. OTShield's UnauthorizedWriteRule still fires because
srcLvl (2) > dstLvl (1), but at HIGH severity rather than CRITICAL
(delta = 1, no L3→L1 jump). The deeper gap — a value-baseline /
tag-dictionary rule that understands *which coil* is safety-critical —
is intentionally not yet implemented and is documented in the demo
DOCX's gap-analysis section.

Expected OTShield detection:
  • Rule     : dpi.unauthorized_write
  • Severity : HIGH      (L2 → L1, delta = 1)
  • MITRE    : T0832 (Manipulation of View, mapped via T0855 rule)
  • Evidence : 2 write PDU(s) from L2 host → L1 host, FC 0x05
  • Indicators: rule:dpi.unauthorized_write, src_level:L2, dst_level:L1,
                write_count:2
  • Topology : 10.10.1.10 → 10.10.2.20 edge flips ORANGE/RED with MODBUS

Usage:
    python3 scenario03_coil_spoof.py                       # 2 single-coil writes (default)
    python3 scenario03_coil_spoof.py --fc 0x0f             # Force Multiple Coils variant
    python3 scenario03_coil_spoof.py --coils 17,33,41      # custom coil addresses
    python3 scenario03_coil_spoof.py --repeat 5            # loop the write sequence 5×

Standard library only — no scapy dependency (proxy blocks installs).
"""
from __future__ import annotations

import argparse
import os
import struct
import time

# --- Lab topology (matches seeded OTShield assets) --------------------------
ATTACKER_IP = "10.10.1.10"     # HMI (compromised), Purdue L2
ATTACKER_MAC = "02:00:00:10:01:10"
PLC_IP = "10.10.2.20"          # PLC, Purdue L1
PLC_MAC = "02:00:00:10:02:20"
MODBUS_PORT = 502
ATTACKER_PORT = 49920

# Canonical coils for the demo. Keep these at "obviously interesting" low
# addresses so the walkthrough reads naturally in a presentation.
DEFAULT_COILS = [17, 33]
COIL_LABELS = {
    17: "SAFETY_INTERLOCK",
    33: "PUMP_RUNNING_INDICATOR",
}


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

def _modbus_write_single_coil_req(tx_id: int, unit_id: int, addr: int, on: bool) -> bytes:
    """FC 0x05 — Force Single Coil. value = 0xFF00 for ON, 0x0000 for OFF."""
    val = 0xFF00 if on else 0x0000
    pdu = struct.pack("!BHH", 0x05, addr & 0xFFFF, val)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _modbus_write_single_coil_resp(tx_id: int, unit_id: int, addr: int, on: bool) -> bytes:
    """FC 0x05 — echoes the request on success."""
    return _modbus_write_single_coil_req(tx_id, unit_id, addr, on)


def _modbus_write_multiple_coils_req(tx_id: int, unit_id: int, addr: int, bits: list[bool]) -> bytes:
    """FC 0x0F — Force Multiple Coils. Bits packed LSB-first per byte."""
    qty = len(bits)
    byte_count = (qty + 7) // 8
    packed = bytearray(byte_count)
    for i, b in enumerate(bits):
        if b:
            packed[i // 8] |= (1 << (i % 8))
    pdu = struct.pack("!BHHB", 0x0F, addr & 0xFFFF, qty, byte_count) + bytes(packed)
    mbap = struct.pack("!HHHB", tx_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def _modbus_write_multiple_coils_resp(tx_id: int, unit_id: int, addr: int, qty: int) -> bytes:
    """FC 0x0F response — echoes start address + quantity only."""
    pdu = struct.pack("!BHH", 0x0F, addr & 0xFFFF, qty & 0xFFFF)
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

def build_scenario(fc: int, coils: list[int], repeat: int) -> list[tuple[float, bytes]]:
    """Construct full sequence: TCP handshake, then one write PDU per coil,
    optionally repeated `repeat` times to produce a more visible burst."""
    pkts: list[tuple[float, bytes]] = []
    t0 = time.time() - 5.0
    eth_a2p = _eth(ATTACKER_MAC, PLC_MAC)
    eth_p2a = _eth(PLC_MAC, ATTACKER_MAC)

    seq_a = 0x50000000
    seq_p = 0x60000000
    ident = 3000

    def ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload, ident_):
        return _ip(src_ip, dst_ip,
                   _tcp(sport, dport, seq, ack, flags, payload, src_ip, dst_ip),
                   ident_)

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
    tx_id = 0
    write_idx = 0
    for r in range(repeat):
        if fc == 0x05:
            for coil in coils:
                tx_id = (tx_id + 1) & 0xFFFF
                req = _modbus_write_single_coil_req(tx_id, 1, coil, True)
                resp = _modbus_write_single_coil_resp(tx_id, 1, coil, True)
                t_req = t0 + 0.010 + write_idx * 0.180
                t_resp = t_req + 0.0008
                pkts.append((t_req,
                             eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP,
                                              ATTACKER_PORT, MODBUS_PORT,
                                              seq_a, seq_p, 0x18, req, ident)))
                ident += 1
                seq_a += len(req)
                pkts.append((t_resp,
                             eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP,
                                              MODBUS_PORT, ATTACKER_PORT,
                                              seq_p, seq_a, 0x18, resp, ident)))
                ident += 1
                seq_p += len(resp)
                write_idx += 1
        elif fc == 0x0F:
            # Pack all requested coils into a single FC 0x0F PDU (all set ON).
            tx_id = (tx_id + 1) & 0xFFFF
            start = min(coils)
            span = max(coils) - start + 1
            bits = [False] * span
            for c in coils:
                bits[c - start] = True
            req = _modbus_write_multiple_coils_req(tx_id, 1, start, bits)
            resp = _modbus_write_multiple_coils_resp(tx_id, 1, start, span)
            t_req = t0 + 0.010 + write_idx * 0.180
            t_resp = t_req + 0.0008
            pkts.append((t_req,
                         eth_a2p + ip_tcp(ATTACKER_IP, PLC_IP,
                                          ATTACKER_PORT, MODBUS_PORT,
                                          seq_a, seq_p, 0x18, req, ident)))
            ident += 1
            seq_a += len(req)
            pkts.append((t_resp,
                         eth_p2a + ip_tcp(PLC_IP, ATTACKER_IP,
                                          MODBUS_PORT, ATTACKER_PORT,
                                          seq_p, seq_a, 0x18, resp, ident)))
            ident += 1
            seq_p += len(resp)
            write_idx += 1
        else:
            raise SystemExit(f"unsupported FC {fc:#04x}; use 0x05 or 0x0F")

    return pkts


def _parse_hex_int(s: str) -> int:
    return int(s, 0)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Scenario 03 — Coil-spoof to falsify safety state pcap generator")
    ap.add_argument("--fc", type=_parse_hex_int, default=0x05,
                    help="function code (0x05 Force Single Coil or 0x0F Force Multiple Coils)")
    ap.add_argument("--coils", type=str, default=",".join(str(c) for c in DEFAULT_COILS),
                    help="comma-separated coil addresses (default: 17,33)")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the write sequence N times (default 1)")
    ap.add_argument("--out", default=None, help="output pcap path")
    args = ap.parse_args()

    try:
        coils = [int(x.strip(), 0) for x in args.coils.split(",") if x.strip()]
    except ValueError as e:
        raise SystemExit(f"invalid --coils: {e}")
    if not coils:
        raise SystemExit("at least one coil address required")

    if args.fc not in (0x05, 0x0F):
        raise SystemExit(f"unsupported --fc {args.fc:#04x}; use 0x05 or 0x0F")

    default_name = f"scenario03_coil_spoof_fc{args.fc:02x}.pcap"
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), default_name)

    pkts = build_scenario(fc=args.fc, coils=coils, repeat=args.repeat)
    write_pcap(pkts, out)
    size = os.path.getsize(out)
    dur = pkts[-1][0] - pkts[0][0] if len(pkts) > 1 else 0
    fc_name = {0x05: "Force Single Coil", 0x0F: "Force Multiple Coils"}[args.fc]
    print(f"wrote {out}")
    print(f"  src      = {ATTACKER_IP}:{ATTACKER_PORT}  (L2, HMI)")
    print(f"  dst      = {PLC_IP}:{MODBUS_PORT}  (L1, PLC)")
    print(f"  fc       = {args.fc:#04x} ({fc_name})")
    labelled = ", ".join(f"{c}({COIL_LABELS.get(c, 'coil')})" for c in coils)
    print(f"  coils    = {labelled}")
    print(f"  repeat   = {args.repeat}")
    print(f"  packets  = {len(pkts)}  (handshake + 2 per write)")
    print(f"  duration = {dur:.3f}s")
    print(f"  size     = {size} bytes")
    print(f"  expected : dpi.unauthorized_write HIGH (L2 → L1, delta=1)")
    print(f"             title 'Unauthorized cross-zone write (L2 → L1)'")
    print(f"             gap  : value-baseline / tag-dictionary rule not yet implemented")


if __name__ == "__main__":
    main()

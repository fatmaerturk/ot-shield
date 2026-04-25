"""Quick raw-decoder for scenario 03 pcaps.

Walks the pcap, finds Modbus request packets (Ethernet / IP / TCP / Modbus),
and prints (fc, coil_addr, value) for each request — no scapy needed.
"""
import os
import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scenario03_coil_spoof_fc05.pcap",
)


def parse_pcap(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise SystemExit("pcap too small")
    magic = struct.unpack("!I", data[0:4])[0]
    if magic != 0xa1b2c3d4:
        raise SystemExit(f"unexpected magic {magic:#x}")
    off = 24
    while off + 16 <= len(data):
        sec, usec, caplen, _origlen = struct.unpack("!IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        yield sec + usec / 1_000_000, pkt


def decode(path: str) -> None:
    print(f"== {os.path.basename(path)} ==")
    for ts, pkt in parse_pcap(path):
        if len(pkt) < 14 + 20 + 20:
            continue
        ip = pkt[14:34]
        if ip[9] != 6:  # not TCP
            continue
        ihl = (ip[0] & 0x0F) * 4
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        tcp = pkt[14 + ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[0:4])
        data_off = (tcp[12] >> 4) * 4
        payload = tcp[data_off:]
        if not payload or len(payload) < 8:
            continue
        # MBAP: tid(2) proto(2) len(2) uid(1) | fc(1) ...
        tid, proto, mlen, uid = struct.unpack("!HHHB", payload[0:7])
        if proto != 0:
            continue
        fc = payload[7]
        descr = ""
        if fc == 0x05 and len(payload) >= 12:  # write single coil request
            addr, val = struct.unpack("!HH", payload[8:12])
            descr = f"FC=0x05 WriteSingleCoil addr={addr} val={val:#06x} ({'ON' if val == 0xFF00 else 'OFF'})"
        elif fc == 0x0F and len(payload) >= 13:  # write multiple coils request
            addr, qty, bcount = struct.unpack("!HHB", payload[8:13])
            bits = payload[13:13 + bcount]
            descr = f"FC=0x0F WriteMultipleCoils addr={addr} qty={qty} bytes={bits.hex()}"
        else:
            descr = f"FC={fc:#04x} (other)"
        print(f"  t={ts:.3f}  {src}:{sport:>5} -> {dst}:{dport:<5}  tid={tid}  {descr}")


if __name__ == "__main__":
    decode(PATH)
    fc0f = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "scenario03_coil_spoof_fc0f.pcap")
    if os.path.exists(fc0f):
        print()
        decode(fc0f)

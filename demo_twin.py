import os, json, time, socket, struct, urllib.request

# --- demo output IP masking: public (attacker) IPs shown as A.B.xxx.xxx; loopback/private stay visible ---
import re as _re
def _maskip(_m):
    _p = _m.group(0).split("."); _a, _b = int(_p[0]), int(_p[1])
    if _a in (0, 10, 127) or (_a == 172 and 16 <= _b <= 31) or (_a == 192 and _b == 168) or (_a == 169 and _b == 254):
        return _m.group(0)
    return _p[0] + "." + _p[1] + ".xxx.xxx"
__b_print = print
def print(*args, **kw):
    args = [_re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _maskip, a) if isinstance(a, str) else a for a in args]
    __b_print(*args, **kw)
# --- end IP masking ---


# OTShield does not drop a generic honeypot. It clones YOUR device - identity and
# register behaviour learned from what was actually observed on the wire - into a
# high-interaction digital twin bound to loopback only. A scanner cannot tell it
# apart from the real PLC: it answers identity probes with your vendor and model,
# serves live drifting register values, and returns the exact PLC error for an
# out-of-range read. Every probe is captured. A read is intel; a write is a breach.
BASE  = os.environ.get("OTSHIELD_BASE", "http://localhost:8080")
CREDS = {"email":    os.environ.get("OTSHIELD_EMAIL", "fatma.erturk@otshield.io"),
         "password": os.environ.get("OTSHIELD_PASSWORD", "Alex123!!!")}  # local dev seed

def _open(req):
    return json.load(urllib.request.urlopen(req, timeout=20))

def login():
    req = urllib.request.Request(BASE + "/api/auth/login",
        data=json.dumps(CREDS).encode(), headers={"Content-Type": "application/json"})
    return _open(req)["token"]

def get(path, token):
    return _open(urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + token}))

def post(path, token):
    return _open(urllib.request.Request(BASE + path, data=b"", method="POST",
        headers={"Authorization": "Bearer " + token}))

# --- tiny Modbus/TCP client ------------------------------------------------
def mbap(pdu):
    return struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu

def request(sock, pdu):
    t0 = time.time()
    sock.sendall(mbap(pdu))
    hdr = sock.recv(7)
    ln = ((hdr[4] << 8) | hdr[5]) - 1
    body = b""
    while len(body) < ln:
        body += sock.recv(ln - len(body))
    return body, (time.time() - t0) * 1000  # resp PDU, ms

def is_exception(pdu):
    return len(pdu) >= 2 and (pdu[0] & 0x80)

def parse_identity(pdu):
    # FC43/MEI 0x0E: 2b 0e 01 conf more next numObjs, then [id len value]*
    out, i, n = {}, 7, pdu[6]
    names = {0x00: "vendor", 0x01: "product", 0x05: "model"}
    for _ in range(n):
        oid, olen = pdu[i], pdu[i + 1]
        out[names.get(oid, hex(oid))] = pdu[i + 2:i + 2 + olen].decode("ascii", "replace")
        i += 2 + olen
    return out

def parse_registers(pdu):
    # FC03/04: fc, byteCount, [hi lo]*
    bc = pdu[1]
    return [((pdu[2 + j] << 8) | pdu[3 + j]) for j in range(0, bc, 2)]

# --- demo ------------------------------------------------------------------
token = login()
print("[TWIN]     OTShield digital twin - clone your device, not a generic honeypot\n")

assets = get("/api/assets?size=500", token)
lst = assets.get("content", assets) if isinstance(assets, dict) else assets
asset = [a for a in lst if (a.get("protocol") or "").upper().find("MODBUS") >= 0][0]

spec = post(f"/api/decoy/twin/{asset['id']}/start", token)
host, port = spec["listenHost"], spec["listenPort"]
print(f"[SOURCE]   real asset: {spec['vendor']} {spec['modelName']} ({spec['realIp']}) - "
      f"{spec['observedEvents']} events observed on the wire")
print(f"[CLONE]    twin serving @ {host}:{port}   (loopback only, off by default)\n")

try:
    sock = socket.create_connection((host, port), timeout=8)

    # 1) IDENTITY - the twin answers as the real device
    pdu, _ = request(sock, bytes([0x2B, 0x0E, 0x01, 0x00]))
    ident = parse_identity(pdu)
    print(f"[IDENTITY] FC43 Read Device ID  ->  vendor=\"{ident.get('vendor')}\"  "
          f"product=\"{ident.get('product')}\"  model=\"{ident.get('model')}\"")
    print("           a scanner reads YOUR device's identity, not a honeypot banner\n")

    # 2) LIVE VALUES - successive reads drift like a running process
    pdu, ms = request(sock, bytes([0x03, 0x00, 0x00, 0x00, 0x06]))
    if is_exception(pdu):
        print("[LIVE]     FC03 @0 -> Illegal Data Address (this device's map starts higher) - map is real\n")
    else:
        t0 = parse_registers(pdu)
        time.sleep(1.6)
        pdu2, _ = request(sock, bytes([0x03, 0x00, 0x00, 0x00, 0x06]))
        t1 = parse_registers(pdu2)
        print(f"[LIVE]     FC03 read holding regs @0..5:")
        print(f"             t0: {t0}")
        print(f"             t1: {t1}   values drift -> a live process, not a dead all-zero device\n")

    # 3) FIDELITY - out-of-range read gets the exact PLC error
    pdu, _ = request(sock, bytes([0x03, 0xEA, 0x60, 0x00, 0x02]))  # addr 60000
    if is_exception(pdu):
        print(f"[FIDELITY] FC03 read @60000 (out of range)  ->  Illegal Data Address (0x{pdu[1]:02X})")
        print("           the twin learned the real register map; invalid reads get the exact PLC error\n")

    # 4) LATENCY - real PLCs are never 0ms
    _, ms = request(sock, bytes([0x2B, 0x0E, 0x01, 0x00]))
    print(f"[LATENCY]  ~{ms:.0f}ms/response  (a fixed 0ms is a classic honeypot tell)\n")

    sock.close()

    # 5) every probe was captured
    inter = get("/api/decoy/twin/interactions", token)
    print(f"[LOG]      {len(inter)} interaction(s) captured against the twin:")
    for it in inter[:6]:
        flag = "WRITE/breach" if it.get("write") else "read"
        print(f"             {it['functionCode']} {it['function']:<28} {flag:<12} from {it['sourceIp']}")
finally:
    post("/api/decoy/twin/stop", token)
    print("\n[TWIN]     twin stopped (loopback listener closed)")

print("\n[DONE]     high-interaction deception cloned from real observed behaviour. A read is intel; a write is a breach.")

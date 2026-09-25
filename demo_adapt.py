import os, json, time, socket, urllib.request

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


# OTShield does not just DETECT a breach, it SELF-HEALS. This closes the deception
# loop's weakest stage - ADAPT. We clone a real Modbus asset into a loopback-only
# decoy twin, then write to it. No legitimate actor ever writes to a decoy, so that
# write is a false-positive-free breach - and the instant it lands the platform
# reacts on its own: expands the decoy fabric, flags the attacker at the OT boundary,
# and rotates in a fresh honeytoken. Every action is a real platform primitive.
BASE  = os.environ.get("OTSHIELD_BASE", "http://localhost:8080")
CREDS = {"email":    os.environ.get("OTSHIELD_EMAIL", "fatma.erturk@otshield.io"),
         "password": os.environ.get("OTSHIELD_PASSWORD", "Alex123!!!")}  # local dev seed
WRITE_PDU = bytes.fromhex("0001000000060106000000ff")  # Modbus FC06  reg[0] = 0x00FF

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

token = login()
print("[LOOP]     OTShield deception loop, closing the ADAPT stage (breach -> self-heal)\n")

# 1) pick a real Modbus asset from the discovered inventory - the twin clones THIS device
assets = get("/api/assets?size=500", token)
lst = assets.get("content", assets) if isinstance(assets, dict) else assets
modbus = [a for a in lst if (a.get("protocol") or "").upper().find("MODBUS") >= 0]
asset = modbus[0]
print(f"[ASSET]    {asset['name']}  ({asset['ipAddress']}, {asset.get('assetType')})  real Modbus device on the inventory")

before = get("/api/decoy/adaptations/stats", token)
top_before = get("/api/decoy/adaptations?limit=1", token)
last_id = top_before[0]["id"] if top_before else None
print(f"[BEFORE]   adaptations={before['totalAdaptations']}  decoys+{before['decoysExpanded']}  "
      f"blocks+{before['attackersBlocked']}  tokens+{before['honeytokensPlanted']}\n")

# 2) clone it into a loopback-only decoy twin (bind 127.0.0.1 only - the safety control)
spec = post(f"/api/decoy/twin/{asset['id']}/start", token)
host, port = spec["listenHost"], spec["listenPort"]
print(f"[TWIN]     cloned -> decoy twin of {spec['vendor']} {spec['modelName']} @ {host}:{port}  (loopback only)")

try:
    # 3) the breach: a Modbus WRITE against the decoy twin
    print(f"[BREACH]   Modbus WRITE  ->  {host}:{port}   (FC06, reg[0]=0x00FF - no legit actor writes to a decoy)")
    print(f"[WIRE]     {WRITE_PDU.hex(' ')}")
    t0 = time.time()
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(WRITE_PDU)
    try: s.recv(64)
    except Exception: pass
    s.close()

    # 4) watch the platform self-heal, autonomously
    ev = None
    for _ in range(20):
        top = get("/api/decoy/adaptations?limit=1", token)
        if top and top[0]["id"] != last_id:
            ev = top[0]; break
        time.sleep(0.4)
    dt = int((time.time() - t0) * 1000)

    if ev is None:
        print("\n[SELF-HEAL] no new adaptation - most likely the 5-min per-attacker+asset dedup window")
        print("            (already self-healed for this source recently). Re-run after 5 min or on another asset.")
    else:
        print(f"\n[SELF-HEAL] platform reacted autonomously in {dt}ms - trigger {ev['trigger']} from {ev['sourceIp']}:")
        for a in ev["actions"]:
            mark = "+" if a["success"] else "x"
            print(f"   [{mark}] {a['type']:<18} {a['detail']}")

    after = get("/api/decoy/adaptations/stats", token)
    print(f"\n[AFTER]    adaptations={after['totalAdaptations']}  decoys+{after['decoysExpanded']}  "
          f"blocks+{after['attackersBlocked']}  tokens+{after['honeytokensPlanted']}")
finally:
    # 5) tear the twin down - it was only up for the demo
    post("/api/decoy/twin/stop", token)
    print("[TWIN]     twin stopped (loopback listener closed)")

print("\n[DONE]     breach to self-heal, no human in the loop, every action a real platform primitive.")

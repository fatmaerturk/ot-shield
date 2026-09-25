import os, json, urllib.request

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


# OTShield does not just consume threat intel, it PRODUCES it: every attacker that
# engages the decoy fabric becomes a first-party, OT-specific IOC, published as a
# live STIX 2.1 feed you can share with your SIEM, ISAC, or TAXII server.
BASE  = os.environ.get("OTSHIELD_BASE", "http://localhost:8080")
CREDS = {"email":    os.environ.get("OTSHIELD_EMAIL", "fatma.erturk@otshield.io"),
         "password": os.environ.get("OTSHIELD_PASSWORD", "Alex123@@@")}  # local dev seed

def _open(req):
    return json.load(urllib.request.urlopen(req, timeout=15))

def login():
    req = urllib.request.Request(BASE + "/api/auth/login",
        data=json.dumps(CREDS).encode(), headers={"Content-Type": "application/json"})
    return _open(req)["token"]

def get(path, token):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + token})
    return _open(req)

token = login()

s = get("/api/threat-intel/feed/summary", token)
print("[FEED]  First-party OT threat intelligence, live")
print(f"        produced IOCs: {s['producedIocs']}    high-risk: {s['highRisk']}    countries: {s['countries']}")
print(f"        protocols: {', '.join(s['protocols'])}")
print(f"        formats: {', '.join(s['formats'])}    URL: {BASE}{s['feedUrl']}\n")

b = get("/api/threat-intel/feed", token)
inds = [o for o in b.get("objects", []) if o.get("type") == "indicator"]
print(f"[STIX]  bundle spec_version {b.get('spec_version')}, {len(inds)} indicators. Sample:\n")
for o in inds[:3]:
    print(f"        {o['pattern']}")
    print(f"          {o['description']}")
    print(f"          labels: {', '.join(o.get('labels', []))}   confidence: {o.get('confidence')}\n")

print("[DONE]  one URL, standard STIX 2.1. Share it with your SIEM, ISAC or TAXII. Intel nobody else has.")

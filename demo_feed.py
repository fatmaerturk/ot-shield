import os, json, urllib.request

# OTShield does not just consume threat intel, it PRODUCES it: every attacker that
# engages the decoy fabric becomes a first-party, OT-specific IOC, published as a
# live STIX 2.1 feed you can share with your SIEM, ISAC, or TAXII server.
BASE  = "http://localhost:8080"
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

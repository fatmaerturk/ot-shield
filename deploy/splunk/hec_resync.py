#!/usr/bin/env python3
# Timestamp-preserving re-sync of the OTShield honeypot corpus -> Splunk HEC.
#
# Pulls /api/honeypot/logs (paginated), renders CEF byte-for-byte like
# SiemForwarderService.renderCef/fromHoneypot, and POSTs to HEC /event with each
# event's REAL timestamp (explicit `time`) so Splunk mirrors OTShield's true
# timeline instead of squashing the whole corpus onto ingest-day.
#
# Designed to run INSIDE the splunk container (it bundles python3):
#   docker compose cp deploy/splunk/hec_resync.py splunk:/tmp/hec_resync.py
#   docker compose exec -e HEC_TOKEN=$SPLUNK_HEC_TOKEN splunk \
#       /opt/splunk/bin/python3 /tmp/hec_resync.py
# From there OTSHIELD defaults to the in-network backend and HEC to localhost.
import json, ssl, os, urllib.request, urllib.error, time
from datetime import datetime

OTSHIELD  = os.environ.get("OTSHIELD_URL", "http://backend:8080")
HEC_URL   = os.environ.get("HEC_URL", "https://127.0.0.1:8088/services/collector/event")
HEC_TOKEN = os.environ.get("HEC_TOKEN", "")
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "1000"))
BATCH     = int(os.environ.get("BATCH", "500"))     # events per HEC POST
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

def cef_header(v):   # escape backslash + pipe
    if v is None: return ""
    return v.replace("\\","\\\\").replace("|","\\|").replace("\n"," ").replace("\r"," ")
def cef_value(v):    # escape backslash + equals + newline
    if v is None: return ""
    return str(v).replace("\\","\\\\").replace("=","\\=").replace("\n"," ").replace("\r"," ")

SEV = {"CRITICAL":10,"HIGH":8,"MEDIUM":5,"LOW":3}
def cef_sev(s):
    return SEV.get((s or "").strip().upper(), 1)

# Deterministic ICS ATT&CK classification of the OBSERVED decoy interaction.
# Not fabrication: a standard mapping of the real attackType to its ICS tactic.
def mitre_of(attack_type):
    a = (attack_type or "").lower()
    if "write" in a or "coil write" in a:
        return ("Impair Process Control", "T0836 Modify Parameter")
    if "exploit" in a:
        return ("Execution", "T0871 Execution through API")
    if "login" in a or "brute" in a or "credential" in a:
        return ("Initial Access", "T0812 Default Credentials")
    if "scan" in a or "recon" in a:
        return ("Discovery", "T0846 Remote System Discovery")
    if "read" in a or "report slave" in a or "encapsulated" in a:
        return ("Discovery", "T0888 Remote System Information Discovery")
    return ("Discovery", "T0846 Remote System Discovery")

RISK = {"CRITICAL":95,"HIGH":80,"MEDIUM":55,"LOW":25}
def risk_of(sev):
    return RISK.get((sev or "").strip().upper(), 15)

def is_private(ip):
    if not ip: return True
    p = ip.split(".")
    if len(p) != 4: return False
    try: a,b = int(p[0]), int(p[1])
    except: return False
    return (a==10 or a==127 or (a==172 and 16<=b<=31) or (a==192 and b==168) or (a==169 and b==254))

def internal(h):
    if is_private(h.get("sourceIp")): return True
    c = h.get("country")
    if c and c.strip().lower().startswith("internal"): return True
    return False

def render_cef(h):
    proto = h.get("protocol") or ""
    name  = "Internet-exposed decoy probed" + (f" ({proto})" if proto.strip() else "")
    sev   = (h.get("severity") or "LOW").strip().upper() or "LOW"
    src   = h.get("sourceIp")
    dhost = h.get("destinationIp")
    msg   = h.get("description") or f"External source {src} interacted with the internet-exposed OT decoy"
    ts    = h.get("timestamp")
    try:    rt = datetime.fromisoformat(ts).strftime("%b %d %Y %H:%M:%S")
    except: rt = ""
    ext = [("rt", rt)]
    if src is not None:   ext.append(("src", src))
    if dhost is not None: ext.append(("dhost", dhost))
    if proto is not None: ext.append(("proto", proto))
    ext.append(("cat", "internet-exposed-decoy"))
    if msg is not None:   ext.append(("msg", msg))
    if h.get("attackType"): ext.append(("otAttackType", h["attackType"]))
    if h.get("country"):    ext.append(("otSrcCountry", h["country"]))
    if h.get("city"):       ext.append(("otSrcCity", h["city"]))
    if h.get("destinationPort") is not None: ext.append(("dpt", str(h["destinationPort"])))
    if h.get("sourcePort") is not None:      ext.append(("spt", str(h["sourcePort"])))
    tactic, technique = mitre_of(h.get("attackType"))
    ext.append(("otMitreTactic", tactic))
    ext.append(("otMitreTechnique", technique))
    ext.append(("otRiskScore", str(risk_of(sev))))
    ext_str = " ".join(f"{k}={cef_value(v)}" for k,v in ext)
    return ("CEF:0|OTShield|OT Deception Platform|1.0|OT-DECOY-PROBE|"
            + cef_header(name) + "|" + str(cef_sev(sev)) + "|" + ext_str)

def epoch(ts):
    try: return datetime.fromisoformat(ts).timestamp()
    except: return time.time()

def post_batch(lines):
    body = "\n".join(lines).encode("utf-8")
    req = urllib.request.Request(HEC_URL, data=body,
        headers={"Authorization": f"Splunk {HEC_TOKEN}", "Content-Type":"application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
                j = json.load(r)
                if j.get("code") == 0: return True
                print("  HEC non-zero:", j); return False
        except urllib.error.URLError as e:
            print(f"  HEC retry {attempt+1}: {e}"); time.sleep(1)
    return False

def fetch_page(page):
    url = f"{OTSHIELD}/api/honeypot/logs?page={page}&size={PAGE_SIZE}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)

def main():
    if not HEC_TOKEN:
        raise SystemExit("HEC_TOKEN env is required")
    page, total, fwd, skipped, batch = 0, 0, 0, 0, []
    while True:
        rows = fetch_page(page)
        if not rows: break
        for h in rows:
            total += 1
            if internal(h): skipped += 1; continue
            ev = {"time": epoch(h.get("timestamp")), "host":"otshield",
                  "source":"udp:1514", "sourcetype":"cef", "index":"main",
                  "event": render_cef(h)}
            batch.append(json.dumps(ev))
            if len(batch) >= BATCH:
                if post_batch(batch): fwd += len(batch)
                batch = []
        page += 1
        if page % 5 == 0: print(f"  page {page} | scanned {total} | forwarded {fwd} | skipped {skipped}")
    if batch and post_batch(batch): fwd += len(batch)
    print(f"DONE. scanned={total} forwarded={fwd} skipped_internal={skipped} pages={page}")

if __name__ == "__main__":
    main()

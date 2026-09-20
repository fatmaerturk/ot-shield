import os, sys, json, urllib.request
try: sys.stdout.reconfigure(encoding="utf-8")  # so Turkiye / USOM render on Windows too
except Exception: pass

# Compliance is usually a spreadsheet audited once a year. OTShield computes it LIVE
# from the platform's own telemetry: the same anomalies, decoy hits, DPI, asset zones
# and cases that catch attackers are the evidence that proves your posture. Two
# standards, one evidence base. Controls with no telemetry basis are reported
# NOT_ASSESSED, never assumed compliant. And a real detected attack drives the NIS2
# reporting clock, right down to a regulator-ready early-warning draft.
BASE  = "http://localhost:8080"
CREDS = {"email":    os.environ.get("OTSHIELD_EMAIL", "fatma.erturk@otshield.io"),
         "password": os.environ.get("OTSHIELD_PASSWORD", "Alex123@@@")}  # local dev seed

def _open(req):
    return json.load(urllib.request.urlopen(req, timeout=25))

def login():
    req = urllib.request.Request(BASE + "/api/auth/login",
        data=json.dumps(CREDS).encode(), headers={"Content-Type": "application/json"})
    return _open(req)["token"]

def get(path, token):
    return _open(urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + token}))

token = login()
print("[GOVERN]   Live compliance, computed from telemetry - not a once-a-year spreadsheet\n")

# ---- IEC 62443-3-3 --------------------------------------------------------
p = get("/api/compliance/iec62443/posture", token)
o, org = p["overall"], p["organization"]
print(f"[62443]    {org['standard']} posture: coverage {o['coveragePct']}%  "
      f"SL {o['achievedSL']}/{o['targetSL']}  {o['classification']}")
print(f"           {o['compliant']} compliant / {o['partial']} partial / {o['notAssessed']} not-assessed  "
      f"of {o['totalRequirements']} system requirements")
for f in p["foundationalRequirements"]:
    tag = "  <- live monitoring & deception" if f["achievedSL"] >= f["targetSL"] and f["coveragePct"] == 100 else ""
    print(f"             {f['fr']} {f['code']:<4} {f['name'][:30]:<30} {f['coveragePct']:>3}%  SL {f['achievedSL']}/{f['targetSL']}{tag}")
print(f"[HONEST]   {o['notAssessed']} of {o['totalRequirements']} reported NOT_ASSESSED - "
      f"no telemetry basis, never assumed compliant\n")

# ---- NIS2 -----------------------------------------------------------------
n = get("/api/compliance/nis2/posture", token)
norg, ps, k = n["organization"], n["postureScore"], n["kpis"]
a21 = n["article21Measures"]
compliant = sum(1 for m in a21 if m["status"] == "COMPLIANT")
partial   = sum(1 for m in a21 if m["status"] == "PARTIAL")
print(f"[NIS2]     posture {ps['score']}/100 {ps['classification']}  |  "
      f"{norg['entityType']}, {norg['sector']}, {norg['country']}")
print(f"[NIS2]     Article 21 measures: {compliant} compliant / {partial} partial of {len(a21)}")
ri = n["reportableIncidents"]
overdue = sum(1 for r in ri if r.get("earlyWarningStatus") == "OVERDUE")
print(f"[NIS2]     reportable incidents (real alerts on the NIS2 clock): {len(ri)}  ({overdue} early-warning overdue)")
inc = ri[0]
print(f"             {inc['severity']}  {inc['title']}")
print(f"               early-warning (24h): {inc['earlyWarningStatus']}   "
      f"incident report (72h): {inc['incidentReportStatus']}   final: {inc['finalReportDeadline'][:10]}\n")

# ---- from detection to a regulator-ready report ---------------------------
ew = get(f"/api/compliance/nis2/early-warning/{inc['alertId']}", token)
a = ew["assessment"]
print(f"[REPORT]   auto-generated {ew['reportType']}:")
print(f"             to: {ew['csirtTarget']}")
print(f"             entity: {ew['reportingEntity']}  |  sector: {ew['sector']}  |  {ew['country']}")
print(f"             assessment: malicious={a['suspectedMaliciousCause']}  cross-border={a['possibleCrossBorderImpact']}")

print("\n[DONE]     two standards, one live evidence base. The same telemetry that catches "
      "attackers proves your compliance - and files the report.")

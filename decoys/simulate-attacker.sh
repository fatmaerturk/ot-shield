#!/usr/bin/env sh
# OTShield internal-decoy attack simulator
# ────────────────────────────────────────
# Runs a sequence of probes from the attacker-sandbox container against the
# four tripwire HMIs on the synthetic OT subnet. Watch the OTShield dashboard
# (Decoy Layer → Fake HMIs tab) — the Tripwire Alarms banner should light up
# within a few seconds and per-site counters should increment.
#
# Usage:
#   docker exec -i attacker-sandbox sh < simulate-attacker.sh
#
# Or interactively:
#   docker exec -it attacker-sandbox sh
#   then paste the commands below.

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  OTShield internal-decoy attack simulation"
echo "  Target subnet: 172.30.50.0/24"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ─── Phase 1: Subnet sweep ────────────────────────────────────────────
echo "[1/4] Subnet recon: nmap port scan of all four HMIs…"
nmap -p 102,502,2404 172.30.50.10-13 2>/dev/null | tail -25
sleep 2

# ─── Phase 2: Real Modbus probe to the substation ────────────────────
echo ""
echo "[2/4] Modbus Read Holding Registers → substation (172.30.50.10:502)"
printf '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a' \
  | ncat -w 2 172.30.50.10 502 | xxd | head -3 || true
sleep 1

# ─── Phase 3: Real Modbus write attempt to water treatment ────────────
echo ""
echo "[3/4] Modbus Write Single Register → water treatment (172.30.50.11:502)"
printf '\x00\x02\x00\x00\x00\x06\x01\x06\x00\x01\x27\x10' \
  | ncat -w 2 172.30.50.11 502 | xxd | head -3 || true
sleep 1

# ─── Phase 4: IEC104 + S7Comm probes ──────────────────────────────────
echo ""
echo "[4/4] IEC104 STARTDT → refinery (172.30.50.12:2404)"
printf '\x68\x04\x07\x00\x00\x00' | ncat -w 2 172.30.50.12 2404 | xxd | head -3 || true

echo ""
echo "[4/4] S7Comm CR (TPKT) → manufacturing (172.30.50.13:102)"
printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02' \
  | ncat -w 2 172.30.50.13 102 | xxd | head -3 || true

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Done. Check the dashboard:"
echo "    Decoy Layer → Fake HMIs tab → Tripwire Alarms banner"
echo "    Attack Intelligence → Top Attackers"
echo "════════════════════════════════════════════════════════════════"

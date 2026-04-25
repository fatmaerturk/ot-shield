# OTShield internal decoys

Tripwire honeypots that live INSIDE an OT/SCADA subnet and treat any inbound
TCP connection as a high-confidence intrusion event.

## What's in the box

| File                  | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `tripwire_hmi.py`     | The honeypot — ~150 line Python, no third-party deps   |
| `Dockerfile`          | 30 MB python:3.12-slim image, runs as unprivileged uid |
| `docker-compose.yml`  | Spins up 4 fake HMIs + an attacker sandbox             |
| `.env.example`        | Backend ingest URL & bearer token                      |

## What it does

Each container masquerades as a real HMI on a synthetic OT subnet
(`172.30.50.0/24`). When *anything* connects to its industrial port:

1. The attacker's first 256 bytes are captured.
2. A meaningful protocol banner is sent back so the attacker stays engaged
   long enough to look real (Modbus exception, S7 CR ack, IEC104 STARTDT
   confirm, HTTP 401 with HMI-themed login page).
3. The event is POSTed to the OTShield backend (`/api/honeypot/ingest`)
   tagged as `internal-decoy` with severity HIGH.
4. The connection is closed — no protocol simulation beyond the first
   response, by design.

The four sites:

| Container               | IP            | Port | Protocol | Vendor    |
| ----------------------- | ------------- | ---- | -------- | --------- |
| `decoy-substation`      | 172.30.50.10  | 502  | Modbus   | Siemens   |
| `decoy-water-treatment` | 172.30.50.11  | 502  | Modbus   | Schneider |
| `decoy-refinery`        | 172.30.50.12  | 2404 | IEC104   | ABB       |
| `decoy-manufacturing`   | 172.30.50.13  | 102  | S7Comm   | Rockwell  |
| `attacker-sandbox`      | 172.30.50.250 | —    | —        | (alpine)  |

## Running it locally

```bash
cd decoys
cp .env.example .env
# (edit .env if your INGEST_URL or INGEST_TOKEN differs)

docker compose up -d --build

# verify everything is up
docker compose ps
```

## Triggering a test alarm

From the attacker sandbox:

```bash
# Single Modbus probe → the substation HMI alarms
docker exec attacker-sandbox ncat -w 1 172.30.50.10 502 < /dev/null

# Subnet sweep — every HMI alarms
docker exec attacker-sandbox nmap -p 102,502,2404 172.30.50.10-13

# Real Modbus Read Holding Registers query
docker exec attacker-sandbox sh -c \
  "printf '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a' | ncat -w 2 172.30.50.10 502"
```

Each one shows up immediately on the OTShield dashboard with
`source = internal-decoy`.

## Tail-watching the honeypots

```bash
docker compose logs -f --tail 20
```

Each `INTRUSION` line corresponds to one inbound connection.

## Tearing it down

```bash
docker compose down
```

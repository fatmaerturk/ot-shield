# OTShield Tripwire HMI — minimal industrial-protocol canary
# ───────────────────────────────────────────────────────────
# A 30 MB image: just python:slim + the tripwire script. Each container
# instance is parametrised via env vars (HMI_TYPE, HMI_PROTOCOL, HMI_PORT,
# INGEST_URL, INGEST_TOKEN, …) so a single image can serve every fake HMI
# in the fleet.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="otshield-tripwire-hmi"
LABEL org.opencontainers.image.description="Industrial-protocol tripwire canary for OT/SCADA networks"
LABEL org.opencontainers.image.source="https://github.com/Fancy/otshield-v1"

WORKDIR /app
COPY tripwire_hmi.py /app/tripwire_hmi.py

# Two of the Modbus / S7 ports we honor (502, 102) are below the 1024 limit
# Linux reserves for root, so the container runs as root. The host is
# unaffected — this is a single-purpose listener, not a multi-tenant box.

# NOTE: No HEALTHCHECK on purpose.
# A TCP-connect health probe to the tripwire's own port would be
# indistinguishable from a real intrusion — the tripwire would alarm on
# every health probe, polluting the dashboard with bogus events. Docker
# already restarts the container on process exit (`restart: unless-stopped`
# in docker-compose.yml), which is enough liveness for this workload.

ENTRYPOINT ["python", "-u", "/app/tripwire_hmi.py"]

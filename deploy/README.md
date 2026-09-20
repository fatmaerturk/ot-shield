# OTShield - deploy to a single GCP VM (docker-compose)

This brings up the whole platform on one VM: **Postgres + Spring Boot backend + nginx frontend**, all with `docker compose`. Only the frontend (port 80/443) is public; the backend and database stay on the internal compose network.

A big win: once the backend is on a public VM, the Conpot honeypot forwarder POSTs **straight to it**, so the ephemeral Cloudflare tunnel goes away for good.

```
                 internet
                    |
             [ nginx :80/443 ]  (frontend container, serves the SPA)
              /            \
      /api /ws /pcap    static files
            |
     [ backend :8080 ]  (Spring Boot, internal only)
            |
     [ postgres :5432 ]  (internal only, data in a volume)

  Conpot VM forwarder  --POST /api/honeypot/ingest-->  this VM (no tunnel)
```

Everything the browser calls is now **relative / same-origin**, so it works from any host. Fill in `<VM_IP>` / `<DOMAIN>` as you go.

---

## 0. One-time: commit the deploy files

These files were added to the repo (`backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx.conf`, `docker-compose.yml`, `.env.prod.template`, `deploy/`). Commit and push them so you can `git clone` on the VM:

```bash
git add backend/Dockerfile frontend/Dockerfile frontend/nginx.conf docker-compose.yml .env.prod.template .gitignore deploy/
git commit -m "Add single-VM docker-compose deployment"
git push
```

The GeoIP `.mmdb` files and the real `.env` are git-ignored on purpose - we copy those to the VM by hand (steps 3 and 4).

---

## 1. Create the VM + firewall (GCP)

```bash
# pick the same region as your Conpot VM to keep latency low
gcloud compute instances create otshield \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --tags=http-server,https-server \
  --zone=<ZONE>

# allow web traffic (skip any rule that already exists)
gcloud compute firewall-rules create allow-http  --allow=tcp:80  --target-tags=http-server
gcloud compute firewall-rules create allow-https --allow=tcp:443 --target-tags=https-server
```

Note the VM's external IP (`<VM_IP>`):
```bash
gcloud compute instances describe otshield --zone=<ZONE> \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

SSH in for the rest:
```bash
gcloud compute ssh otshield --zone=<ZONE>
```

## 2. Install Docker on the VM

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker            # or log out / back in
docker compose version   # confirm the compose plugin is present
```

## 3. Get the code + GeoIP files onto the VM

```bash
# on the VM
git clone <YOUR_REPO_URL> ot-shield
cd ot-shield
```

The MaxMind `.mmdb` files are not in git. Copy them from your laptop (run on the **laptop**):
```bash
gcloud compute scp backend/geoip/GeoLite2-City.mmdb backend/geoip/GeoLite2-ASN.mmdb \
  otshield:~/ot-shield/backend/geoip/ --zone=<ZONE>
```
(Geo/ASN enrichment degrades gracefully if you skip this, but new live attackers won't be geo-tagged.)

## 4. Configure secrets

```bash
# on the VM, in the repo root
cp .env.prod.template .env
# generate the two secrets:
echo "DB_PASSWORD=$(openssl rand -base64 24)"  >> /dev/stderr
echo "JWT_SECRET=$(openssl rand -base64 48)"   >> /dev/stderr
nano .env      # paste those two in, save
```
Leave `HONEYPOT_INGEST_TOKEN` and `REACT_APP_CARTO_KEY` as provided.

## 5. Migrate the database (your 34k demo data)

**On your laptop**, dump the dev database (portable, no ownership baggage):
```bash
pg_dump -h localhost -U postgres -d otshield_db --no-owner --no-acl -Fc -f otshield.dump
```
Copy it up:
```bash
gcloud compute scp otshield.dump otshield:~/ot-shield/ --zone=<ZONE>
```

**On the VM**, start only Postgres, load the dump, then bring up the rest:
```bash
docker compose up -d postgres
# wait until healthy:
until [ "$(docker compose ps postgres --format '{{.Health}}')" = "healthy" ]; do sleep 2; done

docker compose cp otshield.dump postgres:/tmp/otshield.dump
docker compose exec postgres \
  pg_restore -U otshield -d otshield_db --no-owner --clean --if-exists /tmp/otshield.dump
```
A few `--clean` "does not exist, skipping" notices on the first restore are normal.

> Starting fresh instead of migrating? Skip step 5. The backend needs a schema, so set `spring.jpa.hibernate.ddl-auto=update` in `backend/src/main/resources/application-prod.properties` for the very first boot (it creates the tables), then you can set it back to `none`.

## 6. Build and start the stack

```bash
docker compose up -d --build      # first build ~5-10 min (Maven + CRA)
docker compose ps                 # all three Up; postgres healthy
docker compose logs -f backend    # watch it connect to the DB and start
```
Open `http://<VM_IP>/` - the app should load with your migrated data.

## 7. Point the Conpot forwarder at the VM (drop the tunnel)

On the **Conpot VM**, restart the forwarder pointing at this VM's public base URL (no path, no tunnel):
```bash
pkill -f conpot_forwarder.py
export OTSHIELD_INGEST_URL="http://<VM_IP>"          # or https://<DOMAIN> after step 8
export OTSHIELD_INGEST_TOKEN="GcZ9KY7ANmLfvob6SOWxnRBjVlEPX2uaMr805td4IHTCezyU"
nohup python3 ~/conpot_forwarder.py > ~/forwarder.log 2>&1 &
sleep 2 && tail -5 ~/forwarder.log
```
Send one probe to the decoy and confirm it lands: `http://<VM_IP>/threat-intel/attackers` should show it within ~10s. From now on no `cloudflared` tunnel is needed.

## 8. (Recommended) HTTPS + domain with Caddy

Use HTTPS before sharing the link with Thales or a customer (login and JWT are plaintext over HTTP). `deploy/tls/Caddyfile` is ready; Caddy fetches and renews a Let's Encrypt cert automatically.

1. Point a DNS `A` record (e.g. `otshield.yourdomain.com`) at `<VM_IP>`.
2. Add the domain to `.env`:
   ```
   OTSHIELD_DOMAIN=otshield.yourdomain.com
   ```
3. In `docker-compose.yml`, stop publishing the frontend port directly (Caddy will own 80/443) - change the `frontend` service's `ports:` block to `expose:`:
   ```yaml
     frontend:
       # ...
       expose:
         - "80"          # was: ports: ["80:80"]
   ```
4. Add a `caddy` service and two volumes:
   ```yaml
     caddy:
       image: caddy:2
       restart: unless-stopped
       depends_on: [frontend]
       ports:
         - "80:80"
         - "443:443"
       environment:
         OTSHIELD_DOMAIN: ${OTSHIELD_DOMAIN}
       volumes:
         - ./deploy/tls/Caddyfile:/etc/caddy/Caddyfile:ro
         - caddy_data:/data
         - caddy_config:/config

   volumes:
     pgdata:
     caddy_data:      # add these two
     caddy_config:
   ```
5. `docker compose up -d` - open `https://otshield.yourdomain.com`. Then set the Conpot forwarder's `OTSHIELD_INGEST_URL=https://otshield.yourdomain.com` (step 7).

(Alternatively, front the VM with Cloudflare - you already use it - proxied A record, SSL mode "Full". That also hides the origin IP and adds WAF/DDoS.)

---

## First login & hardening

- Log in with the seeded admin (migrated): `fatma.erturk@otshield.io`. **Change this password immediately** in Settings for a public deployment.
- `SIEM forwarding` is OFF by default in prod (`application-prod.properties`). Turn it on from the SIEM page if you also stand up Splunk in the cloud.
- Rotate `HONEYPOT_INGEST_TOKEN` and the CARTO key if this repo is or becomes public (the CARTO key can also be domain-locked in the CARTO dashboard).

## Day-to-day ops

```bash
docker compose logs -f backend            # tail logs
docker compose restart backend            # restart one service
git pull && docker compose up -d --build  # deploy a new version
docker compose down                       # stop (data survives in the pgdata volume)
```

## Troubleshooting

- **Backend crash-loops at boot**: the DB has no schema yet. Run the step-5 restore, then `docker compose up -d`.
- **CRA build runs out of memory** on a small VM: use `e2-medium`+ or add `ENV NODE_OPTIONS=--max-old-space-size=2048` to `frontend/Dockerfile` before `npm run build`.
- **Map shows "API KEY REQUIRED"**: `REACT_APP_CARTO_KEY` must be set in `.env` before `--build` (CRA bakes it in at build time). Rebuild after changing it.
- **Attackers not arriving**: check the Conpot forwarder log on the Conpot VM and that `OTSHIELD_INGEST_URL` points at this VM.

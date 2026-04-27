#!/usr/bin/env python3
"""
OT-Shield Conpot Log Forwarder
================================
GCP VM uzerinde calisan Conpot honeypot'unun log'larini, Cloudflare tunnel
uzerinden local OT-Shield backend'in /api/honeypot/ingest endpoint'ine
iletir.

Calistirma (GCP VM'de):
    python3 conpot_forwarder.py

Konfigurasyon environment variable'larla da override edilebilir:
    INGEST_URL    - Backend ingest URL'i  (default: tunnel URL)
    INGEST_TOKEN  - Bearer token          (default: application.properties'dekiyle ayni)
    LOG_FILE      - Conpot log dosya yolu (default: /var/log/conpot/conpot.log)
    BATCH_SIZE    - Bir POST'taki max log satiri (default: 25)
    FLUSH_INTERVAL- Flush araligi (saniye)  (default: 2.0)
"""

import os
import sys
import time
import json
import signal
import logging
from collections import deque
from pathlib import Path

try:
    import requests
except ImportError:
    print("[FATAL] 'requests' kutuphanesi yok. Kur: pip3 install requests", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Konfigurasyon
# ---------------------------------------------------------------------------
INGEST_URL = os.environ.get(
    "INGEST_URL",
    "https://absence-under-connections-persons.trycloudflare.com/api/honeypot/ingest",
)
INGEST_TOKEN = os.environ.get(
    "INGEST_TOKEN",
    "GcZ9KY7ANmLfvob6SOWxnRBjVlEPX2uaMr805td4IHTCezyU",
)
# Conpot Docker container'inin log'unu yazdigi tipik yollar.
# Eger Conpot'u docker run ile -v ile mount ettiyseniz host yolunu yazin.
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/conpot/conpot.log")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "25"))
FLUSH_INTERVAL = float(os.environ.get("FLUSH_INTERVAL", "2.0"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "10.0"))
MAX_RETRY = int(os.environ.get("MAX_RETRY", "5"))
STATE_FILE = os.environ.get("STATE_FILE", os.path.expanduser("~/.conpot_forwarder.state"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("conpot-forwarder")


# ---------------------------------------------------------------------------
# Kalici offset (yeniden baslatmada ayni satirlari ikinci kez gondermemek icin)
# ---------------------------------------------------------------------------
def load_offset(path: str) -> int:
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        if data.get("file") == path:
            return int(data.get("offset", 0))
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        pass
    return 0


def save_offset(path: str, offset: int) -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({"file": path, "offset": offset}, f)
    except OSError as e:
        log.warning("Offset state yazilamadi (%s): %s", STATE_FILE, e)


# ---------------------------------------------------------------------------
# HTTP gonderimi
# ---------------------------------------------------------------------------
session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {INGEST_TOKEN}",
    "Content-Type": "application/json",
    # Cloudflare Tunnel bazen browser olmayan istekleri filtreler — UA veriyoruz
    "User-Agent": "OTShield-ConpotForwarder/1.0",
})


def post_lines(lines: list) -> bool:
    """Bir batch log satirini ingest endpoint'ine gonderir.
       Basarisizlikta exponential backoff ile MAX_RETRY kere dener."""
    if not lines:
        return True

    payload = {"lines": lines}
    body = json.dumps(payload)

    backoff = 1.0
    for attempt in range(1, MAX_RETRY + 1):
        try:
            r = session.post(INGEST_URL, data=body, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                try:
                    j = r.json()
                    log.info(
                        "Gonderildi: %d satir (processed=%s failed=%s)",
                        len(lines), j.get("processed"), j.get("failed"),
                    )
                except ValueError:
                    log.info("Gonderildi: %d satir (HTTP 200, JSON yok)", len(lines))
                return True
            elif r.status_code == 401:
                log.error(
                    "401 Unauthorized — INGEST_TOKEN application.properties'deki "
                    "honeypot.ingest.token ile esit mi? Cevap: %s", r.text[:200],
                )
                return False  # token yanlissa retry anlamsiz
            elif r.status_code == 503:
                log.error("503 — backend'de honeypot.ingest.token bos. Cevap: %s", r.text[:200])
                return False
            else:
                log.warning(
                    "HTTP %d (deneme %d/%d): %s",
                    r.status_code, attempt, MAX_RETRY, r.text[:200],
                )
        except requests.exceptions.RequestException as e:
            log.warning("Aglar hatasi (deneme %d/%d): %s", attempt, MAX_RETRY, e)

        if attempt < MAX_RETRY:
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    log.error("Batch %d satir %d denemeden sonra DROP edildi.", len(lines), MAX_RETRY)
    return False


# ---------------------------------------------------------------------------
# Tail dongusu
# ---------------------------------------------------------------------------
shutdown = False


def handle_sigterm(signum, frame):
    global shutdown
    log.info("Sinyal %d alindi, kapaniyor...", signum)
    shutdown = True


signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)


def tail_and_forward(path: str) -> None:
    """tail -F gibi davranir: dosya yoksa olusana kadar bekler, rotation'da
       (dosya kuculurse / inode degisirse) en bastan acar."""
    log.info("OT-Shield Conpot Forwarder basladi.")
    log.info("  Kaynak log    : %s", path)
    log.info("  Hedef ingest  : %s", INGEST_URL)
    log.info("  Batch size    : %d  | Flush interval: %.1fs", BATCH_SIZE, FLUSH_INTERVAL)

    buffer = deque()
    last_flush = time.time()
    file_obj = None
    inode = None
    offset = load_offset(path)

    while not shutdown:
        # 1) dosyayi ac (yoksa bekle)
        if file_obj is None:
            if not os.path.exists(path):
                log.warning("Log dosyasi yok: %s — 5s sonra tekrar denenecek", path)
                time.sleep(5)
                continue
            try:
                file_obj = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(file_obj.fileno()).st_ino
                # Dosya boyutu daha kucukse (rotate), bastan basla
                size = os.fstat(file_obj.fileno()).st_size
                if offset > size:
                    log.info("Log rotate algilandi (offset=%d > size=%d), bastan oku", offset, size)
                    offset = 0
                file_obj.seek(offset)
                log.info("Dosya acildi, offset=%d", offset)
            except OSError as e:
                log.error("Dosya acilamadi (%s): %s", path, e)
                time.sleep(5)
                continue

        # 2) yeni satirlari oku
        line = file_obj.readline()
        if line:
            line = line.rstrip("\r\n")
            if line.strip():
                buffer.append(line)
            offset = file_obj.tell()
        else:
            # EOF — dosya rotate olmus mu kontrol et
            try:
                stat_disk = os.stat(path)
                if stat_disk.st_ino != inode or stat_disk.st_size < offset:
                    log.info("Log rotate algilandi, dosyayi yeniden ac")
                    file_obj.close()
                    file_obj = None
                    inode = None
                    offset = 0
                    continue
            except FileNotFoundError:
                log.warning("Log dosyasi silindi, yeniden olusmasini bekliyorum")
                file_obj.close()
                file_obj = None
                offset = 0
                time.sleep(2)
                continue

        # 3) flush kosulu (boyut VEYA zaman)
        now = time.time()
        should_flush = (
            len(buffer) >= BATCH_SIZE
            or (buffer and (now - last_flush) >= FLUSH_INTERVAL)
        )

        if should_flush:
            batch = []
            while buffer and len(batch) < BATCH_SIZE:
                batch.append(buffer.popleft())
            if post_lines(batch):
                save_offset(path, offset)
            else:
                # gonderim basarisizsa satirlari geri yukle (kuyrugun basina)
                for s in reversed(batch):
                    buffer.appendleft(s)
            last_flush = now

        # 4) yeni satir yoksa biraz bekle (CPU yakmayalim)
        if not line:
            time.sleep(0.25)

    # graceful shutdown — kalan buffer'i flush et
    if buffer:
        log.info("Kapanmadan once %d satir flush ediliyor...", len(buffer))
        post_lines(list(buffer))
        save_offset(path, offset)

    if file_obj is not None:
        file_obj.close()
    log.info("Forwarder durdu.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    if not INGEST_TOKEN:
        log.error("INGEST_TOKEN bos — application.properties'deki "
                  "honeypot.ingest.token degerini env veya kod icine yazin.")
        return 2

    # On testi: backend'e ping at, token gecerli mi?
    try:
        r = session.post(INGEST_URL, json={"line": "[FORWARDER-PING] startup probe"}, timeout=HTTP_TIMEOUT)
        log.info("On test: HTTP %d — %s", r.status_code, (r.text or "")[:120])
        if r.status_code == 401:
            log.error("Token reddedildi. Forwarder duruyor.")
            return 3
    except requests.exceptions.RequestException as e:
        log.warning("On test basarisiz (tunnel dusuk olabilir): %s — yine de basliyorum.", e)

    try:
        tail_and_forward(LOG_FILE)
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt")
    except Exception as e:
        log.exception("Beklenmeyen hata: %s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
OT-Shield SPAN Sensor
=====================
Bir SPAN/mirror portuna (veya herhangi bir NIC'e) bagli kutuda calisir:
trafigi dongusel (rolling) pcap dosyalari olarak yakalar ve tamamlanan her
dosyayi OT-Shield backend'in /api/upload/pcap endpoint'ine yukler. Yuklenen
her pcap, elle upload ile BIRE BIR ayni analiz pipeline'indan gecer
(PcapAnalysisService -> dpi_events + asset discovery + anomali kurallari).

Yani bu sensor, "canli OT trafigini OT-Shield'a besleme" bosluguni mevcut
ve test edilmis pcap pipeline'ini yeniden kullanarak kapatir. Gecikme =
rotasyon penceresi (ROTATE_SECONDS, varsayilan 60s) -> near-real-time.

MODLAR
------
1) Tek dosya smoke-test (NIC gerektirmez - once bunu calistir):
       python3 span_sensor.py --once /yol/ornek.pcap
   Pipeline'in uctan uca calistigini tek bir pcap ile dogrular.

2) Canli rolling capture (SPAN portundan):
       python3 span_sensor.py --iface "Ethernet"          # Windows (dumpcap)
       python3 span_sensor.py --iface eth0                 # Linux   (tcpdump)
   Yakalama araci yoksa veya ayri calisiyorsa:

3) Sadece-yukleyici (capture'i baska bir surec SPOOL_DIR'e yaziyorsa):
       python3 span_sensor.py --upload-only

ARAYUZLERI LISTELE
------------------
       python3 span_sensor.py --list

KONFIGURASYON (env veya arg)
----------------------------
   OTSHIELD_URL    Backend kok URL'i          (default: http://localhost:8080)
   SENSOR_TOKEN    Bearer token (opsiyonel)   (upload endpoint auth'luysa doldur)
   IFACE           Yakalama arayuzu           (--iface ile de verilir)
   ROTATE_SECONDS  Rotasyon penceresi (sn)    (default: 60)
   SPOOL_DIR       Pcap spool klasoru         (default: <script>/spool)
   BPF             Capture filtresi           (default: ICS portlari; "" = hepsi)
   DELETE_AFTER    Yuklenen dosyayi sil        (default: true)
   CAPTURE_CMD     Yakalama aracini zorla      (tcpdump|dumpcap|tam yol)
   HTTP_TIMEOUT / MAX_RETRY
"""

import os
import sys
import time
import glob
import signal
import shutil
import socket
import logging
import argparse
import subprocess
from pathlib import Path

try:
    import requests
except ImportError:
    print("[FATAL] 'requests' kutuphanesi yok. Kur: pip3 install requests", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Konfigurasyon
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent

OTSHIELD_URL = os.environ.get("OTSHIELD_URL", "http://localhost:8080").rstrip("/")
UPLOAD_URL = OTSHIELD_URL + "/api/upload/pcap"
SENSOR_TOKEN = os.environ.get("SENSOR_TOKEN", "").strip()
ROTATE_SECONDS = int(os.environ.get("ROTATE_SECONDS", "60"))
SPOOL_DIR = Path(os.environ.get("SPOOL_DIR", str(SCRIPT_DIR / "spool")))
# Varsayilan: yaygin ICS/OT portlari (her iki yon). Bos verirsen tum trafik.
#   502 Modbus · 102 S7comm · 2404 IEC-104 · 20000 DNP3 · 44818/2222 EtherNet/IP
#   47808 BACnet · 4840 OPC-UA · 161 SNMP · 789 Red Lion/Crimson
DEFAULT_BPF = ("tcp port 502 or tcp port 102 or tcp port 2404 or tcp port 20000 "
               "or tcp port 44818 or udp port 2222 or udp port 47808 "
               "or tcp port 4840 or udp port 161 or tcp port 789")
BPF = os.environ.get("BPF", DEFAULT_BPF)
DELETE_AFTER = os.environ.get("DELETE_AFTER", "true").lower() in ("1", "true", "yes", "on")
CAPTURE_CMD = os.environ.get("CAPTURE_CMD", "").strip()
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "30.0"))
MAX_RETRY = int(os.environ.get("MAX_RETRY", "4"))
# Pcap global header'i 24 bayt; bundan kucuk dosya = bos rotasyon, atla.
MIN_PCAP_BYTES = 40

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("span-sensor")

# Sensor identity: lets the backend's ingestion monitor group uploads by sensor.
_HOST = socket.gethostname() or "span-sensor"
SENSOR_ID = os.environ.get("SENSOR_ID", _HOST)

session = requests.Session()
session.headers.update({
    "User-Agent": "OTShield-SpanSensor/1.0",
    "X-Sensor-Id": SENSOR_ID,
    "X-Sensor-Host": _HOST,
})
if SENSOR_TOKEN:
    session.headers.update({"Authorization": f"Bearer {SENSOR_TOKEN}"})

shutdown = False


def handle_sigterm(signum, frame):
    global shutdown
    log.info("Sinyal %d alindi, kapaniyor...", signum)
    shutdown = True


signal.signal(signal.SIGTERM, handle_sigterm)
try:
    signal.signal(signal.SIGINT, handle_sigterm)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Yakalama araci tespiti
# ---------------------------------------------------------------------------
WIN_DUMPCAP = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
]


def find_capture_tool() -> tuple:
    """(tool_kind, executable_path) dondurur. tool_kind: 'tcpdump' | 'dumpcap'."""
    if CAPTURE_CMD:
        kind = "dumpcap" if "dumpcap" in CAPTURE_CMD.lower() else "tcpdump"
        return kind, CAPTURE_CMD
    # Linux/mac: tcpdump tercih
    td = shutil.which("tcpdump")
    if td:
        return "tcpdump", td
    # Windows: dumpcap (Wireshark/Npcap ile gelir)
    dc = shutil.which("dumpcap")
    if dc:
        return "dumpcap", dc
    for p in WIN_DUMPCAP:
        if os.path.exists(p):
            return "dumpcap", p
    return "", ""


def list_interfaces():
    kind, exe = find_capture_tool()
    if not exe:
        log.error("Yakalama araci bulunamadi. Linux: 'apt install tcpdump'. "
                  "Windows: Wireshark+Npcap kur (dumpcap gelir).")
        return 2
    log.info("Yakalama araci: %s (%s)", kind, exe)
    try:
        subprocess.run([exe, "-D"], check=False)
    except Exception as e:
        log.error("Arayuz listesi alinamadi: %s", e)
        return 1
    return 0


def build_capture_proc(iface: str):
    """Rotasyonlu capture surecini baslatir. Her rotasyon BENZERSIZ adli dosya
       yazar; en yeni (hala yazilan) disindaki her dosya 'tamamlanmis' sayilir."""
    kind, exe = find_capture_tool()
    if not exe:
        log.error("Yakalama araci yok. --list ile kontrol et, Wireshark/tcpdump kur.")
        return None, None
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)

    if kind == "tcpdump":
        # -G <sn> + strftime adli -w => zaman bazli, benzersiz adli rotasyon
        tmpl = str(SPOOL_DIR / "cap-%Y%m%d%H%M%S.pcap")
        cmd = [exe, "-i", iface, "-G", str(ROTATE_SECONDS), "-w", tmpl, "-n"]
        if BPF.strip():
            cmd += BPF.split()
    else:  # dumpcap
        # -b duration:<sn> => numarali+zaman damgali dosyalar (cap_00001_<ts>.pcapng)
        out = str(SPOOL_DIR / "cap.pcapng")
        cmd = [exe, "-i", iface, "-b", f"duration:{ROTATE_SECONDS}", "-w", out]
        if BPF.strip():
            cmd += ["-f", BPF]

    log.info("Capture baslatiliyor (%s): %s", kind, " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd)
    except Exception as e:
        log.error("Capture baslatilamadi: %s", e)
        return None, None
    return proc, kind


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
def upload_pcap(path: Path) -> bool:
    """Tek bir pcap dosyasini /api/upload/pcap'e yukler, retry/backoff ile."""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size < MIN_PCAP_BYTES:
        log.info("Bos/kucuk rotasyon atlandi (%d B): %s", size, path.name)
        return True  # basarili say ki silinsin/atlansin

    backoff = 1.0
    for attempt in range(1, MAX_RETRY + 1):
        try:
            with open(path, "rb") as fh:
                files = {"pcap": (path.name, fh, "application/vnd.tcpdump.pcap")}
                r = session.post(UPLOAD_URL, files=files, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                try:
                    j = r.json()
                    total = j.get("total")
                    assets = (j.get("assetDetection") or {}).get("assetsDetected")
                    log.info("Yuklendi: %s (%d B) -> paket=%s, asset-tespit=%s",
                             path.name, size, total, assets)
                except ValueError:
                    log.info("Yuklendi: %s (%d B) -> HTTP 200", path.name, size)
                return True
            elif r.status_code in (401, 403):
                log.error("%d - upload endpoint auth istiyor. SENSOR_TOKEN dogru mu? "
                          "Cevap: %s", r.status_code, r.text[:200])
                return False  # auth hatasinda retry anlamsiz
            elif r.status_code == 400:
                log.warning("400 - backend dosyayi reddetti (bos/yanlis tur?): %s",
                            r.text[:200])
                return True  # tekrar denemeye deger degil; atla
            else:
                log.warning("HTTP %d (deneme %d/%d): %s",
                            r.status_code, attempt, MAX_RETRY, r.text[:200])
        except requests.exceptions.RequestException as e:
            log.warning("Ag hatasi (deneme %d/%d): %s", attempt, MAX_RETRY, e)

        if attempt < MAX_RETRY:
            time.sleep(backoff)
            backoff = min(backoff * 2, 20.0)

    log.error("DROP: %s %d denemeden sonra yuklenemedi.", path.name, MAX_RETRY)
    return False


def completed_pcaps() -> list:
    """SPOOL_DIR'deki tamamlanmis pcap'leri (en yeni haric) eskiden yeniye dondurur.
       En yeni dosya hala yaziliyor olabilir -> ona dokunmayiz."""
    paths = []
    for ext in ("*.pcap", "*.pcapng"):
        paths += glob.glob(str(SPOOL_DIR / ext))
    if len(paths) <= 1:
        return []  # tek dosya varsa hala yaziliyor olabilir
    paths.sort(key=lambda p: os.path.getmtime(p))
    return [Path(p) for p in paths[:-1]]  # en yeniyi birak


def drain_spool():
    """Tamamlanmis dosyalari yukle; basarili olanlari sil."""
    for p in completed_pcaps():
        if shutdown:
            break
        ok = upload_pcap(p)
        if ok and DELETE_AFTER:
            try:
                p.unlink()
            except OSError as e:
                log.warning("Silinemedi %s: %s", p.name, e)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
def preflight() -> bool:
    """Backend'e /api/health/pcap ile ping; native pcap lib durumunu raporla."""
    try:
        r = session.get(OTSHIELD_URL + "/api/health/pcap", timeout=HTTP_TIMEOUT)
        log.info("On test: backend %s -> HTTP %d", OTSHIELD_URL, r.status_code)
        try:
            j = r.json()
            if j.get("nativeLibrary") == "missing":
                log.warning("DIKKAT: backend'de pcap native lib YOK -> yuklenen "
                            "pcap'ler parse edilmeden bos donebilir (asset/anomali "
                            "cikmaz). Backend host'una libpcap/Npcap kur.")
        except ValueError:
            pass
        return True
    except requests.exceptions.RequestException as e:
        log.warning("Backend'e ulasilamadi (%s): %s - yine de devam.", OTSHIELD_URL, e)
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="OT-Shield SPAN pcap sensor")
    ap.add_argument("--once", metavar="FILE", help="Tek pcap yukle ve cik (smoke-test)")
    ap.add_argument("--iface", help="Yakalama arayuzu (canli mod)")
    ap.add_argument("--upload-only", action="store_true",
                    help="Capture baslatma; sadece SPOOL_DIR'i izle ve yukle")
    ap.add_argument("--list", action="store_true", help="Arayuzleri listele ve cik")
    args = ap.parse_args()

    log.info("OT-Shield SPAN Sensor")
    log.info("  Sensor ID   : %s", SENSOR_ID)
    log.info("  Backend     : %s", UPLOAD_URL)
    log.info("  Token       : %s", "var" if SENSOR_TOKEN else "yok (permitAll varsayiliyor)")
    log.info("  Spool       : %s", SPOOL_DIR)
    log.info("  Rotasyon    : %ds | Filtre: %s", ROTATE_SECONDS, BPF or "(hepsi)")

    if args.list:
        return list_interfaces()

    # 1) Tek dosya smoke-test
    if args.once:
        p = Path(args.once)
        if not p.exists():
            log.error("Dosya yok: %s", p)
            return 2
        preflight()
        ok = upload_pcap(p)
        log.info("Smoke-test %s", "BASARILI" if ok else "BASARISIZ")
        return 0 if ok else 1

    preflight()
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)

    capture_proc = None
    if not args.upload_only:
        iface = args.iface or os.environ.get("IFACE", "")
        if not iface:
            log.error("Canli mod icin --iface gerekli (veya IFACE env). "
                      "Arayuzler: python span_sensor.py --list")
            return 2
        session.headers.update({"X-Sensor-Iface": iface})
        capture_proc, _ = build_capture_proc(iface)
        if capture_proc is None:
            return 2
    else:
        log.info("Sadece-yukleyici mod: SPOOL_DIR izleniyor, capture baslatilmadi.")

    # 2/3) Izle-ve-yukle dongusu
    try:
        while not shutdown:
            if capture_proc is not None and capture_proc.poll() is not None:
                log.error("Capture sureci beklenmedik sekilde durdu (kod=%s). "
                          "Arayuz adi/izinler dogru mu? (root/Administrator gerekebilir)",
                          capture_proc.returncode)
                break
            drain_spool()
            time.sleep(min(5, max(1, ROTATE_SECONDS // 4)))
    finally:
        if capture_proc is not None:
            log.info("Capture durduruluyor...")
            try:
                capture_proc.terminate()
                capture_proc.wait(timeout=10)
            except Exception:
                try:
                    capture_proc.kill()
                except Exception:
                    pass
        # kapanista kalan tamamlanmislari bir kez daha dene
        drain_spool()
    log.info("Sensor durdu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

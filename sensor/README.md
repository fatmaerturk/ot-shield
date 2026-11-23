# OT-Shield SPAN Sensor

Müşterinin OT ağından **SPAN/mirror** portuna kopyalanan canlı trafiği OT-Shield'a
besler. Trafiği dönüşümlü (rolling) pcap dosyaları olarak yakalar ve tamamlanan her
dosyayı backend'in `/api/upload/pcap` ucuna yükler. Yüklenen pcap, elle upload ile
**bire bir aynı** analiz pipeline'ından geçer: `PcapAnalysisService` → `dpi_events`
+ asset discovery + anomali kuralları. Yani canlı izleme, bugün çalışan ve test
edilmiş tek yolu (pcap pipeline) yeniden kullanarak elde edilir. Gecikme = rotasyon
penceresi (`ROTATE_SECONDS`, varsayılan 60 sn) → near-real-time.

## Gereksinimler

- **Python 3** + `requests` → `pip install requests`
- Yakalama aracı (canlı mod için):
  - **Linux:** `tcpdump` (`sudo apt install tcpdump`)
  - **Windows:** Wireshark + Npcap (kurulumla birlikte `dumpcap.exe` gelir)
- Sensör kutusu **SPAN/mirror portuna** bağlı olmalı; yakalama için **root/Administrator** gerekir.

## Kullanım

**0) Arayüzleri listele**
```
python span_sensor.py --list
```

**1) Tek dosya smoke-test (NIC gerektirmez — ÖNCE bunu çalıştır)**
Pipeline'ın uçtan uca çalıştığını tek bir pcap ile doğrular:
```
python span_sensor.py --once /yol/ornek.pcap
```
`Yuklendi: ... -> paket=N, asset-tespit=true` görürsen zincir çalışıyor. Ardından
OT-Shield UI'da **Assets** ve **Anomalies** sayfalarında yeni kayıtlar belirmeli.

**2) Canlı rolling capture (SPAN portundan)**
```
# Linux
sudo IFACE=eth0 python3 span_sensor.py --iface eth0
# Windows (yönetici PowerShell)
python span_sensor.py --iface "Ethernet"
```

**3) Sadece-yükleyici** (capture'ı başka bir süreç `SPOOL_DIR`'e yazıyorsa)
```
python span_sensor.py --upload-only
```

## Konfigürasyon (env ya da arg)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `OTSHIELD_URL` | `http://localhost:8080` | Backend kök URL'i |
| `SENSOR_TOKEN` | *(boş)* | Upload ucu auth'luysa Bearer token |
| `IFACE` | — | Yakalama arayüzü (`--iface` ile de verilir) |
| `ROTATE_SECONDS` | `60` | Rotasyon penceresi |
| `SPOOL_DIR` | `<script>/spool` | Pcap spool klasörü |
| `BPF` | ICS portları | Capture filtresi; `""` = tüm trafik |
| `DELETE_AFTER` | `true` | Yüklenen dosyayı sil |
| `CAPTURE_CMD` | *(otomatik)* | `tcpdump`/`dumpcap` yolunu zorla |

Varsayılan BPF yalnız yaygın ICS/OT portlarını yakalar (502 Modbus · 102 S7 ·
2404 IEC-104 · 20000 DNP3 · 44818/2222 EtherNet/IP · 47808 BACnet · 4840 OPC-UA ·
161 SNMP · 789 Red Lion). Kurumsal gürültü böylece pipeline'a girmez.

## Önemli notlar

- **DPI dissector'lar belirli protokolleri anlar** (Modbus, S7comm doğrulandı). Mirror'da
  **ICS segmentini** kopyala; kurumsal trafik çoğunlukla parse edilmeden geçer.
- **Backend host'unda native pcap lib** (libpcap/Npcap) olmalı; yoksa `/api/upload/pcap`
  dosyayı parse etmeden boş döner (sensör ön-testte bunu uyarır).
- **Güvenlik (yapılacak):** `/api/upload/**` şu an `permitAll` (SecurityConfig). Üretimde
  sensör için bir token zorunlu kılınmalı; o zaman `SENSOR_TOKEN` doldurulur. Bu, eşlenik
  backend değişikliğiyle birlikte yapılacak.

## Servis olarak çalıştırma (Linux, systemd — ileride)

```ini
# /etc/systemd/system/otshield-sensor.service
[Unit]
Description=OT-Shield SPAN Sensor
After=network-online.target

[Service]
Environment=OTSHIELD_URL=https://soc.musteri.local
Environment=IFACE=eth0
Environment=ROTATE_SECONDS=60
ExecStart=/usr/bin/python3 /opt/otshield/sensor/span_sensor.py --iface eth0
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

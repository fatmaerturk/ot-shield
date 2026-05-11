# OTShield Demo Video Script

**Hedef süre**: 5 to 7 dakika
**Hedef kitle**: HMGCC Co-Creation reviewer paneli (kısa liste değerlendirmesi)
**Tone**: Sakin, teknik, abartısız. Ne abartı ne özür.
**Dil**: İngilizce (UK English, em-dash yok)
**Anahtar mesaj**: OTShield bugün çalışan bir platform. Phase 1 funding'ı bu platforma somut bir cognitive layer ekliyor.

---

## 0:00 to 0:30 — Opening: OTShield nedir, iki mod

**[Açılış: OTShield ana ekran, browser'da localhost]**

> "This is OTShield: an offline, evidence-driven ICS security platform from Safetech Global, a UK company.
>
> The platform runs in two cooperating modes inside a single product. **SOC Mode** deploys a protocol-aware decoy fabric and turns real attacker engagements into evidence-based intelligence: deep-packet inspection on Modbus and S7Comm, asset discovery, MITRE ATT&CK for ICS coverage, and an internet-exposed decoy fabric that captures live attacker behaviour today.
>
> **Research Mode** turns the same data layer into a copilot-driven research workbench. Bundles, Library, Summary, Inventory, Threads, Findings, Vulns, all running fully offline against a local LLM.
>
> Today I will walk through both modes end to end, against a real-attack PCAP and a tear-down bundle. Everything you are about to see runs on a researcher's laptop with no internet calls."

**[Görsel notu]**: Ana ekrandan SOC Mode ve Research Mode arasındaki mode toggle'ı göster. İki kart yan yana açılırsa daha güçlü.

---

## 0:30 to 1:30 — SOC Mode kısmı 1: PCAP yükleme + protokol analizi

**[Operate -> Network Dashboard'a tıkla]**

> "Let me start in SOC Mode. This is the Network Dashboard. I am uploading a PCAP file captured from a customer engagement. The file contains traffic from an attacker reconnaissance against an ICS environment."

**[PCAP upload butonu, attack PCAP dosyasını seç, upload]**

> "The platform is parsing the PCAP using two dedicated dissectors: Modbus and S7Comm. Function codes, register addresses, exception responses are all extracted with anomaly rules layered on top.
>
> For DNP3, OPC UA, EtherNet/IP and IEC 60870-5-104 we use port-based identification today; the dedicated dissectors for those protocols are extended in the Phase 1 work against HMGCC test data."

**[Sonuç ekranı: protocol distribution chart + top talkers + zone crossings]**

> "Here is what just came back: protocol distribution, top talkers, and zone crossings between Purdue Levels. The platform flags the East-West movement crossing into Level 1, which is exactly the pattern that should alarm an OT operator."

**[Görsel notu]**: Dashboard'da Modbus / S7Comm function code breakdown'unu göster. Anormallikler kırmızı vurgulanmış olmalı.

---

## 1:30 to 2:30 — SOC Mode kısmı 2: Asset discovery + risk

**[Operate -> Assets'a tıkla]**

> "From the same PCAP, OTShield has auto-discovered the assets on this network. PLCs, RTUs, HMIs, engineering workstations, SCADA, and network gear, each tagged with a Purdue level from L0 to L5 and a risk score."

**[Assets tablosu: filtrele "high risk" -> 3-4 asset göster]**

> "Each row shows the manufacturer, the protocol footprint, the open ports, and a risk score driven by exposure plus protocol behaviour seen on the wire.
>
> The high-risk assets here are a Siemens SIMATIC S7-1200 PLC speaking Modbus, and a Schneider Modicon M340 speaking DNP3. Both are reachable from the IT zone, both have function code patterns that match unauthorised-write attempts."

**[Operate -> Network Topology'a tıkla]**

> "The Network Topology page renders the same data as a Purdue-aware diagram. The attack chain is rendered as a path: phishing on an engineering workstation, lateral movement to a PI Historian, then SCADA, then PLC, ending at a pump actuator. This is a realistic ICS attacker journey, rendered in the live platform from real captured traffic."

**[Görsel notu]**: Topoloji animasyonu varsa 5-10 saniye attack chain'in çizilmesini bekle. Yoksa node'ları tek tek vurgulayan zoom yap.

---

## 2:30 to 3:30 — SOC Mode kısmı 3: MITRE ATT&CK + alerts

**[Detect -> MITRE ATT&CK for ICS'e tıkla]**

> "OTShield maps the observed behaviour onto the full ATT&CK for ICS kill chain: initial access through to impact. Ten tactics, real techniques, mapped per attacker session.
>
> Here you see TA0102 Discovery and TA0109 Lateral Movement lit up for this PCAP. The platform clusters multiple attacker sessions into campaigns based on behavioural fingerprints."

**[Detect -> Attacker TTPs'e tıkla]**

> "From the same data we get the per-attacker TTP matrix. IOCs and TTPs can be exported in JSON, CSV or plain formats today, with SIEM, TAXII and MISP push interfaces in the platform. Production-grade TAXII and MISP push is hardened in Phase 2."

**[Respond -> Security Alerts'a tıkla, kısa]**

> "Alerts are ranked by severity with MTTA and MTTR metrics, exportable to CSV, XLSX or PDF. This is the SOC-side of the platform, validated today on Safetech Global's internet-exposed decoy fabric, which sits at TRL 5."

**[Görsel notu]**: ATT&CK matrix'inde kill chain stage'lerini hover et, lit up cell'leri vurgula.

---

## 3:30 to 5:00 — Research Mode: copilot, bundles, threads

**[Sol üstte Mode toggle -> Research Mode'a geç]**

> "Now the same platform, switched to Research Mode. This is what the HMGCC challenge funds: a cognitive layer for vulnerability research, built on top of the existing data layer.
>
> The Research Mode is a working prototype today at TRL 3 to 4. The HMGCC Phase 1 work takes it to TRL 6."

**[Research -> Workspace'e tıkla, mevcut bir bundle aç]**

> "I have an active Research Bundle open. A bundle is a single tear-down workspace: a Library of vendor documents, a Summary, an Inventory of identified components, Ports & Services, Threads of conversation with the copilot, Findings the researcher chooses to keep, and a Vulns view."

**[Research -> Knowledge Library'ye tıkla]**

> "The Library shows the documents this bundle has indexed. Vendor manuals, datasheets, technical PDFs. Today we ingest PDFs and plain-text formats: markdown, text, CSV, via Apache PDFBox, a chunker, and offline embeddings. Phase 1 adds OCR, handwriting recognition, schematic extraction and image understanding, with Tesseract, PaddleOCR, TrOCR, LayoutLMv3 and Gemma 4's native vision."

**[Research -> Summary'ye tıkla]**

> "The Summary is generated by the local LLM. Today that is Llama 3.2 1B Instruct running through Ollama, deliberately small to demonstrate that this works on any laptop. In Phase 1 we upgrade to Gemma 4 26B MoE on a dedicated RTX 5090 dev workstation, with Llama 3.2 retained as a small-model fallback for ablation."

**[Research -> Inventory'ye tıkla]**

> "Inventory is the structured output: components, protocols, exposed services. The deep-extract pipeline is LLM-driven today and protocol-agnostic. Phase 1 adds protocol-specific extractors for Modbus, S7Comm, EtherNet/IP, OPC UA, DNP3 and IEC 60870-5-104."

**[Research -> Threads'e tıkla, mevcut bir thread aç]**

> "And here is the Threads tab: the copilot. I can ask it questions about the bundle. Each answer comes back with inline citations referencing the indexed documents, plus a confidence label, HIGH, MEDIUM or LOW, and a 'needs more sources' flag if the model is not certain.
>
> Today the confidence is a categorical label. In Phase 1 we replace it with a calibrated 0 to 1 score per claim using conformal prediction. We also add an independent agentic verifier on LangGraph that runs three parallel checks per claim: corpus re-query, trusted-source cross-check, and the on-wire cross-check against real PCAP and decoy data. That last one is unique to OTShield, no other applicant has it."

**[Threads tab'inde örnek soru-cevap göster]**

**Örnek soru**: "What ICS protocols does this device expose, and which of them have unauthorised-write attempts in the captured traffic?"

> "The copilot pulls from the Library, cross-checks against the captured PCAP, and answers with citations. This is the bridge between documentation and real network behaviour, the differentiator HMGCC's brief asks for."

**[Research -> Vulns'a tıkla]**

> "Vulns view: 'needs more sources' flag, draft status, confidence labels. Direct evidence for the L3 confidence-scoring layer described in our proposal."

**[Görsel notu]**: Threads tab'inde citation pill'lere hover et, tooltip'leri göster. Confidence label'ı vurgula.

---

## 5:00 to 6:00 — Live Threat Intelligence

**[Mode'u SOC'a geri al, Detect -> Threat Intelligence'a tıkla]**

> "Last stop: live threat intelligence. Safetech Global operates an internet-exposed decoy fabric using the same platform. It is capturing real ICS-protocol attacks from real attackers, right now.
>
> To date we have recorded 157 unique attackers from 20 countries, executing 12,968 attacks. Everything from script-kiddie scans to advanced actors targeting ICS-specific protocol weaknesses across SCADA communication protocols."

**[Geo map: 19 ülke vurgulanmış, attacker dots]**

> "Here is the live engagement geography. Each dot is a real attacker against the decoy fabric. We can drill into any one of them."

**[Bir attacker'a tıkla -> session detail]**

> "This attacker session shows the protocol probed, the function codes attempted, the IOCs extracted, the MITRE ATT&CK techniques mapped, and a behavioural fingerprint we use to cluster across sessions.
>
> For HMGCC, this matters because the decoy fabric feed is packaged as **signed update bundles** for the air-gapped Phase 1 tool. The HMGCC laptop never connects to the internet, but its corpus and detection signatures stay current via a one-way watch-folder ingest. This is how we deliver the offline-update desirable requirement without breaking the air-gap requirement."

**[Detect -> Attacker TTPs -> campaign clusters]**

> "Campaign clustering: same fingerprint plus overlapping ASN or country. This is what feeds the verifier's on-wire cross-check in the Research Mode copilot."

**[Görsel notu]**: Geo map'in ekran kaplayan görüntüsü 5 saniye süreyle. Attacker dot'larının pulse animasyonu varsa kullan.

---

## 6:00 to 6:30 — Closing

**[Ana ekrana dön, OTShield logosu + Safetech Global]**

> "What you have just seen is OTShield today: a working platform with a working SOC mode at TRL 5, a working Research mode at TRL 3 to 4, and a live decoy fabric capturing real attacker traffic.
>
> What HMGCC Phase 1 funding builds on top of this: a calibrated conformal-prediction confidence layer, an agentic verifier with on-wire cross-check, a multilingual ingest pipeline with NLLB-200 prioritising HMGCC's stated languages (German, Japanese, French, Chinese) plus a technical-term dictionary curated with HMGCC, a multi-modal ingest pipeline with OCR, handwriting and schematic understanding, and an adaptive researcher profile.
>
> Twelve weeks. Sixty thousand pounds. TRL 6. Delivered with a reproducible benchmark harness so HMGCC can verify every metric we claim.
>
> We are pre-revenue with three published price tiers and an active customer pipeline, so HMGCC is not a sole customer. The platform you just saw is the one we are taking to commercial customers under NIS2, IEC 62443 and NCSC CAF.
>
> Thank you for watching. Questions are welcome at fatma.erturk@otshield.io."

**[Görsel notu]**: Son 5 saniye — OTShield logo, Safetech Global Limited, contact email, Companies House numarası 15233187. Sade.

---

## Çekim notları (production checklist)

**Demo verileri** (önceden hazırlanması gereken):
- [ ] Real-attack PCAP dosyası (Modbus + S7 unauthorised-write desenli) — DEMO_attack_capture.pcap
- [ ] Mevcut Research Bundle (Library'de 3-5 vendor manual, Inventory dolu, en az bir Thread)
- [ ] Internet-exposed decoy fabric'in canlı veri göstermesi (geo map'in dolu olduğu zaman çek)

**Teknik ayarlar**:
- [ ] Browser zoom: 100%, ekran çözünürlüğü 1920x1080
- [ ] Tarayıcı: Chrome incognito, bookmarks bar gizli
- [ ] Cursor highlight: ekrana büyük ve renkli imleç gerekli (Mouse Highlighter veya benzer)
- [ ] Background music: yumuşak ambient, %15 ses
- [ ] Voiceover: tek take, sessiz oda; mikrofona 15-20 cm
- [ ] Screen recording: 60fps, ses ayrı track

**Aktarım sırası** (önemli):
1. SOC Mode (PCAP + asset + MITRE) → 0:00 - 3:30
2. Mode toggle → Research Mode → 3:30
3. Research → 3:30 - 5:00
4. Mode toggle → SOC Mode → 5:00
5. Threat intelligence → 5:00 - 6:00
6. Closing → 6:00 - 6:30

**Geçişler**: Mode toggle'da 0.5 saniyelik fade var, yeterli. Section'lar arası 1 saniye'lik siyah ekran istemiyoruz (kesintisiz akış).

**Ne yapma listesi**:
- "Production'da" demek yerine "today" / "running today" de
- "Customer'da deployed" deme — pre-revenue
- "8+ ICS protocols" deme — Modbus + S7Comm dedicated, diğerleri port-based
- Conpot adını ASLA telaffuz etme
- Honeypot kelimesini kullanma — "decoy fabric"
- Gemma 4'ün BUGÜN çalıştığı izlenimini verme — "in Phase 1 we upgrade to..."

**Süre yönetimi**:
- 5 dakika hedef, 7 dakika tavan
- Eğer aşıyorsan: SOC Mode kısmı 3'ü (Alerts) çıkar
- Eğer çok kısaysa: Research Mode'da Threads tab'inde ikinci bir soru-cevap göster

---

## Pitch Day kısa versiyonu (2-3 dakika)

Eğer kısa listeye girdiğinde Pitch Day için 2-3 dakikalık özet versiyon istersen:

1. 0:00-0:20: OTShield nedir, iki mod (yukarıdaki ile aynı)
2. 0:20-1:00: SOC Mode tek geçiş — PCAP -> asset -> MITRE -> alert (hızlı montaj)
3. 1:00-2:00: Research Mode + Threads copilot
4. 2:00-2:30: Decoy fabric live attacker map (10 saniye), 157/20/12968 sayıları
5. 2:30-2:45: Closing (12 hafta / £60K / TRL 6)

Bu kısa versiyon HMGCC short-list pitch'inde 20 dakikalık slot'un içine demo bölümü olarak gömülebilir.

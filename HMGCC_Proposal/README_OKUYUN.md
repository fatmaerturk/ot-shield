# OTShield, HMGCC Proposal Paketi

Bu klasör HMGCC Co-Creation başvurusu için **6 sayfalık ana proposal + 3 ek belge (Annex A, B, C)** içeriyor.

## Submission stratejisi (HMGCC Q&A Q6 sonrası güncellendi)

HMGCC Q&A (Q6) net hale getirdi: **"Diagrams, tables and images count towards the six-page limit. Any information that the bidder would like to be assessed should be included within the six-pages."** Limit dışı sadece **title pages, references, personnel CVs ve organisational profiles**.

Bu yüzden strateji ayarlandı:

- **Ana 6-sayfa proposal puanlanan tek belgedir.** Tüm essential (8/8), desirable (4/4), tech stack, deliverables, budget, team, risk, exploitation/Phase 2 zaten 6 sayfa içinde — Q6 sonrası hiçbir kritik bilgi annex'lere bağımlı bırakılmadı.
- **Annex C** (Team CVs + Organisational Profile) HMGCC'nin explicit istisnasıdır (Q6: "personnel CVs and organisational profiles" limit dışı). Bid structure, security posture, BPSS readiness gibi destekleyici bilgi de buraya konuldu.
- **Annex A, B, D, E** *optional supporting evidence* olarak yeniden konumlandı. Her annex'in açılış paragrafı "Reading this annex is not required for evaluation" diyor. Reviewer açarsa hızlı doğrulama, açmazsa puanlama etkilenmez.

HMGCC submission portalında ana proposal'ı zorunlu alana, Annex C'yi "supporting documents" alanına yükleyin. Annex A/B/D/E'yi de yüklemek opsiyonel; faydaları "hızlı reference verification" sınırlıdır.

## Dosyalar

### 1. `OTShield_HMGCC_Proposal.html`  ← **ANA PROPOSAL: 6 sayfa**
- Word'de açın, **File → Save As → PDF** yapın.
- Sayfa düzeni: kompakt 9.5pt font, 0.5/0.6in margins, 5 page-break = 6 sayfa garantili.
- HMGCC submission portalında ana başvuru olarak yükleyin.

### 2. `Annex_A_Technical_Architecture.html`
- Sistem mimarisi (5-modül diyagramı), end-to-end veri akışı, modül-modül spesifikasyonlar, IP register detayı, air-gap-safe update bundle yaklaşımı.
- Word'de açın → PDF olarak kaydedin.
- **Supporting document** olarak yükleyin.

### 3. `Annex_B_Capability_and_Threat_Intel.html`
- OTShield'in mevcut yetenekleri (Research Mode, SOC Mode, Decoy, PCAP, MITRE ATT&CK).
- Live threat-intel verileri (157 attackers, 20 countries, 12,968 attacks).
- Attacker profile mix (script-kiddie + advanced ICS-aware).
- Commercial customer pipeline ve dual-use kanıtı.
- Word'de açın → PDF olarak kaydedin.
- **Supporting document** olarak yükleyin.

### 4. `Annex_C_Team_and_Profile.html`
- Takım üyelerinin detaylı CV'leri (placeholder'lar dolu hâlde).
- OTShield organisational profile.
- Trusted Research / Secure Innovation posture.
- **Submission'dan önce PLACEHOLDER alanlarını doldurun.**
- Word'de açın → PDF olarak kaydedin.
- **Supporting document** olarak yükleyin (CV/profile zaten 6 sayfa limitinin dışındadır).

### 5. `Annex_D_Visual_Capability_Overview.html` + OTShield tanıtım PDF'i
- Bu HTML dosyası, mevcut OTShield tanıtım dokümanına bir **kapak sayfası** sağlar: HMGCC reviewer'a hangi görselin neyi kanıtladığını sayfa-sayfa anlatır.
- **İki adımda yükleyin:**
  1. Bu HTML'i Word'de açıp PDF olarak kaydedin (kapak/intro PDF).
  2. Mevcut OTShield tanıtım PDF'ini kapağın arkasına ekleyin: ya iki PDF'i birleştirin (Adobe Acrobat veya online PDF merger ile), ya da iki ayrı dosya olarak yükleyin (`Annex_D_cover.pdf` + `Annex_D_visual.pdf`).
- Amaç: OTShield'in görsel infografiğini "marketing material" gibi değil, "live capability evidence" olarak sunmak. Reviewer kapaktaki tabloyu okuyup hangi sayfada hangi HMGCC requirement'ının kanıtının olduğunu anlar.
- **Supporting document** olarak yükleyin.

### 6. `Annex_E_Commercial_Maturity_and_Partners.html` + OTShield Partner Benefit PDF'i
- Bu HTML, OTShield'in Partner Benefit dokümanı için kapak sağlar. Reviewer'ın "bu sales material" diye geçiştirmemesi için, **dual-use commercial proof** çerçevesinde sunar.
- İçerik vurguları:
  - 5 tipik reviewer endişesini ve Annex E'nin bunlara nasıl cevap verdiğini gösteren tablo
  - Üç publicly listed pricing tier (£20k/£50k/£75k Starter/Growth/Advanced)
  - Channel partner programı + Cisco hardware/software deployment
  - Dragos/Claroty ile complementary positioning (NOT replacing)
  - NIS2 / IEC 62443 / NCSC CAF alignment
  - SIEM / SOAR / ITSM / CMDB / TAXII-MISP integration matrix
- **İki adımda yükleyin** (Annex D ile aynı yöntem):
  1. Bu HTML'i Word'de açıp PDF olarak kaydedin.
  2. Partner Benefit PDF'iyle birleştirin (Adobe Acrobat veya ilovepdf.com).
- Sonuç: `Annex_E_Commercial_Maturity_and_Partners.pdf` (kapak + partner doc).
- **Supporting document** olarak yükleyin.

### 7. `OTShield_HMGCC_Proposal.md`
- Markdown sürümü ana proposal. Pandoc ile Word'e dönüştürebilirsiniz.

### 6. `Reviewer_Reply_Email.md`
- HMGCC ile çalışan reviewer'a cevap maili taslağı.
- 4 feedback noktasını da kapsıyor.

## Submission öncesi yapılacaklar

1. **PLACEHOLDER alanlarını doldur** (HTML ve Annex C'de):
   - Şirket bilgileri (legal name, registration, address, contact)
   - Takım üyelerinin isimleri ve detaylı özgeçmişleri
   - Organisational profile metni

2. **Word'de açıp PDF olarak kaydet**: ana proposal + Annex A + Annex B + Annex C + Annex D kapak + Annex E kapak. Toplam 6 PDF (kapaklar dahil).

3. **Annex D ve Annex E için ekstra adım**: kapak PDF'lerini ilgili görsel/partner PDF'lerle birleştirin (Adobe Acrobat: Tools → Combine Files; veya ilovepdf.com / smallpdf.com gibi ücretsiz araçlarla):
   - `Annex_D_OTShield_Visual_Capability_Overview.pdf` = Annex D kapak + OTShield tanıtım PDF
   - `Annex_E_Commercial_Maturity_and_Partners.pdf` = Annex E kapak + OTShield Partner Benefit PDF

4. **Sayfa kontrolü:** Word'de Print Preview → ana proposal MUTLAKA 6 sayfada olmalı. Eğer 7. sayfaya taşarsa:
   - En son satıra eklenen "Supporting documents" notu çıkarılabilir
   - Section 4 ve Section 5 başlıklarındaki açıklayıcı kısımlar (": how we will work with HMGCC" gibi) kısaltılabilir
   - Section 1 OTShield today tablosundaki "Commercial maturity & regulatory alignment" satırı kısaltılabilir veya çıkarılıp tüm bilgi sadece Annex E'de bırakılabilir

5. **HMGCC portal**:
   - Ana proposal: ana başvuru alanına yükle
   - Annex A, B, C, D, E: supporting documents alanına yükle (her biri ayrı dosya)

## İçerik Yapısı (Ana Proposal, 6 Sayfa)

| Sayfa | Bölüm |
|-------|-------|
| 1 | Applicant details (kompakt) + Section 1 (Scope, OTShield today tablosu, mapping) |
| 2 | Section 2 (System approach paragrafı + Innovation tablosu + IP) |
| 3 | Section 3 (Deliverables: 8/8 essential, 4/4 desirable, concrete deliverables) |
| 4 | Section 4 (Co-creation engagement) + Section 5 (Sprint plan) |
| 5 | Section 6 (Budget detaylı) |
| 6 | Section 7 (Team) + Section 8 (Exploitation/Phase 2/Risk) + closing |

## İçerik Yapısı (Annex'ler)

| Belge | İçerik |
|-------|-------|
| Annex A | Mimari diyagram, end-to-end flow, modül specs (1-5), innovation→modül haritası, air-gap-safe update bundle yaklaşımı, IP register detay |
| Annex B | OTShield live capabilities tablosu, threat-intel rakamları (157/20/12,968), attacker profile mix, RAG'dan farklılaşma, commercial pipeline |
| Annex C | 4 takım üyesi için CV blokları (placeholder), org profile (Safetech Global), accelerator track record, awards, trusted research posture |
| Annex D | Görsel capability overview kapağı + OTShield tanıtım PDF'i. Her ekran/sayfa hangi HMGCC requirement'ı kanıtladığı tablosuyla çerçevelenmiş |
| Annex E | Commercial maturity kapağı + Partner Benefit PDF'i. Pricing tiers, channel programı, Dragos/Claroty coexistence, NIS2/IEC 62443/CAF alignment, SIEM/SOAR/ITSM/CMDB integration matrix |

## Adreslenmiş Feedback Noktaları (cumulative)

**Reviewer'ın 3 noktası:**
1. **Dual-use** → Section 1 + OTShield today tablosu + Section 8'de güçlü adres
2. **Multilingual 12-week plan** → Section 3'te Sprint 1-Sprint 3 sprint-by-sprint
3. **Co-creation** → Section 4 yeni, Annex A'ya bağlı

**Geçmiş HMGCC feedback'i:**
4. **Overall system approach** → Section 2 kompakt özet + Annex A detaylı

**Stratejik vurgular:**
5. **OTShield mevcut yetenekleri** → Section 1 OTShield today + Annex B
6. **Em-dash temizliği** → tüm em/en dash'ler kaldırıldı, UK English standardı

**Yeni: Live threat-intel + air-gap çözümü:**
7. **Online ICS decoy + offline tool köprüsü** → signed update bundles, hem mevcut "must work offline" zorunluluğu korunuyor hem desirable update mechanism çözülüyor

## Son Tarihler

- **Son başvuru:** 7 Mayıs 2026, Perşembe
- Sonuç bildirimi: 22 Mayıs 2026
- Pitch Day: 2 Haziran 2026
- Onboarding: 12 Haziran 2026
- Proje başlangıcı: Temmuz 2026

## Pitch Day (2 Haziran 2026)

Eğer kısa listeye girerseniz, 20 dakikalık pitch için ayrı bir slayt setine ihtiyacınız olacak. Bana haber verirseniz, bu proposal'dan üretilmiş 6-10 slaytlık bir .pptx hazırlarım.

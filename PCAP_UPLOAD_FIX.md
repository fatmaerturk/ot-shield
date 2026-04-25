# PCAP Upload "Server error" Hatası - Çözüm Kılavuzu

## Yapılan Düzeltmeler

1. **Frontend hata mesajları iyileştirildi** - Artık backend'den gelen detaylı hata mesajlarını gösterecek
2. **Backend logging iyileştirildi** - Hatalar artık daha detaylı loglanıyor

## Sorun Tespiti

PCAP yükleme hatası alıyorsanız, şu adımları takip edin:

### 1. Backend Loglarını Kontrol Edin

Backend'i çalıştırdığınız terminal penceresinde hata mesajlarını kontrol edin. Şu hatalardan biri görünebilir:

- **PCAP4J native library not available**: Npcap yüklü değil
- **File does not exist**: Dosya yolu sorunu
- **File is not readable**: Dosya izinleri sorunu
- **PCAP analysis error**: PCAP dosyası parse edilemiyor

### 2. PCAP4J Health Check

Backend çalışırken tarayıcınızda şu URL'yi açın:
```
http://localhost:8080/api/health/pcap
```

Bu endpoint PCAP4J'nin çalışıp çalışmadığını gösterir.

### 3. Npcap Kurulumu (Windows)

PCAP4J için Npcap gereklidir:

1. https://npcap.com/ adresinden Npcap'i indirin
2. Kurulum sırasında "Install Npcap in WinPcap API-compatible Mode" seçeneğini işaretleyin
3. Kurulumdan sonra bilgisayarı yeniden başlatın
4. Backend'i yeniden başlatın

### 4. Dosya Formatı Kontrolü

- Sadece `.pcap` ve `.pcapng` dosyaları desteklenir
- Dosya boyutu maksimum 2GB olabilir

### 5. Upload Dizini Kontrolü

Backend'in çalıştığı dizinde `uploads/` klasörünün oluşturulduğundan emin olun. Backend otomatik olarak oluşturur, ancak izin sorunu olabilir.

## Hata Mesajları ve Çözümleri

### "PCAP4J native library not available"
**Çözüm:** Npcap'i yükleyin (yukarıdaki adım 3)

### "Dosya yükleme hatası"
**Olası nedenler:**
- Dosya çok büyük (2GB'den fazla)
- Disk alanı yetersiz
- Dosya izinleri sorunu

**Çözüm:**
- Daha küçük bir PCAP dosyası deneyin
- Disk alanını kontrol edin
- Backend'i yönetici olarak çalıştırın

### "PCAP analiz hatası"
**Olası nedenler:**
- PCAP dosyası bozuk
- Desteklenmeyen PCAP formatı

**Çözüm:**
- Farklı bir PCAP dosyası deneyin
- Dosyanın geçerli bir PCAP dosyası olduğundan emin olun

### "Could not connect to server"
**Çözüm:**
- Backend'in çalıştığından emin olun (http://localhost:8080)
- Frontend'deki proxy ayarını kontrol edin (`frontend/package.json`)

## Test Adımları

1. Backend'i başlatın:
```powershell
cd backend
mvn spring-boot:run
```

2. Backend loglarını izleyin - hata mesajları görünecek

3. Frontend'den PCAP dosyası yüklemeyi deneyin

4. Hata mesajını not edin ve backend loglarıyla karşılaştırın

## Geliştirici Notları

- PCAP4J native library yoksa, sistem otomatik olarak simüle edilmiş veri üretir
- Bu durumda PCAP analizi gerçek paketleri parse etmez, ancak sistem çalışmaya devam eder
- Gerçek PCAP analizi için Npcap kurulumu şarttır

## İletişim

Sorun devam ederse, backend loglarını ve frontend console hatalarını kontrol edin ve hata mesajlarını not edin.


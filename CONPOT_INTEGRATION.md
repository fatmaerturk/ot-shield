# Conpot Integration for OTSHIELD

Bu dokümantasyon, OTSHIELD projesinde Conpot honeypot entegrasyonunun nasıl kullanılacağını açıklar.

## 🎯 Özellikler

- **Gerçek Zamanlı Log Takibi**: Conpot logları 2 saniyede bir güncellenir
- **Start/Stop Kontrolü**: Conpot honeypot'unu başlatma ve durdurma
- **İstatistik Analizi**: Bağlantı sayısı, Modbus istekleri, benzersiz IP'ler
- **Simülasyon Modu**: Python yüklü değilse otomatik simülasyon
- **Güvenli API**: JWT tabanlı kimlik doğrulama

## 🚀 Kurulum

### 1. Otomatik Kurulum (Önerilen)

Windows'ta `install_conpot.bat` dosyasını çalıştırın:

```bash
install_conpot.bat
```

### 2. Manuel Kurulum

#### Python Kurulumu
1. [Python'u indirin](https://www.python.org/downloads/)
2. Kurulum sırasında **"Add Python to PATH"** seçeneğini işaretleyin

#### Conpot Kurulumu
```bash
pip install conpot
```

## ▶️ Conpot'u Nasıl Çalıştırırsınız?

### Gerçek Conpot (simülasyon değil) için

Simülasyon modunda kalmamak için:

1. **Conpot’un kurulu olduğu Python’u kullanın** (örn. Python 3.11; 3.14’te Conpot sorunlu).
2. **`backend/src/main/resources/application.properties`** içinde:
   - `conpot.python.path` satırını **Conpot kurduğunuz** Python’un tam yoluna ayarlayın (3.14 değil).
   - Örnek (Conpot’u 3.11 ile kurduysanız):
     ```properties
     conpot.python.path=C:\\Users\\Fancy\\AppData\\Local\\Programs\\Python\\Python311\\python.exe
     ```
3. **Backend’i yeniden başlatın**, sonra arayüzden **Start Conpot** deyin.

Conpot’u hangi Python’a kurduğunuzu bilmiyorsanız, o Python ile terminalde çalıştırın:
`"C:\...\Python311\python.exe" -c "import conpot; print('OK')"`

### Yöntem 1: Arayüzden (Önerilen)

1. **Backend'i çalıştırın** (proje kökünde veya `backend` klasöründe):
   ```bash
   cd backend
   mvn spring-boot:run
   ```
2. **Frontend'i çalıştırın**:
   ```bash
   cd frontend
   npm start
   ```
3. Tarayıcıda **http://localhost:3000** adresine gidin, giriş yapın.
4. **Integrations → Conpot** menüsüne gidin.
5. **"Start Conpot"** butonuna tıklayın.

Bu yöntem için sadece **Python** ve **`pip install conpot`** yeterlidir; projede ayrıca bir `conpot` klasörü olması gerekmez.

### Yöntem 2: Komut satırından (bağımsız)

Conpot'u OTShield dışında, doğrudan terminalde çalıştırmak için:

```bash
# Conpot kurulu değilse:
pip install conpot

# Çalıştırma (foreground, default template):
conpot -f --template default
# veya
python -m conpot -f --template default
```

Logları dosyaya yazmak için:

```bash
conpot -f --template default --logfile conpot.log
```

## 📊 API Endpoints

### Conpot Kontrolü
- `POST /api/conpot/start` - Conpot'u başlat
- `POST /api/conpot/stop` - Conpot'u durdur
- `GET /api/conpot/status` - Durum kontrolü

### Log Yönetimi
- `GET /api/conpot/logs` - Logları getir
- `DELETE /api/conpot/logs` - Logları temizle

### İstatistikler
- `GET /api/conpot/statistics` - İstatistikleri getir
- `GET /api/conpot/health` - Sağlık kontrolü

## 🎮 Kullanım

### Frontend'de Conpot Sayfası

1. **Navigasyon**: "Integrations" > "Conpot" menüsüne gidin
2. **Başlatma**: "Start Conpot" butonuna tıklayın
3. **İzleme**: Gerçek zamanlı logları takip edin
4. **Durdurma**: "Stop Conpot" butonuna tıklayın

### Dashboard Özellikleri

- **İstatistik Kartları**: Toplam saldırı, benzersiz IP, ülke sayısı
- **Grafikler**: Saldırı dağılımı, zaman serisi, ülke bazlı analiz
- **Tag Cloud'lar**: Kullanıcı adı ve şifre denemeleri
- **Canlı Loglar**: Gerçek zamanlı Modbus trafiği

## 🔧 Konfigürasyon

### Backend Konfigürasyonu

`ConpotService.java` dosyasında:

```java
// Log dizini
private final Path logDirectory = Paths.get("conpot_logs");

// Simülasyon log aralığı (saniye)
scheduler.scheduleAtFixedRate(this::generateSimulatedLogs, 0, 5, TimeUnit.SECONDS);
```

### Frontend Konfigürasyonu

`Conpot.tsx` dosyasında:

```typescript
// Log güncelleme aralığı (milisaniye)
interval = setInterval(fetchLogs, 2000);
```

## 🐛 Sorun Giderme

### Windows: "Could not build wheels for crc16, pycrypto"
Bu paketler C derleyicisi gerektirir. Seçenekler:

1. **Simülasyon modu (en kolay):** Uygulamada **Start Conpot** deyin; Conpot kurulu değilse otomatik simülasyon modu açılır ve demo loglar görünür.
2. **C++ Build Tools ile kurulum:** [Build Tools for Visual Studio 2022](https://visualstudio.microsoft.com/visual-cpp-build-tools/) indirip kurun, "Desktop development with C++" seçin. Yeni bir terminal açıp `pip install conpot` çalıştırın.
3. **Script deneyin:** Proje kökünde `install_conpot_windows.bat` çalıştırın; önce `pycryptodome` kurulur, sonra Conpot denenir.

### Conpot Başlatılamıyor
1. Python'un PATH'te olduğunu kontrol edin
2. `pip install conpot` komutunu manuel çalıştırın
3. Simülasyon modu otomatik olarak devreye girer

### Loglar Görünmüyor
1. Backend'in çalıştığını kontrol edin
2. Browser console'da hata mesajlarını kontrol edin
3. Network sekmesinde API çağrılarını kontrol edin

### API Hataları
1. CORS ayarlarını kontrol edin
2. Security config'de `/api/conpot/**` endpoint'inin açık olduğunu kontrol edin
3. JWT token'ın geçerli olduğunu kontrol edin

## 📈 Simülasyon Modu

Python yüklü değilse sistem otomatik olarak simülasyon moduna geçer:

- **Gerçekçi Loglar**: Modbus protokolü simülasyonu
- **Çeşitli IP'ler**: 192.168.1.100, 10.0.0.50, 172.16.0.10
- **Farklı İstekler**: Read, Write, Exception durumları
- **Zaman Damgaları**: Gerçekçi timestamp'ler

## 🔒 Güvenlik

- **JWT Authentication**: Tüm API çağrıları kimlik doğrulama gerektirir
- **CORS Protection**: Sadece localhost:3000'den erişim
- **Input Validation**: Tüm girişler doğrulanır
- **Error Handling**: Güvenli hata mesajları

## 📝 Log Formatı

```
2024-01-15 10:30:15 - New connection from 192.168.1.100:502 (Modbus)
2024-01-15 10:30:16 - Modbus read request: Function code 3, Address 0x0000
2024-01-15 10:30:17 - Modbus write request: Function code 6, Address 0x0001
2024-01-15 10:30:18 - Connection closed from 192.168.1.100
```

## 🎯 Gelecek Özellikler

- [ ] WebSocket ile gerçek zamanlı log streaming
- [ ] Modbus protokolü detaylı analizi
- [ ] Saldırı tespiti ve uyarı sistemi
- [ ] Log export/import özellikleri
- [ ] Çoklu Conpot instance desteği

## 📞 Destek

Sorun yaşarsanız:
1. Backend loglarını kontrol edin
2. Frontend console'da hataları kontrol edin
3. API endpoint'lerini test edin
4. GitHub issues'da sorun bildirin 
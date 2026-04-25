# OTShield v1 - Kurulum ve Çalıştırma Kılavuzu

Bu doküman, OTShield uygulamasının backend ve frontend bileşenlerini nasıl çalıştıracağınızı açıklar.

## Gereksinimler

### Backend Gereksinimleri
- **Java 17** veya üzeri
- **Maven 3.6+**
- **PostgreSQL 12+** (veya H2 Database - geliştirme için)
- **Npcap** (PCAP dosyaları için - Windows)

### Frontend Gereksinimleri
- **Node.js 16+** ve **npm** (veya **yarn**)

## Veritabanı Kurulumu

### PostgreSQL Kurulumu

1. PostgreSQL'i yükleyin ve çalıştırın
2. Veritabanını oluşturun:
```sql
CREATE DATABASE otshield_db;
```

3. `backend/src/main/resources/application.properties` dosyasında veritabanı ayarlarını kontrol edin:
```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/otshield_db
spring.datasource.username=postgres
spring.datasource.password=postgres
```

**Not:** Veritabanı kullanıcı adı ve şifrenizi `application.properties` dosyasında güncelleyin.

## Backend Kurulumu ve Çalıştırma

### 1. Backend Dizinine Gidin
```bash
cd backend
```

### 2. Bağımlılıkları Yükleyin ve Derleyin
```bash
mvn clean install
```

### 3. Uygulamayı Çalıştırın

**Maven ile:**
```bash
mvn spring-boot:run
```

**veya JAR dosyası oluşturup çalıştırın:**
```bash
mvn clean package
java -jar target/login-app-backend-1.0-SNAPSHOT.jar
```

Backend başarıyla çalıştığında `http://localhost:8080` adresinde erişilebilir olacaktır.

### Varsayılan Kullanıcı Bilgileri

Uygulama ilk çalıştırıldığında otomatik olarak bir admin kullanıcısı oluşturulur:
- **Email:** fatma.erturk@otshield.io
- **Şifre:** Alex123@@@
- **Rol:** ROLE_ADMIN

## Frontend Kurulumu ve Çalıştırma

### 1. Frontend Dizinine Gidin
```bash
cd frontend
```

### 2. Bağımlılıkları Yükleyin
```bash
npm install
```

**Not:** TypeScript sürüm uyumsuzluğu hatası alırsanız, `package.json` dosyasında TypeScript versiyonu `^4.9.5` olarak ayarlanmıştır. Eğer hala sorun yaşarsanız:
```bash
npm install --legacy-peer-deps
```

### 3. Uygulamayı Çalıştırın
```bash
npm start
```

Frontend başarıyla çalıştığında tarayıcınızda otomatik olarak `http://localhost:3000` adresi açılacaktır.

**Not:** Frontend, backend ile iletişim kurmak için `package.json` dosyasındaki proxy ayarını kullanır (`"proxy": "http://localhost:8080"`).

## Uygulamayı Tam Olarak Çalıştırma

1. **PostgreSQL veritabanını başlatın**
2. **Backend'i çalıştırın** (8080 portunda)
3. **Frontend'i çalıştırın** (3000 portunda - yeni terminal penceresinde)

### Windows PowerShell Örneği

**Terminal 1 - Backend:**
```powershell
cd backend
mvn spring-boot:run
```

**Terminal 2 - Frontend:**
```powershell
cd frontend
npm start
```

## Sorun Giderme

### PowerShell Execution Policy Hatası (Windows)

PowerShell'de `npm install` veya `npm start` çalıştırırken şu hatayı alıyorsanız:
```
npm : File C:\Program Files\nodejs\npm.ps1 cannot be loaded because running scripts is disabled on this system.
```

**Çözüm 1: Execution Policy'yi Bypass Edin (Önerilen)**
```powershell
powershell -ExecutionPolicy Bypass -Command "cd frontend; npm install"
```

**Çözüm 2: Execution Policy'yi Geçici Olarak Değiştirin**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Sonra normal şekilde:
```powershell
cd frontend
npm install
```

**Çözüm 3: CMD (Komut İstemi) Kullanın**
PowerShell yerine CMD kullanabilirsiniz:
```cmd
cd frontend
npm install
npm start
```

### Backend IDE Hataları (Lombok)

IDE'de `User` sınıfında setter metodları bulunamıyor hatası görüyorsanız:
- Bu normal bir durumdur - Lombok annotation processing compile-time'da setter/getter metodlarını oluşturur
- IDE'de Lombok plugin yüklü değilse bu hataları görebilirsiniz
- Kod derlenir ve çalışır, IDE hataları sadece görseldir
- **Çözüm:** IntelliJ IDEA kullanıyorsanız "Lombok" plugin'ini yükleyin, VS Code kullanıyorsanız "Lombok Annotations Support" extension'ını yükleyin
- Veya sadece `mvn clean install` komutu ile derleyin - kod çalışacaktır

### Backend Bağlantı Hataları
- PostgreSQL'in çalıştığından emin olun
- `application.properties` dosyasındaki veritabanı bilgilerini kontrol edin
- Veritabanının oluşturulduğundan emin olun

### Frontend Proxy Hataları
- Backend'in çalıştığından emin olun (http://localhost:8080)
- `frontend/package.json` dosyasındaki proxy ayarını kontrol edin

### Port Çakışmaları
- Backend varsayılan portu: **8080**
- Frontend varsayılan portu: **3000**
- Bu portlar kullanılıyorsa, ilgili yapılandırma dosyalarında değiştirin

## Ek Notlar

- Backend logları konsolda görüntülenir
- Frontend hot-reload özelliği ile değişiklikler otomatik yansır
- H2 Console'a `http://localhost:8080/h2-console` adresinden erişebilirsiniz (geliştirme modunda)


# IDE Kurulum Kılavuzu - Lombok Plugin

## IntelliJ IDEA için Lombok Plugin Kurulumu

### Adım 1: Plugin Penceresini Açın
1. IntelliJ IDEA'da **File** → **Settings** (veya `Ctrl + Alt + S`) menüsüne gidin
2. Sol menüden **Plugins** seçeneğine tıklayın

### Adım 2: Lombok Plugin'ini Arayın ve Yükleyin
1. Üst kısımdaki arama kutusuna **"Lombok"** yazın
2. **"Lombok"** plugin'ini bulun (JetBrains tarafından geliştirilen)
3. **Install** butonuna tıklayın
4. Yükleme tamamlandıktan sonra **Apply** ve **OK** butonlarına tıklayın
5. IDE'yi yeniden başlatmanız istenecek - **Restart IDE** butonuna tıklayın

### Adım 3: Annotation Processing'i Etkinleştirin
1. **File** → **Settings** → **Build, Execution, Deployment** → **Compiler** → **Annotation Processors**
2. **Enable annotation processing** seçeneğini işaretleyin
3. **Apply** ve **OK** butonlarına tıklayın

### Adım 4: Projeyi Yeniden Derleyin
1. **File** → **Invalidate Caches / Restart...**
2. **Invalidate and Restart** butonuna tıklayın

Artık IDE'de Lombok setter/getter metodlarını görebilmelisiniz!

---

## VS Code için Lombok Extension Kurulumu

### Adım 1: Extension Market'i Açın
1. VS Code'da sol taraftaki **Extensions** ikonuna tıklayın (veya `Ctrl + Shift + X`)
2. Arama kutusuna **"Lombok Annotations Support"** yazın

### Adım 2: Extension'ı Yükleyin
1. **"Lombok Annotations Support for VS Code"** extension'ını bulun
2. **Install** butonuna tıklayın
3. Yükleme tamamlandıktan sonra VS Code'u yeniden başlatın

### Adım 3: Java Extension Pack Kontrolü
VS Code'da Java geliştirme için şu extension'ların yüklü olduğundan emin olun:
- **Extension Pack for Java** (Microsoft tarafından)
- **Language Support for Java(TM) by Red Hat**

### Adım 4: Projeyi Yeniden Yükle
1. **View** → **Command Palette** (veya `Ctrl + Shift + P`)
2. **"Java: Clean Java Language Server Workspace"** komutunu çalıştırın
3. VS Code'u yeniden başlatın

---

## Eclipse için Lombok Kurulumu

### Adım 1: Lombok JAR Dosyasını İndirin
1. https://projectlombok.org/download adresinden `lombok.jar` dosyasını indirin

### Adım 2: Lombok'u Yükleyin
1. Komut satırından şu komutu çalıştırın:
```bash
java -jar lombok.jar
```
2. Açılan pencerede Eclipse kurulum dizininizi seçin
3. **Install / Update** butonuna tıklayın
4. Eclipse'i yeniden başlatın

---

## Alternatif: IDE Olmadan Çalıştırma

IDE plugin'leri yüklemeden de projeyi çalıştırabilirsiniz. Lombok annotation processing Maven derleme sırasında otomatik olarak çalışır:

```powershell
cd backend
mvn clean install
mvn spring-boot:run
```

Bu komutlar IDE hatalarına rağmen başarıyla çalışacaktır çünkü Lombok compile-time'da setter/getter metodlarını oluşturur.

---

## Hangi IDE'yi Kullanıyorsunuz?

- **IntelliJ IDEA** → Yukarıdaki "IntelliJ IDEA için" bölümünü takip edin
- **VS Code** → Yukarıdaki "VS Code için" bölümünü takip edin
- **Eclipse** → Yukarıdaki "Eclipse için" bölümünü takip edin
- **Başka bir IDE** → Maven komutları ile çalıştırabilirsiniz (IDE hataları görseldir, kod çalışır)


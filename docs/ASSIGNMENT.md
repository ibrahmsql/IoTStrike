# 📚 Ödev Projesi: IoTStrike Hardware Security Framework

## Proje Hakkında

Bu proje, **İot Makinalar Güvenliği** dersi kapsamında geliştirilmiş bir IoT güvenlik test framework'üdür.

## Ödev Kapsamı

### 🎯 Hedefler
- IoT cihazlarının güvenlik açıklarını tespit etme
- Donanım seviyesinde güvenlik analizi
- Kablosuz ağ güvenlik testleri
- Side-channel saldırı simülasyonları

### 🛠️ Kullanılan Teknolojiler
- **C/C++**: Ana geliştirme dili
- **Assembly**: Düşük seviye donanım erişimi
- **Zig**: Modern sistem programlama
- **OpenSSL**: Kriptografik işlemler
- **libpcap**: Ağ paket yakalama

### 📋 Özellikler
- ✅ Donanım tarama ve analiz
- ✅ Firmware güvenlik kontrolü
- ✅ Kablosuz ağ penetrasyon testleri
- ✅ Gerçek zamanlı saldırı simülasyonu
- ✅ Side-channel analiz araçları

## Proje Yapısı

```
iotstrike/
├── src/          # Kaynak kodlar
├── include/      # Header dosyaları
├── build/        # Derlenmiş objeler
├── docs/         # Dokümantasyon
├── lib/          # Kütüphaneler
└── tools/        # Test araçları
```

## Derleme ve Çalıştırma

```bash
# Projeyi derle
make clean && make

# Test et
./iotstrike --test

# Donanım taraması
./iotstrike --scan-hardware
```

## Öğrenilen Konular

1. **Sistem Programlama**: C/C++ ile düşük seviye programlama
2. **Donanım Erişimi**: Assembly ile donanım kontrolü
3. **Ağ Güvenliği**: Paket analizi ve kablosuz güvenlik
4. **Kriptografi**: Güvenli iletişim protokolleri
5. **Cross-platform Geliştirme**: Linux/macOS/Windows uyumluluğu

## Notlar

> ⚠️ **Uyarı**: Bu araç sadece eğitim amaçlı geliştirilmiştir. Yalnızca kendi cihazlarınızda veya izin alınmış sistemlerde kullanın.

---

**Geliştirici**:Yiğit İbrahim  
**Tarih**: 2025  
**Ders**: İot Makinalar Güvenliği ve Saldırı teknikleri
**Durum**: Tamamlandı ✅
# Log Analiz API

Bu proje, Apache, Windows Event Log, Firewall ve Application log dosyalarını analiz eden bir REST API sunar.

## Kurulum

1. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

2. Uygulamayı çalıştırın:
```bash
python run.py
```

Uygulama varsayılan olarak http://localhost:8090 adresinde çalışacaktır.

## API Kullanımı

### Log Analizi

Aşağıdaki endpoint'ler ile farklı log dosyalarını analiz edebilirsiniz:

- **Apache Log Analizi**:
  ```bash
  curl -X POST "http://localhost:8090/analyze-apache" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@/path/to/your/apache.log"
  ```

- **Windows Event Log Analizi**:
  ```bash
  curl -X POST "http://localhost:8090/analyze-windows" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@/path/to/your/windows.log"
  ```

- **Firewall Log Analizi**:
  ```bash
  curl -X POST "http://localhost:8090/analyze-firewall" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@/path/to/your/firewall.log"
  ```

- **Application Log Analizi**:
  ```bash
  curl -X POST "http://localhost:8090/analyze-application" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@/path/to/your/application.log"
  ```

### API Dokümantasyonu

Swagger UI üzerinden API dokümantasyonuna erişebilirsiniz:
http://localhost:8090/docs

## Örnek Çıktı

Her bir log tipi için örnek çıktılar aşağıdaki gibidir:

### Apache Log Analizi
```json
{
  "log_type": "apache",
  "total_lines": 3,
  "sample_data": [...],
  "status_counts": {...},
  "zaman_bazli_analiz": {...},
  "anomali_raporu": [...],
  "ip_bazli_analiz": {...},
  "hata_analizi": {...}
}
```

### Windows Event Log Analizi
```json
{
  "log_type": "windows_event",
  "total_events": 3,
  "sample_data": [...],
  "zaman_bazli_analiz": {...},
  "anomali_raporu": [...],
  "ip_bazli_analiz": {...},
  "guvenlik_analizi": {...}
}
```

### Firewall Log Analizi
```json
{
  "log_type": "firewall",
  "total_events": 3,
  "sample_data": [...],
  "zaman_bazli_analiz": {...},
  "anomali_raporu": [...],
  "ip_bazli_analiz": {...},
  "guvenlik_analizi": {...}
}
```

### Application Log Analizi
```json
{
  "log_type": "application",
  "total_events": 3,
  "sample_data": [...],
  "zaman_bazli_analiz": {...},
  "anomali_raporu": [...],
  "ip_bazli_analiz": {...},
  "hata_analizi": {...}
}
``` 

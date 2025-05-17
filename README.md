# Apache Log Analiz API

Bu proje, Apache web sunucusu log dosyalarını analiz eden bir REST API sunar.

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

`POST /analyze` endpoint'ine bir Apache log dosyası göndererek analiz yapabilirsiniz.

Örnek curl komutu:
```bash
curl -X POST "http://localhost:8090/analyze" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@/path/to/your/apache.log"
```

### API Dokümantasyonu

Swagger UI üzerinden API dokümantasyonuna erişebilirsiniz:
http://localhost:8090/docs

## Örnek Çıktı

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
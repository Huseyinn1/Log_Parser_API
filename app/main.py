from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from app.models import LogParseRequest
from app.parsers.apache_parser import parse_apache_log_pandas
from app.analyzers.apache_analyzer import (
    zaman_bazli_analiz,
    anomali_tespiti,
    ip_bazli_analiz,
    hata_analizi
)
from app.parsers.windows_parser import parse_windows_event_log
from app.analyzers.windows_analyzer import (
    windows_zaman_bazli_analiz,
    windows_anomali_tespiti,
    windows_ip_bazli_analiz,
    windows_guvenlik_analizi
)
from app.parsers.syslog_parser import parse_syslog
from app.analyzers.syslog_analyzer import syslog_analiz
from app.parsers.firewall_parser import parse_firewall_log
from app.analyzers.firewall_analyzer import firewall_analiz
from app.parsers.application_parser import parse_application_log
from app.analyzers.application_analyzer import application_analiz

app = FastAPI(
    title="Log Analiz API",
    description="Apache, Windows, Firewall ve Application log dosyalarını analiz eden API",
    version="1.0.0"
)

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/parse-log")
def parse_log_api(request: LogParseRequest, log_type: str = Query("apache", enum=["apache", "windows", "firewall", "application"])):
    if log_type == "apache":
        df = parse_apache_log_pandas(request.log_content)
        if df.empty:
            raise HTTPException(status_code=400, detail="Apache log içeriği parse edilemedi veya boş.")
        response = {
            "log_type": "apache",
            "total_lines": len(df),
            "sample_data": df.head(5).to_dict(orient='records'),
            "status_counts": df['status'].value_counts().to_dict(),
            "zaman_bazli_analiz": zaman_bazli_analiz(df),
            "anomali_raporu": anomali_tespiti(df),
            "ip_bazli_analiz": ip_bazli_analiz(df),
            "hata_analizi": hata_analizi(df),
        }
    elif log_type == "windows":
        df = parse_windows_event_log(request.log_content)
        if df.empty:
            raise HTTPException(status_code=400, detail="Windows Event Log içeriği parse edilemedi veya boş.")
        response = {
            "log_type": "windows_event",
            "total_events": len(df),
            "sample_data": df.head(5).to_dict(orient='records'),
            "zaman_bazli_analiz": windows_zaman_bazli_analiz(df),
            "anomali_raporu": windows_anomali_tespiti(df),
            "ip_bazli_analiz": windows_ip_bazli_analiz(df),
            "guvenlik_analizi": windows_guvenlik_analizi(df)
        }
    elif log_type == "firewall":
        df = parse_firewall_log(request.log_content)
        if df.empty:
            raise HTTPException(status_code=400, detail="Firewall log içeriği parse edilemedi veya boş.")
        response = firewall_analiz(df)
    elif log_type == "application":
        df = parse_application_log(request.log_content)
        if df.empty:
            raise HTTPException(status_code=400, detail="Application log içeriği parse edilemedi veya boş.")
        response = application_analiz(df)
    else:
        raise HTTPException(status_code=400, detail="Desteklenmeyen log tipi.")
    
    return response

@app.post("/analyze-apache")
async def analyze_apache_log(file: UploadFile = File(...)):
    """
    Apache log dosyasını analiz eder ve sonuçları JSON olarak döndürür.
    """
    try:
        content = await file.read()
        log_content = content.decode('utf-8')
        df = parse_apache_log_pandas(log_content)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Apache log dosyası parse edilemedi veya boş.")
        
        anomali_raporu = anomali_tespiti(df)
        
        # Anomali tespitinde bulunan IP'lerden örnek kayıtları seç
        ornek_kayitlar = []
        if anomali_raporu:
            for anomali in anomali_raporu:
                ip = anomali["ip"]
                ip_kayitlari = df[df['remote_host'] == ip].head(1)
                if not ip_kayitlari.empty:
                    ornek_kayitlar.extend(ip_kayitlari.to_dict(orient='records'))
        
        # Eğer anomali kaydı yoksa veya yeterli örnek bulunamadıysa, ilk 3 kaydı al
        if len(ornek_kayitlar) < 3:
            ek_kayitlar = df.head(3 - len(ornek_kayitlar)).to_dict(orient='records')
            ornek_kayitlar.extend(ek_kayitlar)
        
        result = {
            "log_type": "apache",
            "toplam_kayit": len(df),
            "ornek_kayitlar": ornek_kayitlar[:3],
            "status_counts": df['status'].value_counts().to_dict(),
            "zaman_bazli_analiz": zaman_bazli_analiz(df),
            "anomali_raporu": anomali_raporu,
            "ip_bazli_analiz": ip_bazli_analiz(df),
            "hata_analizi": hata_analizi(df)
        }
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/analyze-windows")
async def analyze_windows_log(file: UploadFile = File(...)):
    """
    Windows Event Log dosyasını analiz eder ve sonuçları JSON olarak döndürür.
    """
    try:
        content = await file.read()
        log_content = content.decode('utf-8')
        df = parse_windows_event_log(log_content)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Windows Event Log dosyası parse edilemedi veya boş.")
        
        result = {
            "log_type": "windows_event",
            "total_events": len(df),
            "sample_data": df.head(3).to_dict(orient='records'),
            "zaman_bazli_analiz": windows_zaman_bazli_analiz(df),
            "anomali_raporu": windows_anomali_tespiti(df),
            "ip_bazli_analiz": windows_ip_bazli_analiz(df),
            "guvenlik_analizi": windows_guvenlik_analizi(df)
        }
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/analyze-syslog")
async def analyze_syslog(file: UploadFile = File(...)):
    """
    Syslog dosyasını analiz eder ve sonuçları JSON olarak döndürür.
    """
    try:
        content = await file.read()
        log_content = content.decode('utf-8')
        df, log_type = parse_syslog(log_content)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Syslog dosyası parse edilemedi veya boş.")
            
        result = syslog_analiz(df, log_type)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/analyze-firewall")
async def analyze_firewall_log(file: UploadFile = File(...)):
    """
    Firewall log dosyasını analiz eder ve sonuçları JSON olarak döndürür.
    """
    try:
        content = await file.read()
        log_content = content.decode('utf-8')
        df = parse_firewall_log(log_content)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Firewall log dosyası parse edilemedi veya boş.")
        
        result = firewall_analiz(df)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/analyze-application")
async def analyze_application_log(file: UploadFile = File(...)):
    """
    Application log dosyasını analiz eder ve sonuçları JSON olarak döndürür.
    """
    try:
        content = await file.read()
        log_content = content.decode('utf-8')
        df = parse_application_log(log_content)
        
        if df.empty:
            raise HTTPException(status_code=400, detail="Application log dosyası parse edilemedi veya boş.")
        
        result = application_analiz(df)
        return result
    except Exception as e:
        return {"error": str(e)}
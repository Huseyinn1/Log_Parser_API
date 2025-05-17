import pandas as pd
from typing import Dict, Any, List

def zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Saatlik bazda istek sayılarını hesaplar"""
    df['hour'] = df['time_received'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def anomali_tespiti(df: pd.DataFrame, threshold=50) -> List[str]:
    """Anormal durumları tespit eder"""
    mesajlar = []
    
    # 5xx hataları kontrol et
    kritik_hatalar = df[df['status'] >= 500]
    if len(kritik_hatalar) > threshold:
        mesajlar.append(f"Yüksek hata oranı: {len(kritik_hatalar)}")
    
    # Başarısız giriş denemeleri
    fail_login = df[df['status'].isin([401, 403])]
    if len(fail_login) > threshold:
        mesajlar.append(f"Yüksek başarısız giriş denemesi: {len(fail_login)}")
    
    return mesajlar

def ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """IP bazlı istek sayılarını hesaplar"""
    return df['remote_host'].value_counts().to_dict()

def hata_analizi(df: pd.DataFrame) -> Dict[str, Any]:
    """Detaylı hata analizi yapar"""
    hata_4xx = df[df['status'].between(400, 499)]
    hata_5xx = df[df['status'].between(500, 599)]
    
    top_errors = []
    for _, row in pd.concat([hata_4xx, hata_5xx]).head(5).iterrows():
        top_errors.append({
            "status": int(row['status']),
            "request_line": row['request_line']
        })
    
    return {
        "total_4xx_errors": len(hata_4xx),
        "total_5xx_errors": len(hata_5xx),
        "top_errors": top_errors
    } 
import pandas as pd
from typing import Dict, Any, List

def windows_zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Windows Event Log'ları için saatlik bazda olay sayılarını hesaplar"""
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def windows_anomali_tespiti(df: pd.DataFrame, threshold=50) -> List[str]:
    """Windows Event Log'ları için anormal durumları tespit eder"""
    mesajlar = []
    
    # Hata olaylarını kontrol et
    error_events = df[df['event_type'].str.contains('Error', case=False, na=False)]
    if len(error_events) > threshold:
        mesajlar.append(f"Yüksek hata olayı sayısı: {len(error_events)}")
    
    # Güvenlik olaylarını kontrol et
    security_events = df[df['event_type'].str.contains('Security', case=False, na=False)]
    if len(security_events) > threshold:
        mesajlar.append(f"Yüksek güvenlik olayı sayısı: {len(security_events)}")
    
    return mesajlar

def windows_ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Windows Event Log'ları için IP bazlı olay sayılarını hesaplar"""
    # IP adreslerini mesajlardan çıkar
    df['ip'] = df['message'].str.extract(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    return df['ip'].value_counts().to_dict()

def windows_guvenlik_analizi(df: pd.DataFrame) -> Dict[str, Any]:
    """Windows Event Log'ları için güvenlik olaylarını analiz eder"""
    # Sadece güvenlik olaylarını filtrele
    security_df = df[df['source'].str.contains('Security', case=False, na=False)]
    
    # Başarılı ve başarısız giriş denemelerini analiz et
    basarili_giris = security_df[security_df['event_id'] == '4624']
    basarisiz_giris = security_df[security_df['event_id'] == '4625']
    
    # Logon tiplerini analiz et
    logon_tipleri = security_df['logon_type'].value_counts().to_dict()
    
    # Güvenlik ID'lerini analiz et
    security_ids = security_df['security_id'].value_counts().to_dict()
    
    # Hesap adlarını analiz et
    hesap_adlari = security_df['account_name'].value_counts().to_dict()
    
    return {
        "toplam_guvenlik_olayi": len(security_df),
        "basarili_giris_sayisi": len(basarili_giris),
        "basarisiz_giris_sayisi": len(basarisiz_giris),
        "logon_tipleri": logon_tipleri,
        "security_ids": security_ids,
        "hesap_adlari": hesap_adlari,
        "basarisiz_giris_detaylari": basarisiz_giris[['timestamp', 'account_name', 'failure_reason']].to_dict(orient='records')[:5],
        "basarili_giris_detaylari": basarili_giris[['timestamp', 'account_name', 'logon_type']].to_dict(orient='records')[:5]
    } 
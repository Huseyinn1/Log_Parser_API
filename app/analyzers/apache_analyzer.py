import pandas as pd
from typing import Dict, Any, List

def zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Saatlik bazda istek sayılarını hesaplar"""
    df['hour'] = df['time_received'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def anomali_tespiti(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Apache loglarındaki anomalileri tespit eder"""
    anomali_raporu = []
    
    # Brute Force Saldırısı Tespiti
    failed_logins = df[df['status'].isin([401, 403])]
    if not failed_logins.empty:
        ip_failures = failed_logins.groupby('remote_host').size()
        for ip, count in ip_failures.items():
            if count >= 5:  # 5 veya daha fazla başarısız giriş denemesi
                anomali_raporu.append({
                    "tip": "brute_force_saldirisi",
                    "ip": ip,
                    "toplam_deneme": int(count),
                    "son_deneme": failed_logins[failed_logins['remote_host'] == ip].iloc[-1]['time_received'].strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # Yüksek Hata Oranı Tespiti
    error_requests = df[df['status'] >= 500]
    if not error_requests.empty:
        ip_errors = error_requests.groupby('remote_host').size()
        for ip, count in ip_errors.items():
            if count >= 3:  # 3 veya daha fazla 5xx hatası
                anomali_raporu.append({
                    "tip": "yuksek_hata_orani",
                    "ip": ip,
                    "toplam_hata": int(count),
                    "son_hata": error_requests[error_requests['remote_host'] == ip].iloc[-1]['time_received'].strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # Şüpheli Dosya Erişim Denemeleri
    suspicious_paths = ['/wp-admin', '/admin', '/phpmyadmin', '/config.php', '/.env', '/wp-login.php']
    suspicious_requests = df[df['request_line'].str.contains('|'.join(suspicious_paths), na=False)]
    if not suspicious_requests.empty:
        ip_suspicious = suspicious_requests.groupby('remote_host').size()
        for ip, count in ip_suspicious.items():
            if count >= 2:  # 2 veya daha fazla şüpheli erişim
                anomali_raporu.append({
                    "tip": "supheli_dosya_erisimi",
                    "ip": ip,
                    "toplam_deneme": int(count),
                    "son_deneme": suspicious_requests[suspicious_requests['remote_host'] == ip].iloc[-1]['time_received'].strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # SQL Injection ve XSS Denemeleri
    injection_patterns = ["'", ";", "UNION", "SELECT", "<script>", "onerror="]
    injection_requests = df[df['request_line'].str.contains('|'.join(injection_patterns), case=False, na=False)]
    if not injection_requests.empty:
        ip_injections = injection_requests.groupby('remote_host').size()
        for ip, count in ip_injections.items():
            if count >= 2:  # 2 veya daha fazla injection denemesi
                anomali_raporu.append({
                    "tip": "injection_denemesi",
                    "ip": ip,
                    "toplam_deneme": int(count),
                    "son_deneme": injection_requests[injection_requests['remote_host'] == ip].iloc[-1]['time_received'].strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return anomali_raporu

def ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """IP bazlı istek sayılarını hesaplar"""
    result = {
        "toplam_ip_sayisi": len(df['remote_host'].unique()),
        "ip_detaylari": df['remote_host'].value_counts().to_dict(),
        "hata_olan_ip_detaylari": df[df['status'] >= 400]['remote_host'].value_counts().to_dict()
    }
    return result

def hata_analizi(df: pd.DataFrame) -> Dict[str, Any]:
    """Detaylı hata analizi yapar"""
    hata_4xx = df[df['status'].between(400, 499)]
    hata_5xx = df[df['status'].between(500, 599)]
    
    top_errors = []
    for _, row in pd.concat([hata_4xx, hata_5xx]).head(5).iterrows():
        top_errors.append({
            "status": int(row['status']),
            "request_line": row['request_line'],
            "ip": row['remote_host'],
            "timestamp": row['time_received'].strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return {
        "total_4xx_errors": len(hata_4xx),
        "total_5xx_errors": len(hata_5xx),
        "top_errors": top_errors
    } 
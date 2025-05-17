import pandas as pd
from typing import Dict, Any, List

def syslog_zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Syslog'lar için saatlik bazda olay sayılarını hesaplar"""
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def syslog_anomali_tespiti(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Syslog kayıtlarındaki anomalileri tespit eder"""
    anomali_raporu = []
    
    # Başarısız giriş denemelerini IP bazlı say
    failed_logins = df[df['message'].str.contains('Failed password', na=False)]
    if not failed_logins.empty:
        ip_failures = failed_logins.groupby('ip').size()
        total_failures = ip_failures.sum()
        
        if total_failures > 5:
            anomali_raporu.append({
                "tip": "yuksek_basarisiz_giris",
                "toplam_deneme": int(total_failures),
                "ip_detaylari": {
                    ip: int(count) for ip, count in ip_failures.items()
                }
            })
    
    return anomali_raporu

def syslog_ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """Syslog'lar için IP bazlı analiz yapar"""
    result = {
        "toplam_ip_sayisi": 0,
        "ip_detaylari": {}
    }
    
    # Auth logları için IP analizi
    if 'log_type' in df.columns and 'auth' in df['log_type'].values and 'ip' in df.columns:
        auth_ips = df[df['ip'].notna()]['ip'].value_counts()
        result["auth_ip_detaylari"] = auth_ips.to_dict()
        result["toplam_ip_sayisi"] += len(auth_ips)
    
    # Firewall logları için IP analizi
    if 'log_type' in df.columns and 'firewall' in df['log_type'].values:
        if 'src_ip' in df.columns:
            src_ips = df[df['src_ip'].notna()]['src_ip'].value_counts()
            result["firewall_src_ip_detaylari"] = src_ips.to_dict()
            result["toplam_ip_sayisi"] += len(src_ips)
        
        if 'dst_ip' in df.columns:
            dst_ips = df[df['dst_ip'].notna()]['dst_ip'].value_counts()
            result["firewall_dst_ip_detaylari"] = dst_ips.to_dict()
    
    return result

def syslog_program_analizi(df: pd.DataFrame) -> Dict[str, int]:
    """Syslog'lar için program bazlı analiz yapar"""
    if 'program' in df.columns:
        return df['program'].value_counts().to_dict()
    return {}

def syslog_analiz(df: pd.DataFrame, log_type: str) -> Dict[str, Any]:
    """Syslog'lar için genel analiz yapar"""
    anomali_raporu = syslog_anomali_tespiti(df)
    
    # Anomali tespitinde bulunan IP'lerden örnek kayıtları seç
    ornek_kayitlar = []
    if anomali_raporu:
        for anomali in anomali_raporu:
            if anomali["tip"] == "yuksek_basarisiz_giris":
                for ip in anomali["ip_detaylari"].keys():
                    ip_kayitlari = df[df['ip'] == ip].head(1)
                    if not ip_kayitlari.empty:
                        ornek_kayitlar.extend(ip_kayitlari.to_dict(orient='records'))
    
    # Eğer anomali kaydı yoksa veya yeterli örnek bulunamadıysa, ilk 3 kaydı al
    if len(ornek_kayitlar) < 3:
        ek_kayitlar = df.head(3 - len(ornek_kayitlar)).to_dict(orient='records')
        ornek_kayitlar.extend(ek_kayitlar)
    
    return {
        "log_type": log_type,
        "toplam_kayit": len(df),
        "zaman_bazli_analiz": syslog_zaman_bazli_analiz(df),
        "anomali_raporu": anomali_raporu,
        "ip_bazli_analiz": syslog_ip_bazli_analiz(df),
        "program_analizi": syslog_program_analizi(df),
        "ornek_kayitlar": ornek_kayitlar[:3]  # En fazla 3 örnek kayıt
    } 
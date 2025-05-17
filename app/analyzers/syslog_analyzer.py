import pandas as pd
from typing import Dict, Any, List

def syslog_zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Syslog'lar için saatlik bazda olay sayılarını hesaplar"""
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def syslog_anomali_tespiti(df: pd.DataFrame) -> List[str]:
    """Syslog'lar için anormal durumları tespit eder"""
    mesajlar = []
    
    # Auth logları için anomali kontrolü
    if 'log_type' in df.columns and 'auth' in df['log_type'].values:
        failed_logins = df[df['message'].str.contains('Failed password', na=False)]
        if len(failed_logins) > 5:
            mesajlar.append(f"Yüksek sayıda başarısız giriş denemesi: {len(failed_logins)}")
        
        # Aynı IP'den çok sayıda başarısız giriş
        if 'ip' in df.columns:
            ip_failures = df[df['message'].str.contains('Failed password', na=False)]['ip'].value_counts()
            suspicious_ips = ip_failures[ip_failures > 3]
            if not suspicious_ips.empty:
                mesajlar.append(f"Şüpheli IP'lerden çok sayıda başarısız giriş: {suspicious_ips.to_dict()}")
    
    # Firewall logları için anomali kontrolü
    if 'log_type' in df.columns and 'firewall' in df['log_type'].values:
        blocked_ips = df[df['action'].str.contains('BLOCK', na=False)]['src_ip'].value_counts()
        suspicious_ips = blocked_ips[blocked_ips > 5]
        if not suspicious_ips.empty:
            mesajlar.append(f"Çok sayıda engellenen IP: {suspicious_ips.to_dict()}")
    
    # Systemd logları için anomali kontrolü
    if 'log_type' in df.columns and 'systemd' in df['log_type'].values:
        failed_services = df[df['message'].str.contains('Failed', na=False)]
        if len(failed_services) > 0:
            mesajlar.append(f"Başarısız servis başlatma sayısı: {len(failed_services)}")
    
    return mesajlar

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
    return {
        "log_type": log_type,
        "toplam_kayit": len(df),
        "zaman_bazli_analiz": syslog_zaman_bazli_analiz(df),
        "anomali_raporu": syslog_anomali_tespiti(df),
        "ip_bazli_analiz": syslog_ip_bazli_analiz(df),
        "program_analizi": syslog_program_analizi(df),
        "ornek_kayitlar": df.head(3).to_dict(orient='records')
    } 
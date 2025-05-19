import pandas as pd
from typing import Dict, Any, List

def application_zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Application logları için saatlik bazda olay sayılarını hesaplar"""
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def application_anomali_tespiti(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Application loglarındaki anomalileri tespit eder"""
    anomali_raporu = []
    
    # API Kötüye Kullanımı
    api_abuse = df[df['status_code'] >= 400].groupby(['ip', 'endpoint']).size().reset_index(name='count')
    api_abuse = api_abuse[api_abuse['count'] >= 10]  # 10 veya daha fazla hata
    for _, row in api_abuse.iterrows():
        anomali_raporu.append({
            "tip": "api_kotuye_kullanim",
            "ip": row['ip'],
            "endpoint": row['endpoint'],
            "hata_sayisi": int(row['count']),
            "son_hata": df[(df['ip'] == row['ip']) & (df['endpoint'] == row['endpoint'])]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Session Hijacking Denemeleri
    session_hijack = df[df['user_agent'].str.contains('curl|wget|python-requests', case=False, na=False)]
    if not session_hijack.empty:
        ip_hijack = session_hijack.groupby('ip').size()
        for ip, count in ip_hijack.items():
            if count >= 5:  # 5 veya daha fazla şüpheli istek
                anomali_raporu.append({
                    "tip": "session_hijacking_denemesi",
                    "ip": ip,
                    "istek_sayisi": int(count),
                    "son_istek": session_hijack[session_hijack['ip'] == ip]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # Yüksek Response Time
    high_response = df[df['response_time'] >= 1000]  # 1 saniyeden uzun yanıt süreleri
    if not high_response.empty:
        ip_slow = high_response.groupby('ip').size()
        for ip, count in ip_slow.items():
            if count >= 3:  # 3 veya daha fazla yavaş yanıt
                anomali_raporu.append({
                    "tip": "yuksek_response_time",
                    "ip": ip,
                    "yavas_yanit_sayisi": int(count),
                    "son_yavas_yanit": high_response[high_response['ip'] == ip]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
                })
    
    # Şüpheli User Agent'lar
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'metasploit', 'burp', 'zap']
    suspicious = df[df['user_agent'].str.contains('|'.join(suspicious_agents), case=False, na=False)]
    if not suspicious.empty:
        ip_suspicious = suspicious.groupby('ip').size()
        for ip, count in ip_suspicious.items():
            anomali_raporu.append({
                "tip": "supheli_user_agent",
                "ip": ip,
                "istek_sayisi": int(count),
                "son_istek": suspicious[suspicious['ip'] == ip]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return anomali_raporu

def application_ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """Application logları için IP bazlı analiz yapar"""
    result = {
        "toplam_ip_sayisi": len(df['ip'].unique()),
        "hata_veren_ip_sayisi": len(df[df['status_code'] >= 400]['ip'].unique()),
        "ip_detaylari": df['ip'].value_counts().to_dict(),
        "endpoint_detaylari": df['endpoint'].value_counts().to_dict(),
        "method_detaylari": df['method'].value_counts().to_dict(),
        "status_code_detaylari": df['status_code'].value_counts().to_dict()
    }
    return result

def application_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """Application logları için genel analiz yapar"""
    anomali_raporu = application_anomali_tespiti(df)
    
    # Anomali tespitinde bulunan IP'lerden örnek kayıtları seç
    ornek_kayitlar = []
    if anomali_raporu:
        for anomali in anomali_raporu:
            ip = anomali["ip"]
            ip_kayitlari = df[df['ip'] == ip].head(1)
            if not ip_kayitlari.empty:
                ornek_kayitlar.extend(ip_kayitlari.to_dict(orient='records'))
    
    # Eğer anomali kaydı yoksa veya yeterli örnek bulunamadıysa, ilk 3 kaydı al
    if len(ornek_kayitlar) < 3:
        ek_kayitlar = df.head(3 - len(ornek_kayitlar)).to_dict(orient='records')
        ornek_kayitlar.extend(ek_kayitlar)
    
    return {
        "log_type": "application",
        "toplam_kayit": len(df),
        "ornek_kayitlar": ornek_kayitlar[:3],
        "zaman_bazli_analiz": application_zaman_bazli_analiz(df),
        "anomali_raporu": anomali_raporu,
        "ip_bazli_analiz": application_ip_bazli_analiz(df)
    } 
import pandas as pd
from typing import Dict, Any, List

def firewall_zaman_bazli_analiz(df: pd.DataFrame) -> Dict[str, int]:
    """Firewall logları için saatlik bazda olay sayılarını hesaplar"""
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size().to_dict()
    return {str(k): int(v) for k, v in hourly_counts.items()}

def firewall_anomali_tespiti(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Firewall loglarındaki anomalileri tespit eder"""
    anomali_raporu = []
    
    # Port Tarama Tespiti
    port_scan = df[df['action'] == 'DENY'].groupby('src_ip').agg({
        'dst_port': 'nunique',
        'timestamp': 'count'
    }).reset_index()
    
    port_scan = port_scan[port_scan['dst_port'] >= 5]  # 5 veya daha fazla farklı porta erişim denemesi
    for _, row in port_scan.iterrows():
        anomali_raporu.append({
            "tip": "port_tarama",
            "ip": row['src_ip'],
            "farkli_port_sayisi": int(row['dst_port']),
            "toplam_deneme": int(row['timestamp']),
            "son_deneme": df[df['src_ip'] == row['src_ip']]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # DDoS Saldırısı Tespiti
    ddos = df[df['action'] == 'DENY'].groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
    ddos = ddos[ddos['count'] >= 100]  # 100 veya daha fazla istek
    for _, row in ddos.iterrows():
        anomali_raporu.append({
            "tip": "ddos_saldirisi",
            "kaynak_ip": row['src_ip'],
            "hedef_ip": row['dst_ip'],
            "istek_sayisi": int(row['count']),
            "son_istek": df[(df['src_ip'] == row['src_ip']) & (df['dst_ip'] == row['dst_ip'])]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Şüpheli Port Erişimleri
    suspicious_ports = ['22', '23', '3389', '445', '1433', '3306', '5432', '27017']
    suspicious = df[df['dst_port'].isin(suspicious_ports) & (df['action'] == 'DENY')]
    if not suspicious.empty:
        ip_suspicious = suspicious.groupby('src_ip').size()
        for ip, count in ip_suspicious.items():
            if count >= 3:  # 3 veya daha fazla şüpheli port erişim denemesi
                anomali_raporu.append({
                    "tip": "supheli_port_erisimi",
                    "ip": ip,
                    "toplam_deneme": int(count),
                    "son_deneme": suspicious[suspicious['src_ip'] == ip]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return anomali_raporu

def firewall_ip_bazli_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """Firewall logları için IP bazlı analiz yapar"""
    result = {
        "toplam_ip_sayisi": len(df['src_ip'].unique()),
        "engellenen_ip_sayisi": len(df[df['action'] == 'DENY']['src_ip'].unique()),
        "ip_detaylari": {
            "kaynak_ip": df['src_ip'].value_counts().to_dict(),
            "hedef_ip": df['dst_ip'].value_counts().to_dict()
        },
        "protokol_detaylari": df['protocol'].value_counts().to_dict(),
        "port_detaylari": {
            "kaynak_port": df['src_port'].value_counts().to_dict(),
            "hedef_port": df['dst_port'].value_counts().to_dict()
        }
    }
    return result

def firewall_analiz(df: pd.DataFrame) -> Dict[str, Any]:
    """Firewall logları için genel analiz yapar"""
    anomali_raporu = firewall_anomali_tespiti(df)
    
    # Anomali tespitinde bulunan IP'lerden örnek kayıtları seç
    ornek_kayitlar = []
    if anomali_raporu:
        for anomali in anomali_raporu:
            ip = anomali.get('ip') or anomali.get('kaynak_ip')
            if ip:
                ip_kayitlari = df[df['src_ip'] == ip].head(1)
                if not ip_kayitlari.empty:
                    ornek_kayitlar.extend(ip_kayitlari.to_dict(orient='records'))
    
    # Eğer anomali kaydı yoksa veya yeterli örnek bulunamadıysa, ilk 3 kaydı al
    if len(ornek_kayitlar) < 3:
        ek_kayitlar = df.head(3 - len(ornek_kayitlar)).to_dict(orient='records')
        ornek_kayitlar.extend(ek_kayitlar)
    
    return {
        "log_type": "firewall",
        "toplam_kayit": len(df),
        "ornek_kayitlar": ornek_kayitlar[:3],
        "zaman_bazli_analiz": firewall_zaman_bazli_analiz(df),
        "anomali_raporu": anomali_raporu,
        "ip_bazli_analiz": firewall_ip_bazli_analiz(df)
    } 
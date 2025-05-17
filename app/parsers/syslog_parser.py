import pandas as pd
import re
from typing import Dict, Any, Tuple
from datetime import datetime

def detect_syslog_type(log_content: str) -> str:
    """Syslog tipini belirler"""
    lines = log_content.strip().split('\n')
    if not lines:
        return "unknown"
    
    # Her satır için kontrol et
    auth_count = 0
    firewall_count = 0
    systemd_count = 0
    cron_count = 0
    classic_count = 0
    
    for line in lines:
        # Auth log kontrolü
        if re.search(r'sshd.*Failed password|sudo.*authentication failure|Failed password for|authentication failure|Invalid user|Failed password', line):
            auth_count += 1
        
        # Firewall log kontrolü
        if re.search(r'\[UFW BLOCK\]|\[iptables\]|\[firewalld\]|kernel:|IN=.*OUT=.*SRC=.*DST=', line):
            firewall_count += 1
        
        # Systemd log kontrolü
        if re.search(r'systemd\[1\]:|Started Daily|Started system|systemd.*Started|systemd.*Stopped', line):
            systemd_count += 1
        
        # Cron log kontrolü
        if re.search(r'CRON|anacron|cron|\(root\)|\(www-data\)|CMD\s+\(', line):
            cron_count += 1
        
        # Klasik syslog kontrolü
        if re.match(r'^<\d+>.*?:\s+.*$', line):
            classic_count += 1
    
    # En çok eşleşen tipi döndür
    counts = {
        'auth': auth_count,
        'firewall': firewall_count,
        'systemd': systemd_count,
        'cron': cron_count,
        'classic': classic_count
    }
    
    max_type = max(counts.items(), key=lambda x: x[1])
    return max_type[0] if max_type[1] > 0 else "unknown"

def parse_timestamp(timestamp_str: str) -> pd.Timestamp:
    """Farklı tarih formatlarını parse eder"""
    try:
        # Yıl bilgisi yoksa ekle
        if not re.search(r'\d{4}', timestamp_str):
            current_year = datetime.now().year
            timestamp_str = f"{timestamp_str} {current_year}"
        
        # Farklı tarih formatlarını dene
        formats = [
            '%b %d %H:%M:%S %Y',  # May 17 10:21:12 2023
            '%Y-%m-%d %H:%M:%S',  # 2023-05-17 10:21:12
            '%b %d %H:%M:%S',     # May 17 10:21:12
            '%Y/%m/%d %H:%M:%S'   # 2023/05/17 10:21:12
        ]
        
        for fmt in formats:
            try:
                return pd.to_datetime(timestamp_str, format=fmt)
            except:
                continue
        
        # Hiçbir format uymazsa pandas'ın otomatik parse etmesini dene
        return pd.to_datetime(timestamp_str)
    except:
        return pd.NaT

def parse_firewall_log(log_content: str) -> pd.DataFrame:
    """Firewall log formatını parse eder"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            # Tarih ve saat bilgisini ayır
            timestamp_match = re.match(r'(.*?)\s+kernel:', line)
            if not timestamp_match:
                continue
                
            timestamp = timestamp_match.group(1)
            
            # Detayları parse et
            details = line[line.find('['):]
            
            record = {
                'timestamp': parse_timestamp(timestamp),
                'host': 'localhost',  # Firewall loglarında genelde host bilgisi yok
                'program': 'kernel',
                'message': details,
                'log_type': 'firewall',
                'action': re.search(r'\[(.*?)\]', details).group(1) if '[' in details else None,
                'interface': re.search(r'IN=(\S+)', details).group(1) if 'IN=' in details else None,
                'src_ip': re.search(r'SRC=(\S+)', details).group(1) if 'SRC=' in details else None,
                'dst_ip': re.search(r'DST=(\S+)', details).group(1) if 'DST=' in details else None,
                'protocol': re.search(r'PROTO=(\S+)', details).group(1) if 'PROTO=' in details else None,
                'src_port': re.search(r'SPT=(\d+)', details).group(1) if 'SPT=' in details else None,
                'dst_port': re.search(r'DPT=(\d+)', details).group(1) if 'DPT=' in details else None
            }
            
            records.append(record)
        except Exception as e:
            print(f"Firewall log parse hatası: {str(e)}")
            continue
    
    return pd.DataFrame(records)

def parse_classic_syslog(log_content: str) -> pd.DataFrame:
    """Klasik Syslog formatını parse eder"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            match = re.match(r'<(\d+)>(.*?)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)', line)
            if match:
                priority, timestamp, host, program, pid, message = match.groups()
                records.append({
                    'timestamp': parse_timestamp(timestamp),
                    'host': host,
                    'program': program,
                    'pid': pid,
                    'priority': priority,
                    'message': message,
                    'log_type': 'classic'
                })
        except Exception as e:
            print(f"Classic syslog parse hatası: {str(e)}")
            continue
    
    return pd.DataFrame(records)

def parse_auth_log(log_content: str) -> pd.DataFrame:
    """Auth log formatını parse eder"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            match = re.match(r'(.*?)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)', line)
            if match:
                timestamp, host, program, pid, message = match.groups()
                records.append({
                    'timestamp': parse_timestamp(timestamp),
                    'host': host,
                    'program': program,
                    'pid': pid,
                    'message': message,
                    'log_type': 'auth',
                    'user': re.search(r'for\s+(\S+)', message).group(1) if 'for' in message else None,
                    'ip': re.search(r'from\s+(\S+)', message).group(1) if 'from' in message else None,
                    'port': re.search(r'port\s+(\d+)', message).group(1) if 'port' in message else None
                })
        except Exception as e:
            print(f"Auth log parse hatası: {str(e)}")
            continue
    
    return pd.DataFrame(records)

def parse_systemd_log(log_content: str) -> pd.DataFrame:
    """Systemd journal log formatını parse eder"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            match = re.match(r'(.*?)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)', line)
            if match:
                timestamp, host, program, pid, message = match.groups()
                records.append({
                    'timestamp': parse_timestamp(timestamp),
                    'host': host,
                    'program': program,
                    'pid': pid,
                    'message': message,
                    'log_type': 'systemd',
                    'service': re.search(r'Started\s+(\S+)', message).group(1) if 'Started' in message else None
                })
        except Exception as e:
            print(f"Systemd log parse hatası: {str(e)}")
            continue
    
    return pd.DataFrame(records)

def parse_cron_log(log_content: str) -> pd.DataFrame:
    """Cron log formatını parse eder"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            # Cron log formatı: May 17 10:21:12 hostname CRON[12345]: (root) CMD (command)
            match = re.match(r'(.*?)\s+(\S+)\s+(CRON|anacron)\[(\d+)\]:\s+\((.*?)\)\s+(.*)', line)
            if match:
                timestamp, host, program, pid, user, message = match.groups()
                records.append({
                    'timestamp': parse_timestamp(timestamp),
                    'host': host,
                    'program': program,
                    'pid': pid,
                    'message': message,
                    'log_type': 'cron',
                    'user': user,
                    'job': re.search(r'CMD\s+(.*?)$', message).group(1) if 'CMD' in message else None
                })
            else:
                # Alternatif format: May 17 10:21:12 hostname cron[12345]: (root) CMD (command)
                match = re.match(r'(.*?)\s+(\S+)\s+cron\[(\d+)\]:\s+\((.*?)\)\s+(.*)', line)
                if match:
                    timestamp, host, pid, user, message = match.groups()
                    records.append({
                        'timestamp': parse_timestamp(timestamp),
                        'host': host,
                        'program': 'cron',
                        'pid': pid,
                        'message': message,
                        'log_type': 'cron',
                        'user': user,
                        'job': re.search(r'CMD\s+(.*?)$', message).group(1) if 'CMD' in message else None
                    })
        except Exception as e:
            print(f"Cron log parse hatası: {str(e)}")
            continue
    
    return pd.DataFrame(records)

def parse_syslog(log_content: str) -> Tuple[pd.DataFrame, str]:
    """Syslog içeriğini parse eder ve tipini belirler"""
    try:
        log_type = detect_syslog_type(log_content)
        
        if log_type == "classic":
            df = parse_classic_syslog(log_content)
        elif log_type == "auth":
            df = parse_auth_log(log_content)
        elif log_type == "systemd":
            df = parse_systemd_log(log_content)
        elif log_type == "firewall":
            df = parse_firewall_log(log_content)
        elif log_type == "cron":
            df = parse_cron_log(log_content)
        else:
            raise ValueError("Desteklenmeyen syslog formatı")
        
        # Geçersiz tarihleri filtrele
        df = df[df['timestamp'].notna()]
        
        if df.empty:
            raise ValueError("Log içeriği parse edilemedi veya boş")
        
        return df, log_type
    except Exception as e:
        raise ValueError(f"Log parse hatası: {str(e)}") 
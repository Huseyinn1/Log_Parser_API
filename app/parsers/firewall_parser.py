import pandas as pd
from typing import Tuple

def parse_firewall_log(log_content: str) -> pd.DataFrame:
    """
    Firewall loglarını parse eder.
    Örnek format:
    [2023-10-10 13:55:36] DENY TCP 192.168.1.100:54321 -> 10.0.0.1:80 (SYN) IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd
    """
    lines = log_content.strip().split('\n')
    data = []
    
    for line in lines:
        try:
            # Tarih ve saat
            timestamp = line[1:20]  # [2023-10-10 13:55:36]
            
            # Action ve protokol
            parts = line[21:].split()
            action = parts[0]  # DENY/ACCEPT
            protocol = parts[1]  # TCP/UDP/ICMP
            
            # IP ve port bilgileri
            src_ip_port = parts[2]  # 192.168.1.100:54321
            dst_ip_port = parts[4]  # 10.0.0.1:80
            
            src_parts = src_ip_port.split(':')
            if len(src_parts) != 2:
                raise ValueError(f"Kaynak IP:port ayrıştırılamadı: {src_ip_port}")
            src_ip = src_parts[0]
            src_port = src_parts[1]
            
            dst_parts = dst_ip_port.split(':')
            if len(dst_parts) != 2:
                raise ValueError(f"Hedef IP:port ayrıştırılamadı: {dst_ip_port}")
            dst_ip = dst_parts[0]
            dst_port = dst_parts[1]
            
            # TCP flag'leri
            tcp_flags = parts[5].strip('()') if len(parts) > 5 else ''
            
            # Interface bilgileri
            in_interface = ''
            out_interface = ''
            for part in parts:
                if part.startswith('IN='):
                    in_interface = part[3:]
                elif part.startswith('OUT='):
                    out_interface = part[4:]
            
            data.append({
                'timestamp': pd.to_datetime(timestamp),
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'tcp_flags': tcp_flags,
                'in_interface': in_interface,
                'out_interface': out_interface,
                'raw_log': line
            })
        except Exception as e:
            print(f"Log satırı parse edilemedi: {line}")
            print(f"Hata: {str(e)}")
            continue
    
    return pd.DataFrame(data) 
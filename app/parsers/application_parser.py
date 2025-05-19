import pandas as pd
from typing import Tuple
import json

def parse_application_log(log_content: str) -> pd.DataFrame:
    """
    Application loglarını parse eder.
    Örnek format (JSON):
    {
        "timestamp": "2023-10-10T13:55:36Z",
        "level": "ERROR",
        "service": "api",
        "endpoint": "/api/v1/users",
        "method": "POST",
        "status_code": 400,
        "user_id": "user123",
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "request_body": "...",
        "response_time": 150,
        "error_message": "Invalid input"
    }
    """
    lines = log_content.strip().split('\n')
    data = []
    
    for line in lines:
        try:
            # JSON formatındaki log satırını parse et
            log_entry = json.loads(line)
            
            # Temel alanları çıkar
            entry = {
                'timestamp': pd.to_datetime(log_entry.get('timestamp')),
                'level': log_entry.get('level'),
                'service': log_entry.get('service'),
                'endpoint': log_entry.get('endpoint'),
                'method': log_entry.get('method'),
                'status_code': log_entry.get('status_code'),
                'user_id': log_entry.get('user_id'),
                'ip': log_entry.get('ip'),
                'user_agent': log_entry.get('user_agent'),
                'request_body': log_entry.get('request_body'),
                'response_time': log_entry.get('response_time'),
                'error_message': log_entry.get('error_message'),
                'raw_log': line
            }
            
            data.append(entry)
        except json.JSONDecodeError:
            print(f"JSON parse hatası: {line}")
            continue
        except Exception as e:
            print(f"Log satırı parse edilemedi: {line}")
            print(f"Hata: {str(e)}")
            continue
    
    return pd.DataFrame(data) 
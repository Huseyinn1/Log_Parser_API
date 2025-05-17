import pandas as pd
import re

def parse_windows_event_log(log_content: str) -> pd.DataFrame:
    """Windows Event Log dosyasını DataFrame'e dönüştürür"""
    lines = log_content.strip().split('\n')
    records = []
    current_record = {}
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Yeni kayıt başlangıcı
        if line.startswith('Date:'):
            if current_record:
                records.append(current_record)
            current_record = {
                'timestamp': None,
                'source': None,
                'event_id': None,
                'task_category': None,
                'level': None,
                'message': [],
                'security_id': None,
                'account_name': None,
                'logon_type': None,
                'failure_reason': None
            }
            
            # Tarih ve saat
            date_match = re.search(r'Date: (.*?)\s+Source:', line)
            if date_match:
                current_record['timestamp'] = pd.to_datetime(date_match.group(1))
            
            # Kaynak
            source_match = re.search(r'Source: (.*?)\s+Event ID:', line)
            if source_match:
                current_record['source'] = source_match.group(1)
            
            # Event ID
            event_id_match = re.search(r'Event ID: (\d+)', line)
            if event_id_match:
                current_record['event_id'] = event_id_match.group(1)
            
            # Task Category
            task_match = re.search(r'Task Category: (.*?)\s+Level:', line)
            if task_match:
                current_record['task_category'] = task_match.group(1)
            
            # Level
            level_match = re.search(r'Level: (.*?)\s+Message:', line)
            if level_match:
                current_record['level'] = level_match.group(1)
        
        # Security ID
        elif 'Security ID:' in line:
            security_id_match = re.search(r'Security ID: (.*?)$', line)
            if security_id_match:
                current_record['security_id'] = security_id_match.group(1).strip()
        
        # Account Name
        elif 'Account Name:' in line:
            account_match = re.search(r'Account Name: (.*?)$', line)
            if account_match:
                current_record['account_name'] = account_match.group(1).strip()
        
        # Logon Type
        elif 'Logon Type:' in line:
            logon_match = re.search(r'Logon Type: (\d+)', line)
            if logon_match:
                current_record['logon_type'] = logon_match.group(1)
        
        # Failure Reason
        elif 'Failure Reason:' in line:
            failure_match = re.search(r'Failure Reason: (.*?)$', line)
            if failure_match:
                current_record['failure_reason'] = failure_match.group(1).strip()
        
        # Message içeriği
        elif line and not line.startswith('Subject:'):
            current_record['message'].append(line)
    
    # Son kaydı ekle
    if current_record:
        records.append(current_record)
    
    # DataFrame oluştur
    df = pd.DataFrame(records)
    
    # Message listesini string'e çevir
    if not df.empty and 'message' in df.columns:
        df['message'] = df['message'].apply(lambda x: ' '.join(x) if isinstance(x, list) else x)
    
    return df 
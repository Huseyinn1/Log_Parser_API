import pandas as pd

def parse_apache_log_pandas(log_content: str) -> pd.DataFrame:
    """Apache log dosyasını DataFrame'e dönüştürür"""
    lines = log_content.strip().split('\n')
    records = []
    
    for line in lines:
        try:
            parts = line.split()
            if len(parts) >= 9:
                record = {
                    'remote_host': parts[0],
                    'remote_logname': parts[1],
                    'remote_user': parts[2],
                    'time_received': parts[3] + ' ' + parts[4],
                    'request_line': ' '.join(parts[5:8]),
                    'status': int(parts[8]),
                    'bytes_sent': int(parts[9]) if len(parts) > 9 else 0
                }
                records.append(record)
        except Exception as e:
            continue
    
    df = pd.DataFrame(records)
    if not df.empty:
        df['time_received'] = pd.to_datetime(df['time_received'], format='[%d/%b/%Y:%H:%M:%S %z]')
    return df 
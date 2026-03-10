import boto3
import json
import os
import gzip
from datetime import datetime, timedelta
from analyze_attacks import analyze_attack_logs_with_streams

def parse_s3_url(s3_url):
    """Parse S3 URL to extract bucket and prefix"""
    if s3_url.startswith('s3://'):
        s3_url = s3_url[5:]
    parts = s3_url.split('/', 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ''
    return bucket, prefix

def fetch_s3_logs(bucket_name, start_time, end_time, region='us-west-2', prefix='', progress_queue=None):
    """Download JSON log files from S3 bucket and save to Log directory"""
    s3_client = boto3.client('s3', region_name=region)
    log_dir = os.path.join(os.path.dirname(__file__), 'Log')
    
    # Clean up old logs
    if os.path.exists(log_dir):
        msg = "Cleaning up old log files..."
        print(msg)
        if progress_queue:
            progress_queue.put({'status': 'info', 'message': msg})
        
        for file in os.listdir(log_dir):
            file_path = os.path.join(log_dir, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")
    
    os.makedirs(log_dir, exist_ok=True)
    
    msg = f"Fetching logs from S3 bucket: {bucket_name}"
    print(msg)
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': msg})
    
    # List objects in bucket
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)
    
    msg = "Discovering log files..."
    print(msg)
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': msg})
    
    matching_files = []
    paginator = s3_client.get_paginator('list_objects_v2')
    
    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        if 'Contents' not in page:
            continue
        
        for obj in page['Contents']:
            key = obj['Key']
            last_modified = obj['LastModified'].timestamp() * 1000
            
            # Filter by time range and log file extensions
            if start_ms <= last_modified <= end_ms and (key.lower().endswith('.json') or key.lower().endswith('.gz') or key.lower().endswith('.log')):
                matching_files.append({'key': key, 'size': obj['Size']})
    
    total_files = len(matching_files)
    msg = f"Found {total_files} log file(s) in time range"
    print(msg)
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': msg})
    
    if total_files == 0:
        print("No files found in the specified time range")
        return log_dir
    
    # Download and process each file
    for idx, file_info in enumerate(matching_files, 1):
        key = file_info['key']
        msg = f"[{idx}/{total_files}] Downloading {key}"
        print(msg)
        if progress_queue:
            progress_queue.put({'status': 'progress', 'message': msg, 'current': idx, 'total': total_files})
        
        try:
            # Download file
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            raw_content = response['Body'].read()
            
            # Decompress if gzipped
            if key.lower().endswith('.gz'):
                content = gzip.decompress(raw_content).decode('utf-8')
            else:
                content = raw_content.decode('utf-8')
            
            # Parse log entries
            log_entries = []
            for line in content.strip().split('\n'):
                if line.strip():
                    log_entries.append(line)
            
            # Use short filename: s3_<index>.txt
            log_file = os.path.join(log_dir, f's3_log_{idx}.txt')
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(log_entries))
            
            print(f"  Saved {len(log_entries)} log entries")
        
        except Exception as e:
            print(f"  Error: {e}")
            if progress_queue:
                progress_queue.put({'status': 'error', 'message': f"Error: {str(e)}"})
    
    print(f"\nAll logs downloaded to: {log_dir}\n")
    return log_dir

if __name__ == "__main__":
    # Configuration
    s3_input = input("Enter S3 bucket name or S3 URL (s3://bucket/prefix): ").strip()
    
    # Parse S3 URL if provided
    if s3_input.startswith('s3://'):
        BUCKET_NAME, PREFIX = parse_s3_url(s3_input)
        print(f"Parsed - Bucket: {BUCKET_NAME}, Prefix: {PREFIX}")
    else:
        BUCKET_NAME = s3_input
        PREFIX = input("Enter prefix/folder path (optional, press Enter to skip): ").strip()
    
    # Time range options
    print("\nTime Range Options:")
    print("1. Last N hours")
    print("2. Specific date/time range")
    choice = input("Select option (1 or 2): ").strip()
    
    if choice == '2':
        start_str = input("Enter start date/time (YYYY-MM-DD HH:MM): ")
        end_str = input("Enter end date/time (YYYY-MM-DD HH:MM): ")
        start_time = datetime.strptime(start_str, '%Y-%m-%d %H:%M')
        end_time = datetime.strptime(end_str, '%Y-%m-%d %H:%M')
    else:
        hours = int(input("Enter hours of logs to fetch (default 24): ") or "24")
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
    
    REGION = input("Enter AWS region (default us-west-2): ") or "us-west-2"
    
    # Fetch logs
    log_dir = fetch_s3_logs(BUCKET_NAME, start_time, end_time, REGION, PREFIX)
    
    # Analyze logs
    print("="*80)
    print("Starting log analysis...")
    print("="*80 + "\n")
    
    results, malicious_activities = analyze_attack_logs_with_streams(log_dir)
    
    # Generate reports
    from fetch_and_analyze import save_to_csv_with_streams, save_malicious_report_with_streams
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    summary_file = f"log_analysis_{timestamp}.csv"
    malicious_file = f"malicious_activities_report_{timestamp}.csv"
    
    save_to_csv_with_streams(results, summary_file)
    save_malicious_report_with_streams(malicious_activities, malicious_file)
    
    print(f"\n{'='*80}")
    print(f"Analysis complete!")
    print(f"  - Summary report: {summary_file}")
    print(f"  - Malicious activities report: {malicious_file}")
    print(f"  - Total unique IPs: {len(results)}")
    print(f"  - Total malicious activities detected: {len(malicious_activities)}")
    print(f"{'='*80}")

import boto3
import os
from datetime import datetime, timedelta
from analyze_attacks import analyze_attack_logs_with_streams, save_to_csv_with_streams, save_malicious_report_with_streams
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

lock = threading.Lock()

def fetch_stream_logs(client, log_group_name, stream_name, start_ms, end_ms, log_dir, progress_queue, idx, total):
    """Fetch logs for a single stream"""
    try:
        kwargs = {
            'logGroupName': log_group_name,
            'logStreamNames': [stream_name],
            'startTime': start_ms,
            'endTime': end_ms
        }
        
        stream_logs = []
        while True:
            response = client.filter_log_events(**kwargs)
            events = response.get('events', [])
            stream_logs.extend([event['message'] for event in events])
            
            if 'nextToken' not in response:
                break
            kwargs['nextToken'] = response['nextToken']
        
        if stream_logs:
            log_group_safe = log_group_name.replace('/', '_').replace('\\', '_').replace(':', '_')
            safe_stream_name = stream_name.replace('/', '_').replace('\\', '_').replace(':', '_')
            log_file = os.path.join(log_dir, f'{log_group_safe}_{safe_stream_name}.txt')
            
            with open(log_file, 'w') as f:
                f.write('\n'.join(stream_logs))
        
        with lock:
            msg = f"[{idx}/{total}] {stream_name} - {len(stream_logs)} entries"
            print(msg)
            if progress_queue:
                progress_queue.put({'status': 'progress', 'message': msg, 'current': idx, 'total': total})
        
        return len(stream_logs)
    except Exception as e:
        print(f"Error fetching {stream_name}: {e}")
        return 0

def fetch_cloudwatch_logs(log_group_name, start_time, end_time, region='us-west-2', progress_queue=None, skip_cleanup=False):
    """Fetch logs from CloudWatch Log Group per stream"""
    client = boto3.client('logs', region_name=region)
    log_dir = os.path.join(os.path.dirname(__file__), 'Log')
    
    # Clean up old logs only if not skipped (first log group only)
    if not skip_cleanup:
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
    
    msg = f"Fetching logs from: {log_group_name}"
    print(msg)
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': msg})
    
    # Get all log streams
    streams_list = []
    kwargs = {'logGroupName': log_group_name, 'orderBy': 'LastEventTime', 'descending': True}
    
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': 'Discovering log streams...'})
    
    while True:
        response = client.describe_log_streams(**kwargs)
        streams_list.extend(response['logStreams'])
        if 'nextToken' not in response:
            break
        kwargs['nextToken'] = response['nextToken']
    
    streams = {'logStreams': streams_list}
    total_streams = len(streams['logStreams'])
    
    msg = f"Found {total_streams} log stream(s)"
    print(msg)
    if progress_queue:
        progress_queue.put({'status': 'info', 'message': msg})
    
    # Filter streams by time range
    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)
    
    valid_streams = []
    for stream in streams['logStreams']:
        stream_start = stream.get('firstEventTimestamp', 0)
        stream_end = stream.get('lastEventTimestamp', 0)
        if not (stream_end < start_ms or stream_start > end_ms):
            valid_streams.append(stream)
    
    print(f"Streams in time range: {len(valid_streams)}")
    
    # Fetch streams in parallel (10 at a time)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for idx, stream in enumerate(valid_streams, 1):
            future = executor.submit(
                fetch_stream_logs,
                client,
                log_group_name,
                stream['logStreamName'],
                start_ms,
                end_ms,
                log_dir,
                progress_queue,
                idx,
                len(valid_streams)
            )
            futures.append(future)
        
        # Wait for all to complete
        total_logs = 0
        for future in as_completed(futures):
            total_logs += future.result()
    
    print(f"\nTotal logs fetched: {total_logs}")
    print(f"All logs downloaded to: {log_dir}\n")
    return log_dir

fetch_cloudwatch_logs_with_progress = fetch_cloudwatch_logs

if __name__ == "__main__":
    # Valid AWS regions
    valid_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-south-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
    ]
    
    # Configuration
    LOG_GROUP_NAME = input("Enter CloudWatch Log Group name: ")
    
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
        # Add 1 minute to end time to include logs up to the end minute
        end_time = end_time + timedelta(minutes=1)
    else:
        hours = int(input("Enter hours of logs to fetch (default 24): ") or "24")
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
    
    REGION = input("Enter AWS region (default us-west-2): ") or "us-west-2"
    
    # Validate region
    if REGION not in valid_regions:
        print(f"\nError: Invalid region '{REGION}'")
        print(f"Valid regions: {', '.join(valid_regions)}")
        print("\nDid you mean 'us-west-2'?")
        exit(1)
    
    # Fetch logs
    log_dir = fetch_cloudwatch_logs(LOG_GROUP_NAME, start_time, end_time, REGION)
    
    # Analyze logs
    print("="*80)
    print("Starting log analysis...")
    print("="*80 + "\n")
    
    results, malicious_activities = analyze_attack_logs_with_streams(log_dir)
    
    # Generate reports
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

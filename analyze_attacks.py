import os
import re
import csv
import ipaddress
from collections import defaultdict
from datetime import datetime
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def get_geo_location(ip):
    if is_private_ip(ip):
        return "Private Network"
    
    # Try ipapi.co (no signup, 1000/day)
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', '')
            country = data.get('country_name', '')
            if city and country:
                return f"{city}, {country}"
            elif country:
                return country
    except:
        pass
    
    # Fallback to ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                city = data.get('city', '')
                country = data.get('country', '')
                if city and country:
                    return f"{city}, {country}"
                elif country:
                    return country
    except:
        pass
    
    return "Unknown"

def get_geo_batch(ips, priority_ips=None, max_workers=10):
    """Fetch geo data in parallel - prioritize attacking IPs"""
    from collections import Counter
    ip_counts = Counter(ips)
    
    # Lookup all priority IPs (attacking IPs) + IPs with 5+ requests
    ips_to_lookup = set(priority_ips or [])
    ips_to_lookup.update([ip for ip, count in ip_counts.items() if count >= 5])
    ips_to_lookup = [ip for ip in ips_to_lookup if not is_private_ip(ip)]
    
    results = {}
    print(f"  Fetching geo data for {len(ips_to_lookup)} IPs using {max_workers} workers...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(get_geo_location, ip): ip for ip in ips_to_lookup}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
                time.sleep(0.1)
            except:
                results[ip] = "Unknown"
    
    # Fill remaining IPs
    for ip in set(ips):
        if ip not in results:
            if is_private_ip(ip):
                results[ip] = "Private Network"
            else:
                results[ip] = "Unknown"
    
    return results

def is_legitimate_request(path, status):
    # Legitimate patterns for PHP applications
    legitimate_patterns = [
        r'^/[a-zA-Z0-9_/-]+\.php$',  # Normal PHP files
        r'^/[a-zA-Z0-9_/-]+\.php\?route=',  # OpenCart routes
        r'^/index\.php\?',
        r'^/[a-zA-Z0-9_/-]+/(register|account|dashboard|profile|checkout|cart)',  # Laravel routes
        r'^/view_[a-zA-Z0-9_]+\.php',  # View/edit config files
        r'^/admin/[a-zA-Z0-9_/-]+\?',  # Admin panel with query params
        r'^/api/',
        r'^/assets/',
        r'^/images/',
        r'^/css/',
        r'^/js/',
        r'^/uploads/',
        r'^/static/',
        r'^/public/',
        r'^/vendor/',
        r'^/favicon\.ico',
        r'^/robots\.txt',
        r'^/sitemap\.xml',
        r'^/login$',  # Login page
        r'^/login/',  # Login routes
    ]
    
    # If status is 200 or 301/302 (success/redirect), likely legitimate
    if status in ['200', '301', '302', '304']:
        for pattern in legitimate_patterns:
            if re.match(pattern, path, re.IGNORECASE):
                return True
    
    return False

def detect_attack_type(request_path, status):
    attack_patterns = {
        'SQL Injection': [r'union.*select', r'or.*1=1', r'\bselect\b.*\bfrom\b', r'drop\s+table', r"'\s*or\s*'1'\s*=\s*'1"],
        'Path Traversal': [r'\.\./\.\./'],
        'Git Exposure': [r'\.git/', r'\.git/config', r'\.git/HEAD'],
        'Environment File': [r'\.env', r'\.aws/credentials'],
        'Config File Access': [r'wp-config\.php', r'web\.config', r'configuration\.php', r'config\.inc\.php', r'config\.php', r'config\.json', r'config\.yml', r'database\.yml'],
        'Admin Panel Scan': [r'/phpmyadmin', r'/wp-admin', r'/administrator', r'/admin(?!/)', r'authLogin', r'AppsLocalLogin', r'/partymgr', r'showLogin'],
        'Shell Upload': [r'shell\.php', r'cmd\.php', r'c99\.php', r'r57\.php', r'backdoor\.php'],
        'XSS Attempt': [r'<script>', r'javascript:', r'onerror=', r'onload='],
        'Directory Listing': [r'\?dir=', r'\?path='],
        'Backup File': [r'\.bak$', r'\.backup$', r'\.old$', r'\.sql$', r'\.zip$', r'\.tar\.gz$', r'backup\.', r'dump\.'],
        'Info Disclosure': [r'phpinfo\.php', r'info\.php', r'test\.php', r'debug\.php', r'\?phpinfo', r'sitecore.*\.xml', r'/cgi-bin/']
    }
    
    detected = []
    for attack_type, patterns in attack_patterns.items():
        for pattern in patterns:
            if re.search(pattern, request_path, re.IGNORECASE):
                detected.append(attack_type)
                break
    
    # Skip legitimate paths only if status is success AND path is normal
    if detected and status in ['200', '301', '302', '304']:
        if is_legitimate_request(request_path, status):
            return []
    
    return detected

def clean_filename(filename):
    return filename.replace('.txt', '')

def process_single_file(filepath, filename, max_workers):
    """Process a single log file and return results"""
    ip_counts = defaultdict(int)
    ip_attacks = defaultdict(list)
    file_results = []
    file_malicious = []

    try:
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            print(f"  Skipping (empty file): {filename}")
            return [], []
    except:
        print(f"  Skipping (file locked): {filename}")
        return [], []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = 0
            for line in f:
                line = line.strip().rstrip('\r\n')
                if not line:
                    continue
                line_count += 1

                if line_count == 1:
                    print(f"  First line starts with: {line[:50]}...")
                    print(f"  Line starts with h2/http: {line.startswith(('h2', 'http', 'https', 'ws', 'wss'))}")

                if line.startswith('{'):
                    try:
                        import json
                        log_data = json.loads(line)
                        client_ip = log_data.get('httpRequest', {}).get('clientIp', '')
                        if client_ip:
                            method = log_data.get('httpRequest', {}).get('httpMethod', 'GET')
                            path = log_data.get('httpRequest', {}).get('uri', '/')
                            status = log_data.get('responseCodeSent', '000')
                            action = log_data.get('action', 'UNKNOWN')
                            ip_counts[client_ip] += 1
                            if action == 'BLOCK':
                                rule_id = log_data.get('terminatingRuleId', 'Unknown Rule')
                                file_malicious.append({'stream_name': clean_filename(filename), 'ip': client_ip, 'attack_type': f'WAF Block: {rule_id}', 'method': method, 'path': path, 'status': status, 'raw_log': line})
                                if f'WAF Block: {rule_id}' not in ip_attacks[client_ip]:
                                    ip_attacks[client_ip].append(f'WAF Block: {rule_id}')
                            else:
                                for attack_type in detect_attack_type(path, status):
                                    file_malicious.append({'stream_name': clean_filename(filename), 'ip': client_ip, 'attack_type': attack_type, 'method': method, 'path': path, 'status': status, 'raw_log': line})
                                    if attack_type not in ip_attacks[client_ip]:
                                        ip_attacks[client_ip].append(attack_type)
                        continue
                    except:
                        pass

                if line.startswith(('http', 'https', 'h2', 'ws', 'wss')):
                    match = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+|-)\s+(\d+|-)\s+(\d+)\s+(\d+)\s+"([^"]+)"', line)
                    if match:
                        client_ip = match.group(4).split(':')[0]
                        status = match.group(9)
                        request_line = match.group(13)
                        req_parts = request_line.split()
                        if len(req_parts) >= 2:
                            method = req_parts[0]
                            url = req_parts[1]
                            path = '/' + url.split('/', 3)[3] if '://' in url and url.count('/') >= 3 else url
                            ip_counts[client_ip] += 1
                            for attack_type in detect_attack_type(path, status):
                                file_malicious.append({'stream_name': clean_filename(filename), 'ip': client_ip, 'attack_type': attack_type, 'method': method, 'path': path, 'status': status, 'raw_log': line})
                                if attack_type not in ip_attacks[client_ip]:
                                    ip_attacks[client_ip].append(attack_type)
                    continue

                match = re.match(r'^([\d\.]+)\s+-\s+-\s+\[.*?\]\s+"(\w+)\s+([^"]+)"\s+(\d+)', line)
                if match:
                    ip = match.group(1)
                    method, path, status = match.group(2), match.group(3), match.group(4)
                    ip_counts[ip] += 1
                    for attack_type in detect_attack_type(path, status):
                        file_malicious.append({'stream_name': clean_filename(filename), 'ip': ip, 'attack_type': attack_type, 'method': method, 'path': path, 'status': status, 'raw_log': line})
                        if attack_type not in ip_attacks[ip]:
                            ip_attacks[ip].append(attack_type)
    except Exception as e:
        print(f"  Error reading file: {e}")
        return [], []

    print(f"  Found {len(ip_counts)} unique IPs")
    ips_with_attacks = [ip for ip in ip_counts.keys() if ip in ip_attacks]
    geo_data = get_geo_batch(list(ip_counts.keys()), ips_with_attacks, max_workers)

    for ip, count in ip_counts.items():
        if ip in ip_attacks and ip_attacks[ip]:
            file_results.append({'stream_name': clean_filename(filename), 'ip': ip, 'geo_location': geo_data.get(ip, 'Unknown'), 'attack_count': count, 'attack_types': ', '.join(ip_attacks[ip])})

    print(f"  Completed!")
    return file_results, file_malicious


def analyze_attack_logs_with_streams(log_dir, progress_callback=None, max_workers=10):
    results = []
    malicious_activities = []
    files = [f for f in os.listdir(log_dir) if f.endswith('.txt')]

    print(f"Found {len(files)} log file(s)\n")
    print(f"Using {max_workers} parallel workers for analysis\n")

    def process_with_progress(args):
        idx, filename = args
        filepath = os.path.join(log_dir, filename)
        if not os.path.exists(filepath):
            print(f"  Skipping (file not found): {filename}")
            return [], []
        print(f"Processing {idx}/{len(files)}: {filename}...")
        if progress_callback:
            progress_callback(idx, len(files), f"Processing {filename}")
        return process_single_file(filepath, filename, max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_with_progress, (idx, f)): f for idx, f in enumerate(files, 1)}
        for future in as_completed(futures):
            file_results, file_malicious = future.result()
            results.extend(file_results)
            malicious_activities.extend(file_malicious)

    return results, malicious_activities

# Keep old function for backward compatibility
def analyze_attack_logs(log_dir):
    return analyze_attack_logs_with_streams(log_dir)

def save_to_csv_with_streams(results, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Stream Name', 'Client IP', 'Geo Location', 'Number of Requests', 'Attack Types'])
        for row in sorted(results, key=lambda x: (x['stream_name'], -x['attack_count'])):
            writer.writerow([row['stream_name'], row['ip'], row['geo_location'], row['attack_count'], row['attack_types']])

def save_to_csv(results, output_file):
    save_to_csv_with_streams(results, output_file)

def save_malicious_report_with_streams(malicious_activities, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Stream Name', 'Client IP', 'Attack Type', 'Method', 'Request Path', 'Status Code', 'Raw Log'])
        for activity in malicious_activities:
            writer.writerow([activity['stream_name'], activity['ip'], activity['attack_type'],
                           activity['method'], activity['path'], activity['status'], activity.get('raw_log', '')])

def save_malicious_report(malicious_activities, output_file):
    save_malicious_report_with_streams(malicious_activities, output_file)

if __name__ == "__main__":
    log_dir = os.path.join(os.path.dirname(__file__), 'Log')
    summary_file = f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    malicious_file = f"malicious_activities_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    results, malicious_activities = analyze_attack_logs(log_dir)
    save_to_csv(results, summary_file)
    save_malicious_report(malicious_activities, malicious_file)
    
    print(f"\n{'='*80}")
    print(f"Analysis complete!")
    print(f"  - Summary report: {summary_file}")
    print(f"  - Malicious activities report: {malicious_file}")
    print(f"  - Total unique IPs: {len(results)}")
    print(f"  - Total malicious activities detected: {len(malicious_activities)}")
    print(f"{'='*80}")


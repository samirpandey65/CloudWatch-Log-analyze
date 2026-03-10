from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import os
import json
from collections import defaultdict, Counter
from analyze_attacks import analyze_attack_logs_with_streams, save_to_csv_with_streams, save_malicious_report_with_streams
from datetime import datetime, timedelta
import boto3
import threading
import queue
import time
from live_monitor import monitor_manager
from auth import authenticate, login_required, admin_required, init_default_users, load_users, save_users, hash_password

app = Flask(__name__)
app.secret_key = 'cloudwatch-log-analyzer-secret-key-2024'

# Initialize default users
init_default_users()

# Start background monitor worker
def monitor_worker():
    """Background worker that continuously checks all monitors"""
    while True:
        try:
            monitors = list(monitor_manager.monitors.values())
            active_count = sum(1 for m in monitors if m.running)
            
            if active_count > 0:
                monitor_manager.check_all()
            
            # Wait for minimum check interval
            min_interval = min([m.check_interval for m in monitors if m.running], default=60)
            time.sleep(min_interval)
        except Exception as e:
            print(f"Monitor worker error: {e}")
            time.sleep(60)

worker_thread = threading.Thread(target=monitor_worker, daemon=True)
worker_thread.start()

# Global data storage
dashboard_data = {
    'results': [],
    'malicious_activities': [],
    'last_updated': None
}

# Progress queue for SSE
progress_queue = queue.Queue()

def load_analysis_data():
    """Load and analyze logs"""
    log_dir = os.path.join(os.path.dirname(__file__), 'Log')
    if os.path.exists(log_dir) and os.listdir(log_dir):
        print(f"Analyzing logs from: {log_dir}")
        
        def progress_cb(current, total, msg):
            progress_queue.put({'status': 'analyzing', 'message': msg, 'current': current, 'total': total})
        
        # Use 20 workers for faster processing (configurable)
        max_workers = int(os.environ.get('MAX_WORKERS', 20))
        results, malicious_activities = analyze_attack_logs_with_streams(log_dir, progress_cb, max_workers)
        dashboard_data['results'] = results
        dashboard_data['malicious_activities'] = malicious_activities
        dashboard_data['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Delete old reports before generating new ones
        import glob
        for old_file in glob.glob('log_analysis_*.csv') + glob.glob('malicious_activities_report_*.csv'):
            try:
                os.remove(old_file)
            except:
                pass
        
        # Generate CSV reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_file = f"log_analysis_{timestamp}.csv"
        malicious_file = f"malicious_activities_report_{timestamp}.csv"
        save_to_csv_with_streams(results, summary_file)
        save_malicious_report_with_streams(malicious_activities, malicious_file)
        print(f"Reports saved: {summary_file}, {malicious_file}")
        
        print(f"Loaded {len(results)} results and {len(malicious_activities)} malicious activities")
        return True
    else:
        print(f"No logs found in {log_dir}")
        return False

def get_top_attacked_streams(limit=20):
    """Get top 20 most attacked log streams"""
    stream_attacks = defaultdict(int)
    for activity in dashboard_data['malicious_activities']:
        stream_attacks[activity['stream_name']] += 1
    
    top_streams = sorted(stream_attacks.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{'stream': s[0], 'attacks': s[1]} for s in top_streams]

def get_top_attacker_ips(limit=20):
    """Get top 20 attacker IPs with stream names"""
    ip_attacks = defaultdict(lambda: {'count': 0, 'geo': 'Unknown', 'types': set(), 'streams': set()})
    
    for activity in dashboard_data['malicious_activities']:
        ip = activity['ip']
        ip_attacks[ip]['count'] += 1
        ip_attacks[ip]['types'].add(activity['attack_type'])
        ip_attacks[ip]['streams'].add(activity['stream_name'])
    
    # Add geo location
    for result in dashboard_data['results']:
        if result['ip'] in ip_attacks:
            ip_attacks[result['ip']]['geo'] = result['geo_location']
    
    top_ips = sorted(ip_attacks.items(), key=lambda x: x[1]['count'], reverse=True)[:limit]
    return [{'ip': ip, 'attacks': data['count'], 'geo': data['geo'], 
             'types': ', '.join(data['types']), 'streams': ', '.join(sorted(data['streams']))} for ip, data in top_ips]

def get_attack_by_country():
    """Get attack counts by country from malicious activities"""
    country_attacks = defaultdict(int)
    
    # Get geo for attacking IPs from results
    ip_geo_map = {r['ip']: r['geo_location'] for r in dashboard_data['results']}
    
    for activity in dashboard_data['malicious_activities']:
        ip = activity['ip']
        geo = ip_geo_map.get(ip, 'Unknown')
        if geo and geo not in ['Unknown', 'Private Network'] and ',' in geo:
            country = geo.split(',')[-1].strip()
            country_attacks[country] += 1
    
    return sorted([{'country': c, 'attacks': count} for c, count in country_attacks.items()], key=lambda x: x['attacks'], reverse=True)

def get_attack_types_distribution():
    """Get distribution of attack types"""
    attack_types = Counter()
    for activity in dashboard_data['malicious_activities']:
        attack_types[activity['attack_type']] += 1
    
    return [{'type': t, 'count': c} for t, c in attack_types.most_common()]

def get_summary_stats():
    """Get summary statistics"""
    if not dashboard_data['results']:
        return {'total_ips': 0, 'total_attacks': 0, 'total_streams': 0, 'malicious_ips': 0}
    
    total_ips = len(set(r['ip'] for r in dashboard_data['results']))
    total_attacks = len(dashboard_data['malicious_activities'])
    total_streams = len(set(r['stream_name'] for r in dashboard_data['results']))
    malicious_ips = len(set(a['ip'] for a in dashboard_data['malicious_activities']))
    
    return {
        'total_ips': total_ips,
        'total_attacks': total_attacks,
        'total_streams': total_streams,
        'malicious_ips': malicious_ips
    }

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', user=session.get('user'))

@app.route('/login')
def login_page():
    """Login page"""
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def login():
    """Login API"""
    data = request.json
    user = authenticate(data.get('username'), data.get('password'))
    if user:
        session['user'] = user
        return jsonify({'success': True, 'user': user})
    return jsonify({'success': False, 'error': 'Invalid credentials'})

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout API"""
    session.pop('user', None)
    return jsonify({'success': True})

@app.route('/api/current-user')
@login_required
def current_user():
    """Get current user info"""
    return jsonify({'user': session.get('user')})

@app.route('/users')
@admin_required
def users_page():
    """User management page"""
    return render_template('users.html')

@app.route('/api/users')
@admin_required
def get_users():
    """Get all users"""
    users = load_users()
    # Remove passwords from response
    safe_users = {k: {kk: vv for kk, vv in v.items() if kk != 'password'} for k, v in users.items()}
    return jsonify({'users': safe_users, 'current_user': session.get('user')})

@app.route('/api/users/add', methods=['POST'])
@admin_required
def add_user():
    """Add new user"""
    data = request.json
    users = load_users()
    
    if data['username'] in users:
        return jsonify({'success': False, 'error': 'User already exists'})
    
    users[data['username']] = {
        'password': hash_password(data['password']),
        'email': data['email'],
        'role': data['role']
    }
    save_users(users)
    return jsonify({'success': True, 'message': 'User added successfully'})

@app.route('/api/users/update', methods=['POST'])
@admin_required
def update_user():
    """Update user"""
    data = request.json
    users = load_users()
    
    if data['username'] not in users:
        return jsonify({'success': False, 'error': 'User not found'})
    
    users[data['username']]['email'] = data['email']
    users[data['username']]['role'] = data['role']
    if data.get('password'):
        users[data['username']]['password'] = hash_password(data['password'])
    
    save_users(users)
    return jsonify({'success': True, 'message': 'User updated successfully'})

@app.route('/api/users/delete', methods=['POST'])
@admin_required
def delete_user():
    """Delete user"""
    data = request.json
    users = load_users()
    
    if data['username'] not in users:
        return jsonify({'success': False, 'error': 'User not found'})
    
    if data['username'] == session['user']['username']:
        return jsonify({'success': False, 'error': 'Cannot delete yourself'})
    
    del users[data['username']]
    save_users(users)
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/api/refresh')
@login_required
def refresh_data():
    """Refresh analysis data"""
    success = load_analysis_data()
    return jsonify({'success': success, 'last_updated': dashboard_data['last_updated']})

@app.route('/api/summary')
@login_required
def get_summary():
    """Get summary statistics"""
    return jsonify(get_summary_stats())

@app.route('/api/top-streams')
@login_required
def top_streams():
    """Get top attacked streams"""
    return jsonify(get_top_attacked_streams())

@app.route('/api/top-ips')
@login_required
def top_ips():
    """Get top attacker IPs"""
    return jsonify(get_top_attacker_ips())

@app.route('/api/attack-map')
def attack_map():
    """Get attack distribution by country"""
    return jsonify(get_attack_by_country())

@app.route('/api/stream-details/<stream_name>')
def stream_details(stream_name):
    """Get detailed attack info for a specific stream"""
    stream_activities = [a for a in dashboard_data['malicious_activities'] if a['stream_name'] == stream_name]
    
    # Get unique IPs and attack types for this stream
    ip_counts = defaultdict(int)
    attack_type_counts = defaultdict(int)
    
    for activity in stream_activities:
        ip_counts[activity['ip']] += 1
        attack_type_counts[activity['attack_type']] += 1
    
    return jsonify({
        'stream_name': stream_name,
        'total_attacks': len(stream_activities),
        'unique_ips': len(ip_counts),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
        'attack_types': [{'type': t, 'count': c} for t, c in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)],
        'recent_attacks': stream_activities[:50]
    })

@app.route('/api/country-details/<country_name>')
def country_details(country_name):
    """Get detailed attack info for a specific country"""
    ip_geo_map = {r['ip']: r['geo_location'] for r in dashboard_data['results']}
    
    country_activities = [a for a in dashboard_data['malicious_activities'] 
                         if country_name in ip_geo_map.get(a['ip'], '')]
    
    ip_counts = defaultdict(int)
    attack_type_counts = defaultdict(int)
    stream_counts = defaultdict(int)
    
    for activity in country_activities:
        ip_counts[activity['ip']] += 1
        attack_type_counts[activity['attack_type']] += 1
        stream_counts[activity['stream_name']] += 1
    
    return jsonify({
        'country': country_name,
        'total_attacks': len(country_activities),
        'unique_ips': len(ip_counts),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
        'top_streams': [{'stream': s, 'count': c} for s, c in sorted(stream_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
        'attack_types': [{'type': t, 'count': c} for t, c in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)]
    })

@app.route('/api/ip-logs/<ip_address>')
def ip_logs(ip_address):
    """Get detailed log entries for a specific IP"""
    ip_logs = [a for a in dashboard_data['malicious_activities'] if a['ip'] == ip_address]
    
    return jsonify({
        'ip': ip_address,
        'total_logs': len(ip_logs),
        'logs': ip_logs[:100]  # Limit to 100 most recent
    })

@app.route('/api/full-report')
def full_report():
    """Get complete detailed report"""
    return jsonify({
        'summary': get_summary_stats(),
        'results': dashboard_data['results'],
        'malicious_activities': dashboard_data['malicious_activities'],
        'last_updated': dashboard_data['last_updated']
    })

@app.route('/api/download-report')
def download_report():
    """Download complete report as CSV"""
    import io
    import csv
    from flask import make_response
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write malicious activities
    writer.writerow(['Stream Name', 'IP Address', 'Geo Location', 'Attack Type', 'Method', 'Path', 'Status', 'Raw Log'])
    
    ip_geo_map = {r['ip']: r['geo_location'] for r in dashboard_data['results']}
    
    for activity in dashboard_data['malicious_activities']:
        writer.writerow([
            activity['stream_name'],
            activity['ip'],
            ip_geo_map.get(activity['ip'], 'Unknown'),
            activity['attack_type'],
            activity['method'],
            activity['path'],
            activity['status'],
            activity.get('raw_log', '')
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=complete_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/api/download-pdf')
def download_pdf():
    """Download complete report as PDF"""
    from flask import make_response
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_LEFT
        import io
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), topMargin=0.5*inch, bottomMargin=0.5*inch, leftMargin=0.5*inch, rightMargin=0.5*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=22, textColor=colors.HexColor('#667eea'), spaceAfter=10, alignment=1)
        elements.append(Paragraph('AWS Log Attack Dashboard - Security Analysis Report', title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary Statistics
        summary = get_summary_stats()
        summary_data = [
            ['Total IPs', 'Malicious IPs', 'Total Attacks', 'Log Streams'],
            [str(summary['total_ips']), str(summary['malicious_ips']), str(summary['total_attacks']), str(summary['total_streams'])]
        ]
        summary_table = Table(summary_data, colWidths=[2.5*inch]*4)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, 1), 18),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 1), (-1, 1), 12),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Log Overview Section
        overview_style = ParagraphStyle('Overview', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#764ba2'), spaceAfter=8)
        elements.append(Paragraph('Log Analysis Overview', overview_style))
        
        # Get log time range and stream info
        log_streams = set(r['stream_name'] for r in dashboard_data['results'])
        attack_type_summary = defaultdict(int)
        for activity in dashboard_data['malicious_activities']:
            attack_type_summary[activity['attack_type']] += 1
        
        overview_text = ParagraphStyle('OverviewText', parent=styles['Normal'], fontSize=9, spaceAfter=5, leftIndent=10)
        elements.append(Paragraph(f'<b>Analysis Period:</b> {dashboard_data["last_updated"]}', overview_text))
        elements.append(Paragraph(f'<b>Total Servers Analyzed:</b> {len(log_streams)}', overview_text))
        elements.append(Paragraph(f'<b>Total Malicious Activities Detected:</b> {len(dashboard_data["malicious_activities"])}', overview_text))
        
        # Top attack types summary
        top_attack_types = sorted(attack_type_summary.items(), key=lambda x: x[1], reverse=True)[:5]
        attack_summary_text = ', '.join([f'{atype} ({count})' for atype, count in top_attack_types])
        elements.append(Paragraph(f'<b>Most Common Attack Types:</b> {attack_summary_text}', overview_text))
        elements.append(Spacer(1, 0.2*inch))
        
        # Get attack recommendations
        attack_recommendations = {
            'SQL Injection': 'Use parameterized queries, input validation, and WAF rules',
            'XSS Attempt': 'Implement output encoding, Content Security Policy (CSP)',
            'Path Traversal': 'Validate file paths, restrict directory access',
            'Shell Upload': 'Block file uploads, scan uploaded files, restrict execution',
            'Admin Panel Scan': 'Implement rate limiting, use strong authentication',
            'Config File Access': 'Restrict file permissions, move configs outside web root',
            'Git Exposure': 'Block .git directory access in web server config',
            'Environment File': 'Move .env files outside web root, use proper permissions',
            'Backup File': 'Remove backup files from production, block access',
            'Directory Listing': 'Disable directory listing in web server',
            'Suspicious Activity': 'Review logs, implement IP blocking, enable monitoring'
        }
        
        # Group attacks by stream and get top IPs per stream
        stream_attacks = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'types': set()}))
        ip_geo_map = {r['ip']: r['geo_location'] for r in dashboard_data['results']}
        
        for activity in dashboard_data['malicious_activities']:
            stream = activity['stream_name']
            ip = activity['ip']
            stream_attacks[stream][ip]['count'] += 1
            stream_attacks[stream][ip]['types'].add(activity['attack_type'])
        
        # Get top streams
        top_streams = sorted(stream_attacks.items(), key=lambda x: sum(ip['count'] for ip in x[1].values()), reverse=True)[:5]
        
        section_style = ParagraphStyle('SectionTitle', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#667eea'), spaceAfter=8)
        
        for stream_name, ips in top_streams:
            elements.append(Paragraph(f'Server: {stream_name}', section_style))
            
            # Top 10 IPs for this stream
            top_ips = sorted(ips.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
            
            ip_data = [['Rank', 'IP Address', 'Location', 'Attacks', 'Attack Types']]
            for idx, (ip, data) in enumerate(top_ips, 1):
                ip_data.append([
                    str(idx),
                    ip,
                    ip_geo_map.get(ip, 'Unknown')[:25],
                    str(data['count']),
                    ', '.join(list(data['types'])[:3])[:45]
                ])
            
            ip_table = Table(ip_data, colWidths=[0.4*inch, 1.1*inch, 2*inch, 0.7*inch, 3*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#764ba2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')])
            ]))
            elements.append(ip_table)
            
            # Attack types and recommendations for this stream
            stream_attack_types = set()
            for ip_data in ips.values():
                stream_attack_types.update(ip_data['types'])
            
            if stream_attack_types:
                elements.append(Spacer(1, 0.1*inch))
                rec_style = ParagraphStyle('Recommendation', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#333333'), leftIndent=10, spaceAfter=3, alignment=TA_LEFT)
                elements.append(Paragraph('<b>Detected Attacks & Recommendations:</b>', rec_style))
                
                for attack_type in sorted(stream_attack_types)[:5]:
                    recommendation = attack_recommendations.get(attack_type, 'Review logs and implement security best practices')
                    if 'WAF' in attack_type:
                        recommendation = 'Review WAF rules, consider blocking source IPs'
                    elements.append(Paragraph(f'• <b>{attack_type}:</b> {recommendation}', rec_style))
            
            elements.append(Spacer(1, 0.15*inch))
            
            # Page break after every 2 streams
            if top_streams.index((stream_name, ips)) % 2 == 1 and top_streams.index((stream_name, ips)) < len(top_streams) - 1:
                elements.append(PageBreak())
        
        # Footer
        elements.append(Spacer(1, 0.2*inch))
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.grey, alignment=1)
        elements.append(Paragraph(f'Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | For complete logs, download CSV report', footer_style))
        
        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()
        
        response = make_response(pdf)
        response.headers['Content-Disposition'] = f'attachment; filename=security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        response.headers['Content-Type'] = 'application/pdf'
        return response
    except ImportError:
        return jsonify({'error': 'reportlab not installed. Run: pip install reportlab'}), 500

@app.route('/fetch')
@login_required
def fetch_page():
    """Fetch logs page"""
    return render_template('fetch.html')

@app.route('/fetch-s3')
@login_required
def fetch_s3_page():
    """Fetch S3 logs page"""
    return render_template('fetch_s3.html')

@app.route('/api/fetch-logs', methods=['POST'])
def fetch_logs_api():
    """API endpoint to fetch logs from CloudWatch"""
    req_data = request.json
    
    def run_fetch():
        try:
            log_groups = req_data.get('log_groups', [])
            time_range = req_data.get('time_range', 'hours')
            time_data = req_data.get('time_data', {})
            region = req_data.get('region', 'us-west-2')
            max_workers = req_data.get('max_workers', 20)
            
            # Set environment variable for this request
            os.environ['MAX_WORKERS'] = str(max_workers)
            
            progress_queue.put({'status': 'started', 'message': f'Starting log fetch with {max_workers} workers...'})
            
            if time_range == 'hours':
                hours = time_data.get('hours', 24)
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=hours)
            else:
                start_time = datetime.strptime(time_data['start_date'], '%Y-%m-%dT%H:%M')
                end_time = datetime.strptime(time_data['end_date'], '%Y-%m-%dT%H:%M')
            
            from fetch_and_analyze import fetch_cloudwatch_logs_with_progress
            
            for idx, log_group in enumerate(log_groups):
                progress_queue.put({'status': 'fetching', 'message': f'Fetching from {log_group}...'})
                # Only cleanup on first log group (idx == 0)
                fetch_cloudwatch_logs_with_progress(log_group.strip(), start_time, end_time, region, progress_queue, skip_cleanup=(idx > 0))
            
            progress_queue.put({'status': 'analyzing', 'message': 'Starting analysis...', 'current': 0, 'total': 0})
            load_analysis_data()
            
            progress_queue.put({
                'status': 'completed',
                'message': 'Fetch completed!',
                'total_logs': len(dashboard_data['results']),
                'total_attacks': len(dashboard_data['malicious_activities'])
            })
        except Exception as e:
            progress_queue.put({'status': 'error', 'message': str(e)})
    
    thread = threading.Thread(target=run_fetch)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Fetch started'})

@app.route('/api/fetch-progress')
def fetch_progress():
    """SSE endpoint for fetch progress"""
    def generate():
        while True:
            try:
                msg = progress_queue.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('status') in ['completed', 'error']:
                    break
            except:
                yield f"data: {{\"status\": \"keepalive\"}}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/fetch-s3-logs', methods=['POST'])
def fetch_s3_logs_api():
    """API endpoint to fetch logs from S3"""
    req_data = request.json
    
    def run_s3_fetch():
        try:
            from fetch_s3_logs import fetch_s3_logs, parse_s3_url
            
            bucket_input = req_data.get('bucket_name', '')
            prefix = req_data.get('prefix', '')
            time_range = req_data.get('time_range', 'hours')
            time_data = req_data.get('time_data', {})
            region = req_data.get('region', 'us-west-2')
            max_workers = req_data.get('max_workers', 20)
            
            # Set environment variable for this request
            os.environ['MAX_WORKERS'] = str(max_workers)
            
            # Parse S3 URL if provided
            if bucket_input.startswith('s3://'):
                bucket_name, parsed_prefix = parse_s3_url(bucket_input)
                if not prefix:  # Use parsed prefix if no manual prefix provided
                    prefix = parsed_prefix
            else:
                bucket_name = bucket_input
            
            progress_queue.put({'status': 'started', 'message': 'Starting S3 log fetch...'})
            
            if time_range == 'hours':
                hours = time_data.get('hours', 24)
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=hours)
            else:
                start_time = datetime.strptime(time_data['start_date'], '%Y-%m-%dT%H:%M')
                end_time = datetime.strptime(time_data['end_date'], '%Y-%m-%dT%H:%M')
            
            progress_queue.put({'status': 'fetching', 'message': f'Fetching from S3 bucket {bucket_name}...'})
            fetch_s3_logs(bucket_name, start_time, end_time, region, prefix, progress_queue)
            
            progress_queue.put({'status': 'analyzing', 'message': 'Starting analysis...', 'current': 0, 'total': 0})
            load_analysis_data()
            
            progress_queue.put({
                'status': 'completed',
                'message': 'S3 fetch completed!',
                'total_logs': len(dashboard_data['results']),
                'total_attacks': len(dashboard_data['malicious_activities'])
            })
        except Exception as e:
            progress_queue.put({'status': 'error', 'message': str(e)})
    
    thread = threading.Thread(target=run_s3_fetch)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'S3 fetch started'})

@app.route('/live-monitor')
@login_required
def live_monitor_page():
    """Live monitoring page"""
    return render_template('live_monitor.html')

@app.route('/live-logs')
def live_logs_page():
    """Live log streaming page"""
    return render_template('live_logs.html')

@app.route('/log-fetch')
def log_fetch_page():
    """Log fetch options page"""
    return render_template('log_fetch.html')

@app.route('/reports')
def reports_page():
    """Reports listing page"""
    return render_template('reports.html')

@app.route('/api/list-reports')
def list_reports():
    """List all generated CSV reports"""
    import glob
    reports = []
    for pattern in ['log_analysis_*.csv', 'malicious_activities_report_*.csv']:
        for filepath in glob.glob(pattern):
            stat = os.stat(filepath)
            reports.append({
                'name': os.path.basename(filepath),
                'size': f"{stat.st_size // 1024} KB",
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
    reports.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify({'reports': reports})

@app.route('/api/download-file/<filename>')
def download_file(filename):
    """Download a specific report file"""
    from flask import send_file
    if filename.startswith(('log_analysis_', 'malicious_activities_report_')) and filename.endswith('.csv'):
        filepath = os.path.join(os.path.dirname(__file__), filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/view-file/<filename>')
def view_file(filename):
    """View CSV file content"""
    import csv
    if filename.startswith(('log_analysis_', 'malicious_activities_report_')) and filename.endswith('.csv'):
        filepath = os.path.join(os.path.dirname(__file__), filename)
        if os.path.exists(filepath):
            rows = []
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    rows.append(row)
            return jsonify({'rows': rows})
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/stream-logs')
def stream_logs():
    """SSE endpoint for live log streaming"""
    log_group = request.args.get('log_group')
    region = request.args.get('region', 'us-west-2')
    
    def generate():
        import boto3
        from datetime import datetime, timedelta
        import time
        
        try:
            client = boto3.client('logs', region_name=region)
            last_time = datetime.now() - timedelta(minutes=1)
            
            while True:
                try:
                    end_time = datetime.now()
                    
                    response = client.filter_log_events(
                        logGroupName=log_group,
                        startTime=int(last_time.timestamp() * 1000),
                        endTime=int(end_time.timestamp() * 1000)
                    )
                    
                    events = response.get('events', [])
                    
                    for event in events:
                        message = event['message']
                        stream = event.get('logStreamName', 'Unknown')
                        timestamp = event.get('timestamp', int(datetime.now().timestamp() * 1000))
                        
                        # Detect log type
                        log_type = 'info'
                        if 'error' in message.lower() or 'exception' in message.lower():
                            log_type = 'error'
                        elif 'warn' in message.lower():
                            log_type = 'warning'
                        
                        # Check for attacks
                        is_attack = False
                        attack_type = None
                        
                        # Parse log for attack detection
                        import re
                        match = re.search(r'"(\w+)\s+([^"]+)"\s+(\d+)', message)
                        if match:
                            path = match.group(2)
                            status = match.group(3)
                            from analyze_attacks import detect_attack_type
                            attack_types = detect_attack_type(path, status)
                            if attack_types:
                                is_attack = True
                                attack_type = attack_types[0]
                                log_type = 'attack'
                        
                        log_data = {
                            'status': 'log',
                            'timestamp': timestamp,
                            'stream': stream,
                            'message': message,
                            'log_type': log_type,
                            'is_attack': is_attack,
                            'attack_type': attack_type
                        }
                        
                        yield f"data: {json.dumps(log_data)}\n\n"
                    
                    last_time = end_time
                    time.sleep(2)  # Check every 2 seconds
                    
                except Exception as e:
                    error_data = {'status': 'error', 'message': str(e)}
                    yield f"data: {json.dumps(error_data)}\n\n"
                    break
        except Exception as e:
            error_data = {'status': 'error', 'message': str(e)}
            yield f"data: {json.dumps(error_data)}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/monitor/add', methods=['POST'])
def add_monitor():
    """Add a new live monitor"""
    data = request.json
    log_group = data.get('log_group')
    region = data.get('region', 'us-west-2')
    check_interval = data.get('check_interval', 60)
    
    success = monitor_manager.add_monitor(log_group, region, check_interval)
    return jsonify({'success': success})

@app.route('/api/monitor/remove', methods=['POST'])
def remove_monitor():
    """Remove a live monitor"""
    data = request.json
    log_group = data.get('log_group')
    
    success = monitor_manager.remove_monitor(log_group)
    return jsonify({'success': success})

@app.route('/api/monitor/status')
def monitor_status():
    """Get status of all monitors"""
    return jsonify(monitor_manager.get_status())

@app.route('/api/monitor/alerts')
def monitor_alerts():
    """Get all alerts"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(monitor_manager.get_all_alerts(limit))

@app.route('/api/monitor/check', methods=['POST'])
def check_monitors():
    """Manually trigger check for all monitors"""
    alerts = monitor_manager.check_all()
    return jsonify({'success': True, 'new_alerts': len(alerts), 'alerts': alerts})

@app.route('/api/recent-logs')
def recent_logs():
    """Get recent logs from a log group"""
    log_group = request.args.get('log_group')
    region = request.args.get('region', 'us-west-2')
    limit = request.args.get('limit', 5, type=int)
    
    try:
        client = boto3.client('logs', region_name=region)
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=5)
        
        response = client.filter_log_events(
            logGroupName=log_group,
            startTime=int(start_time.timestamp() * 1000),
            endTime=int(end_time.timestamp() * 1000),
            limit=limit
        )
        
        logs = []
        for event in response.get('events', []):
            message = event['message']
            timestamp = event.get('timestamp', int(datetime.now().timestamp() * 1000))
            
            # Check for attacks
            is_attack = False
            attack_type = None
            import re
            match = re.search(r'"(\w+)\s+([^"]+)"\s+(\d+)', message)
            if match:
                path = match.group(2)
                status = match.group(3)
                from analyze_attacks import detect_attack_type
                attack_types = detect_attack_type(path, status)
                if attack_types:
                    is_attack = True
                    attack_type = attack_types[0]
            
            logs.append({
                'timestamp': timestamp,
                'message': message,
                'is_attack': is_attack,
                'attack_type': attack_type
            })
        
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e), 'logs': []})

@app.route('/api/email-config', methods=['GET', 'POST'])
def email_config():
    """Get or update email configuration"""
    config_file = os.path.join(os.path.dirname(__file__), 'email_config.json')
    
    if request.method == 'POST':
        config = request.json
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Reload config in all monitors
        for monitor in monitor_manager.monitors.values():
            monitor.email_config = monitor.load_email_config()
        
        return jsonify({'success': True})
    else:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Hide password
                if 'password' in config:
                    config['password'] = '***' if config['password'] else ''
                return jsonify(config)
        return jsonify({'enabled': False})

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Send a test email"""
    config_file = os.path.join(os.path.dirname(__file__), 'email_config.json')
    
    if not os.path.exists(config_file):
        return jsonify({'success': False, 'error': 'Email not configured'})
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        if not config.get('enabled'):
            return jsonify({'success': False, 'error': 'Email notifications are disabled'})
        
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = 'Test Email - CloudWatch Log Analyzer'
        
        body = f"""<html><body>
        <h2>Test Email Successful!</h2>
        <p>This is a test email from CloudWatch Log Analyzer.</p>
        <p><b>Configuration:</b></p>
        <ul>
            <li>SMTP Server: {config['smtp_server']}</li>
            <li>SMTP Port: {config['smtp_port']}</li>
            <li>From: {config['from_email']}</li>
            <li>To: {', '.join(config['to_emails'])}</li>
        </ul>
        <p>If you received this email, your configuration is working correctly!</p>
        <p><i>Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i></p>
        </body></html>"""
        
        msg.attach(MIMEText(body, 'html'))
        
        # Try SMTP with STARTTLS (port 587) or SMTP_SSL (port 465)
        if config['smtp_port'] == 465:
            server = smtplib.SMTP_SSL(config['smtp_server'], config['smtp_port'])
        else:
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'], timeout=10)
            server.starttls()
        server.login(config['from_email'], config['password'])
        server.send_message(msg)
        server.quit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    print("="*80)
    print("AWS LOG ATTACK DASHBOARD")
    print("="*80)
    print("\nLoading initial data...")
    success = load_analysis_data()
    if success:
        print(f"✓ Data loaded successfully")
        print(f"✓ Total IPs: {len(set(r['ip'] for r in dashboard_data['results']))}")
        print(f"✓ Total Attacks: {len(dashboard_data['malicious_activities'])}")
    else:
        print("Warning: No data loaded. Run fetch_and_analyze.py first to fetch logs.")
    print(f"\n🌐 Dashboard starting at http://localhost:5000")
    print(f"   Press Ctrl+C to stop\n")
    app.run(debug=False, host='0.0.0.0', port=5000)

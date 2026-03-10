import boto3
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os
import re
from analyze_attacks import detect_attack_type

class LiveMonitor:
    def __init__(self, log_group, region='us-west-2', check_interval=60):
        self.log_group = log_group
        self.region = region
        self.check_interval = check_interval
        self.client = boto3.client('logs', region_name=region)
        self.running = False
        self.last_check_time = None
        self.alerts = []
        self.email_config = self.load_email_config()
        self.emailed_alerts = set()  # Track sent emails: (ip, attack_type, path)
        
    def load_email_config(self):
        config_file = os.path.join(os.path.dirname(__file__), 'email_config.json')
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        return None
    
    def parse_log_entry(self, log_line):
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (.*?) HTTP/\d\.\d" (\d+)'
        match = re.match(pattern, log_line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'status': match.group(5)
            }
        return None
    
    def check_logs(self):
        end_time = datetime.now()
        start_time = self.last_check_time or (end_time - timedelta(minutes=5))
        
        kwargs = {
            'logGroupName': self.log_group,
            'startTime': int(start_time.timestamp() * 1000),
            'endTime': int(end_time.timestamp() * 1000)
        }
        
        new_alerts = []
        
        try:
            response = self.client.filter_log_events(**kwargs)
            events = response.get('events', [])
            
            for event in events:
                log_entry = self.parse_log_entry(event['message'])
                if log_entry:
                    attack_types = detect_attack_type(log_entry['path'], log_entry['status'])
                    if attack_types:
                        for attack_type in attack_types:
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'log_group': self.log_group,
                                'stream': event.get('logStreamName', 'Unknown'),
                                'ip': log_entry['ip'],
                                'attack_type': attack_type,
                                'method': log_entry['method'],
                                'path': log_entry['path'],
                                'status': log_entry['status']
                            }
                            new_alerts.append(alert)
                            self.alerts.append(alert)
            
            # Filter new alerts for email (remove duplicates)
            if new_alerts and self.email_config:
                unique_alerts = []
                for alert in new_alerts:
                    alert_key = (alert['ip'], alert['attack_type'], alert['path'])
                    if alert_key not in self.emailed_alerts:
                        unique_alerts.append(alert)
                        self.emailed_alerts.add(alert_key)
                
                if unique_alerts:
                    self.send_email_alert(unique_alerts)
            
            self.last_check_time = end_time
            return new_alerts
            
        except Exception as e:
            print(f"Error checking logs: {e}")
            return []
    
    def send_email_alert(self, alerts):
        if not self.email_config or not self.email_config.get('enabled'):
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = ', '.join(self.email_config['to_emails'])
            msg['Subject'] = f"Security Alert: {len(alerts)} NEW threats detected in {self.log_group}"
            
            # Count total attacks including duplicates
            total_attacks = len(self.alerts)
            unique_sent = len(alerts)
            
            body = f"<h2>Security Threats Detected</h2>"
            body += f"<p><b>Log Group:</b> {self.log_group}</p>"
            body += f"<p><b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
            body += f"<p><b>New Unique Threats:</b> {unique_sent}</p>"
            body += f"<p><b>Total Attacks (including duplicates):</b> {total_attacks}</p><hr>"
            
            for alert in alerts[:10]:
                body += f"<div style='margin:10px 0; padding:10px; background:#f5f5f5;'>"
                body += f"<b>IP:</b> {alert['ip']}<br>"
                body += f"<b>Attack Type:</b> {alert['attack_type']}<br>"
                body += f"<b>Path:</b> {alert['path']}<br>"
                body += f"<b>Method:</b> {alert['method']} | <b>Status:</b> {alert['status']}<br>"
                body += f"<b>Log Group:</b> {alert['log_group']}<br>"
                body += f"<b>Stream:</b> {alert['stream']}<br>"
                body += f"</div>"
            
            if len(alerts) > 10:
                body += f"<p>... and {len(alerts) - 10} more unique threats</p>"
            
            body += f"<p style='color:#999; font-size:12px;'><i>Note: Duplicate alerts (same IP, attack type, and path) are not sent again via email but are counted in total attacks.</i></p>"
            
            msg.attach(MIMEText(body, 'html'))
            
            if self.email_config['smtp_port'] == 465:
                server = smtplib.SMTP_SSL(self.email_config['smtp_server'], self.email_config['smtp_port'])
            else:
                server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'], timeout=10)
                server.starttls()
            server.login(self.email_config['from_email'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"Email alert sent for {len(alerts)} threats")
        except Exception as e:
            print(f"Error sending email: {e}")
    
    def start(self):
        self.running = True
        self.last_check_time = datetime.now() - timedelta(minutes=5)
        print(f"Live monitor started for {self.log_group}")
        
    def stop(self):
        self.running = False
        print(f"Live monitor stopped for {self.log_group}")
    
    def get_status(self):
        return {
            'log_group': self.log_group,
            'region': self.region,
            'running': self.running,
            'last_check': self.last_check_time.isoformat() if self.last_check_time else None,
            'total_alerts': len(self.alerts),
            'check_interval': self.check_interval
        }

class MonitorManager:
    def __init__(self):
        self.monitors = {}
        self.state_file = os.path.join(os.path.dirname(__file__), 'monitor_state.json')
        self.load_state()
    
    def add_monitor(self, log_group, region='us-west-2', check_interval=60):
        if log_group not in self.monitors:
            monitor = LiveMonitor(log_group, region, check_interval)
            monitor.start()
            self.monitors[log_group] = monitor
            self.save_state()
            return True
        return False
    
    def remove_monitor(self, log_group):
        if log_group in self.monitors:
            self.monitors[log_group].stop()
            del self.monitors[log_group]
            self.save_state()
            return True
        return False
    
    def check_all(self):
        all_alerts = []
        for monitor in self.monitors.values():
            if monitor.running:
                alerts = monitor.check_logs()
                all_alerts.extend(alerts)
        return all_alerts
    
    def get_all_alerts(self, limit=100):
        all_alerts = []
        for monitor in self.monitors.values():
            all_alerts.extend(monitor.alerts)
        return sorted(all_alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_status(self):
        return [monitor.get_status() for monitor in self.monitors.values()]
    
    def save_state(self):
        state = {
            'monitors': [
                {
                    'log_group': m.log_group,
                    'region': m.region,
                    'check_interval': m.check_interval
                }
                for m in self.monitors.values()
            ]
        }
        with open(self.state_file, 'w') as f:
            json.dump(state, f)
    
    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    for m in state.get('monitors', []):
                        self.add_monitor(m['log_group'], m['region'], m['check_interval'])
            except:
                pass

monitor_manager = MonitorManager()

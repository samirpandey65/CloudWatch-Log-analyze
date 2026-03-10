# CloudWatch Log Analyzer

Fetch logs from AWS CloudWatch Log Groups or S3 buckets and analyze them for security threats and malicious activities.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure AWS credentials:
```bash
aws configure
```
Or set environment variables:
```bash
set AWS_ACCESS_KEY_ID=<your-key>
set AWS_SECRET_ACCESS_KEY=<your-secret>
set AWS_DEFAULT_REGION=us-east-1
```

## Usage

### Option 1: CloudWatch Logs

Run the script:
```bash
python fetch_and_analyze.py
```

You'll be prompted for:
- CloudWatch Log Group name
- Hours of logs to fetch (default: 24)
- AWS region (default: us-east-1)

### Option 2: S3 Logs

Run the S3 fetch script:
```bash
python fetch_s3_logs.py
```

You'll be prompted for:
- S3 bucket name
- Prefix/folder path (optional)
- Time range (hours or specific date range)
- AWS region (default: us-west-2)

### Option 3: Web Dashboard

Run the dashboard:
```bash
python dashboard.py
```

Access at http://localhost:5000
- Fetch CloudWatch logs via web interface
- Fetch S3 logs via web interface
- View interactive security analysis
- Download CSV/PDF reports

### Option 4: Live Monitoring

Access the Live Monitoring section in the dashboard:
1. Navigate to http://localhost:5000/live-monitor
2. Add CloudWatch log groups to monitor
3. Configure email notifications (optional)
4. View real-time alerts as threats are detected

Features:
- Continuous monitoring of CloudWatch log groups
- Real-time threat detection
- Email notifications for security alerts
- View currently running monitors
- Check status and alert history

## Output

The tool generates two CSV reports:
1. **log_analysis_[timestamp].csv** - Summary of IPs, locations, and attack types
2. **malicious_activities_report_[timestamp].csv** - Detailed malicious activity log

## Features

- Fetches logs from CloudWatch Log Groups
- Downloads JSON logs from S3 buckets with time-based filtering
- Detects multiple attack types (SQL injection, XSS, path traversal, etc.)
- Geo-location lookup for IP addresses
- Filters legitimate requests from suspicious ones
- Generates comprehensive CSV reports
- Interactive web dashboard with real-time analysis
- **Live monitoring with real-time alerts**
- **Email notifications for security threats**
- **Monitor multiple log groups simultaneously**
- **View active monitors and alert history**




My Gmail App password 
Password:= otnx grfi shsr toem
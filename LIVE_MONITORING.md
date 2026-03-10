# Live Monitoring Quick Start Guide

## What is Live Monitoring?

Live Monitoring continuously watches your CloudWatch log groups for security threats in real-time. When malicious activity is detected, you'll see alerts immediately and optionally receive email notifications.

## Getting Started

### 1. Start the Dashboard

```bash
python dashboard.py
```

The dashboard will start at http://localhost:5000

### 2. Navigate to Live Monitoring

- Click "🔴 Live Monitoring" in the sidebar
- Or go directly to http://localhost:5000/live-monitor

### 3. Add a Monitor

Fill in the form:
- **Log Group Name**: Your CloudWatch log group (e.g., `/aws/lambda/my-function`)
- **AWS Region**: Select your AWS region (default: us-west-2)
- **Check Interval**: How often to check for new logs (default: 60 seconds)

Click "🚀 Start Monitoring"

### 4. Configure Email Notifications (Optional)

1. Check "Enable Email Notifications"
2. Enter your SMTP details:
   - For Gmail: Use `smtp.gmail.com` port `587`
   - Generate an App Password (see EMAIL_SETUP.md)
3. Enter recipient email addresses (comma separated)
4. Click "💾 Save Configuration"

### 5. Monitor Alerts

The "Recent Alerts" section shows:
- Attack type detected
- Source IP address
- Log group and stream
- Request details (method, path, status)
- Timestamp

## Features

### Active Monitors Section
- View all running monitors
- See last check time
- View total alerts per monitor
- Stop/remove monitors

### Recent Alerts Section
- Real-time threat notifications
- Last 50 alerts displayed
- Auto-refreshes every 30 seconds
- Manual "Check Now" button for immediate scan

### Email Notifications
- Automatic emails when threats detected
- Includes top 10 threats per email
- Configurable recipients
- Works with Gmail, Outlook, Yahoo, and custom SMTP

## How It Works

1. **Background Worker**: Runs continuously checking all active monitors
2. **Log Scanning**: Fetches new logs since last check
3. **Threat Detection**: Analyzes logs for attack patterns
4. **Alert Generation**: Creates alerts for malicious activity
5. **Notification**: Displays in dashboard and sends emails

## Attack Types Detected

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Shell Upload Attempts
- Admin Panel Scanning
- Config File Access
- Git Repository Exposure
- Environment File Access
- Backup File Access
- Directory Listing
- Suspicious Activity

## Best Practices

1. **Check Interval**: 
   - Use 60-120 seconds for production
   - Lower intervals (30s) for high-security environments
   - Higher intervals (300s+) for low-traffic logs

2. **Multiple Monitors**:
   - Monitor critical log groups separately
   - Use different check intervals based on importance

3. **Email Notifications**:
   - Use distribution lists for team notifications
   - Set up email filters to prioritize alerts
   - Test configuration before relying on it

4. **Alert Management**:
   - Review alerts regularly
   - Investigate high-severity threats immediately
   - Use "Check Now" for on-demand scans

## Monitoring Status

The dashboard shows:
- 🟢 Running: Monitor is actively checking logs
- 🔴 Stopped: Monitor has been stopped
- Last Check: Timestamp of most recent scan
- Total Alerts: Cumulative threats detected

## Stopping Monitors

To stop monitoring a log group:
1. Find the monitor in "Active Monitors"
2. Click "🗑️ Remove"
3. Confirm the action

Note: Removing a monitor doesn't delete alert history.

## Persistence

- Monitor configurations are saved to `monitor_state.json`
- Monitors automatically restart when dashboard restarts
- Alert history is kept in memory (cleared on restart)

## Troubleshooting

**Monitor not detecting threats?**
- Verify log group name is correct
- Check AWS credentials have CloudWatch read permissions
- Ensure logs are being written to the group

**Emails not sending?**
- See EMAIL_SETUP.md for detailed configuration
- Test SMTP settings with a simple email client first
- Check firewall/network allows SMTP connections

**Dashboard slow?**
- Increase check intervals
- Reduce number of active monitors
- Check AWS API rate limits

## AWS Permissions Required

Your AWS credentials need:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:*"
    }
  ]
}
```

## Next Steps

- Set up monitors for all critical log groups
- Configure email notifications for your team
- Review alerts daily
- Integrate with incident response workflow
- Export alerts for compliance reporting

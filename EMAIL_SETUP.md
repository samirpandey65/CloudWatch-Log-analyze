# Email Notification Setup Guide

## Gmail Setup (Recommended)

1. **Enable 2-Factor Authentication**
   - Go to your Google Account settings
   - Navigate to Security
   - Enable 2-Step Verification

2. **Generate App Password**
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and "Other (Custom name)"
   - Name it "CloudWatch Monitor"
   - Copy the 16-character password

3. **Configure in Dashboard**
   - Navigate to Live Monitoring page
   - Enable Email Notifications
   - SMTP Server: `smtp.gmail.com`
   - SMTP Port: `587`
   - From Email: Your Gmail address
   - Password: The 16-character app password
   - To Emails: Recipient email addresses (comma separated)

## Other Email Providers

### Outlook/Office 365
- SMTP Server: `smtp.office365.com`
- SMTP Port: `587`
- Use your Outlook email and password

### Yahoo Mail
- SMTP Server: `smtp.mail.yahoo.com`
- SMTP Port: `587`
- Generate app password from Yahoo Account Security

### Custom SMTP Server
- Use your organization's SMTP server details
- Ensure port 587 (TLS) is accessible
- Use appropriate credentials

## Testing Email Notifications

1. Configure email settings in the dashboard
2. Add a monitor for a log group
3. Click "Check Now" to manually trigger a check
4. If threats are detected, you'll receive an email

## Troubleshooting

**Email not sending?**
- Verify SMTP credentials are correct
- Check if 2FA is enabled and app password is used
- Ensure firewall allows outbound SMTP connections
- Check spam/junk folder for test emails

**Gmail blocking sign-in?**
- Use App Password instead of regular password
- Enable "Less secure app access" (not recommended)
- Check Google Account security alerts

## Email Format

Emails include:
- Log group name
- Timestamp of detection
- Total number of threats
- Top 10 threat details (IP, attack type, path, stream)
- Link to dashboard for full details

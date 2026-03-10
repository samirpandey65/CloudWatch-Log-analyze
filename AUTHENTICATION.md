# Authentication System

## Overview

The CloudWatch Log Analyzer now includes a complete authentication system with animated login/logout pages and role-based access control.

## Features

- **Animated Login Page** - Modern, responsive login interface with smooth animations
- **Role-Based Access Control** - Two user roles: Admin and User
- **User Management** - Admin can create, edit, and delete users
- **Session Management** - Secure session-based authentication
- **Password Hashing** - SHA-256 password encryption

## Default Users

### Admin Account
- **Username:** admin
- **Password:** admin123
- **Role:** admin
- **Permissions:** Full access including user management

### User Account
- **Username:** user
- **Password:** user123
- **Role:** user
- **Permissions:** Access to dashboard and reports (no user management)

## User Roles

### Admin
- Full access to all features
- Can manage users (create, edit, delete)
- Can access user management page at `/users`
- Can view and download all reports
- Can fetch logs and configure monitoring

### User
- Access to dashboard and analytics
- Can view reports
- Can fetch logs
- Cannot manage other users
- Cannot access user management page

## Usage

### First Time Setup

1. Start the dashboard:
```bash
python dashboard.py
```

2. Navigate to http://localhost:5000

3. You'll be redirected to the login page

4. Login with default credentials:
   - Admin: `admin` / `admin123`
   - User: `user` / `user123`

### Managing Users (Admin Only)

1. Login as admin
2. Click "User Management" in the sidebar
3. Add new users with the "+ Add User" button
4. Edit existing users by clicking "Edit"
5. Delete users by clicking "Delete"

### Changing Passwords

1. Login as admin
2. Go to User Management
3. Click "Edit" on the user
4. Enter new password
5. Click "Save"

### Logout

Click the "Logout" button in the sidebar or navigate to any protected page after session expires.

## Security Features

- **Password Hashing:** All passwords are hashed using SHA-256
- **Session Management:** Flask sessions with secure secret key
- **Protected Routes:** All dashboard routes require authentication
- **Role Verification:** Admin-only routes check user role
- **Auto-redirect:** Unauthenticated users redirected to login

## File Structure

```
├── auth.py                    # Authentication module
├── dashboard.py               # Updated with auth integration
├── users.json                 # User database (auto-created)
├── templates/
│   ├── login.html            # Animated login page
│   ├── users.html            # User management page
│   └── dashboard.html        # Updated with user info
```

## API Endpoints

### Public Endpoints
- `GET /login` - Login page
- `POST /api/login` - Login authentication

### Protected Endpoints (Login Required)
- `GET /` - Dashboard
- `GET /fetch` - Fetch logs page
- `GET /fetch-s3` - Fetch S3 logs page
- `GET /live-monitor` - Live monitoring
- `POST /api/logout` - Logout
- `GET /api/current-user` - Get current user info
- All other dashboard API endpoints

### Admin-Only Endpoints
- `GET /users` - User management page
- `GET /api/users` - Get all users
- `POST /api/users/add` - Add new user
- `POST /api/users/update` - Update user
- `POST /api/users/delete` - Delete user

## Customization

### Change Secret Key

Edit `dashboard.py`:
```python
app.secret_key = 'your-custom-secret-key-here'
```

### Add More Roles

Edit `auth.py` to add custom role decorators:
```python
def custom_role_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        if session['user']['role'] not in ['admin', 'custom_role']:
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)
    return decorated
```

### Customize Login Page

Edit `templates/login.html` to change:
- Colors and gradients
- Animation effects
- Logo and branding
- Background animations

## Troubleshooting

### Can't Login
- Check username and password
- Ensure `users.json` exists
- Check console for errors

### Session Expires Too Quickly
Add to `dashboard.py`:
```python
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=24)
```

### Forgot Admin Password
Delete `users.json` and restart the application to recreate default users.

## Security Best Practices

1. **Change Default Passwords** immediately after first login
2. **Use Strong Passwords** for all accounts
3. **Change Secret Key** in production
4. **Use HTTPS** in production environments
5. **Regular Backups** of `users.json`
6. **Monitor Access Logs** for suspicious activity

## Future Enhancements

- Password reset functionality
- Email verification
- Two-factor authentication
- Password complexity requirements
- Account lockout after failed attempts
- Audit logging
- LDAP/Active Directory integration

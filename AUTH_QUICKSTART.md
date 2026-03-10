# Quick Start - Authentication System

## 🚀 Getting Started in 3 Steps

### Step 1: Start the Dashboard
```bash
python dashboard.py
```

### Step 2: Open Browser
Navigate to: **http://localhost:5000**

### Step 3: Login
Use default credentials:
- **Admin:** `admin` / `admin123`
- **User:** `user` / `user123`

---

## 🎨 Features

### ✨ Animated Login Page
- Modern gradient design
- Smooth animations
- Responsive layout
- Floating bubble background

### 👥 User Management (Admin Only)
- Create new users
- Edit existing users
- Delete users
- Assign roles (Admin/User)

### 🔐 Role-Based Access
- **Admin:** Full access + user management
- **User:** Dashboard and reports only

---

## 📋 Common Tasks

### Change Your Password (Admin)
1. Click "User Management" in sidebar
2. Click "Edit" on your username
3. Enter new password
4. Click "Save"

### Add New User (Admin)
1. Go to User Management
2. Click "+ Add User"
3. Fill in details:
   - Username
   - Email
   - Password
   - Role (Admin/User)
4. Click "Save"

### Logout
Click "Logout" button in the sidebar

---

## 🔑 Default Accounts

| Username | Password | Role | Access |
|----------|----------|------|--------|
| admin | admin123 | Admin | Full access + user management |
| user | user123 | User | Dashboard and reports only |

⚠️ **Important:** Change default passwords immediately!

---

## 🛡️ Security Tips

1. ✅ Change default passwords on first login
2. ✅ Use strong passwords (8+ characters, mixed case, numbers)
3. ✅ Don't share credentials
4. ✅ Logout when done
5. ✅ Regular password updates

---

## 🎯 Quick Reference

### Login Page
- URL: `http://localhost:5000/login`
- Auto-redirects if not logged in

### Dashboard
- URL: `http://localhost:5000/`
- Shows user info in sidebar
- Admin sees "User Management" option

### User Management (Admin Only)
- URL: `http://localhost:5000/users`
- Manage all users
- Create, edit, delete accounts

---

## 🐛 Troubleshooting

### Can't Login?
- Check username/password spelling
- Try default credentials
- Check console for errors

### Forgot Password?
- Admin can reset any user's password
- Delete `users.json` to reset all (creates defaults)

### Session Expired?
- Just login again
- Sessions last for browser session

---

## 📞 Need Help?

Check the full documentation: `AUTHENTICATION.md`

---

**Enjoy your secure CloudWatch Log Analyzer! 🎉**

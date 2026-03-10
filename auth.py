import json
import os
import hashlib
from functools import wraps
from flask import session, redirect, url_for, jsonify

USERS_FILE = 'users.json'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def init_default_users():
    users = load_users()
    if not users:
        users = {
            'admin': {
                'password': hash_password('admin123'),
                'role': 'admin',
                'email': 'admin@example.com'
            },
            'user': {
                'password': hash_password('user123'),
                'role': 'user',
                'email': 'user@example.com'
            }
        }
        save_users(users)
    return users

def authenticate(username, password):
    users = load_users()
    if username in users:
        if users[username]['password'] == hash_password(password):
            return {'username': username, 'role': users[username]['role'], 'email': users[username]['email']}
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        if session['user']['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

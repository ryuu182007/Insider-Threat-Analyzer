"""Insider Threat Detection System - Main Application Entry Point."""

import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, redirect, url_for, session
from backend.routes.api import api_bp
from backend.services.data_service import verify_login, reset_password
from database.init_db import init_database

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
# Secret key for session management (change this in production)
app.secret_key = 'itds-secret-key-2024'

# Register API blueprint
app.register_blueprint(api_bp, url_prefix='/api')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    error = None
    success = None
    username_val = ''
    if request.method == 'POST':
        username_val = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user = verify_login(username_val, password)
        if user:
            session['analyst'] = username_val
            session['is_admin'] = user['is_admin']
            session['user_id'] = user['id']
            if user['is_admin'] == 1:
                return redirect(url_for('index'))
            else:
                return redirect(url_for('member_dashboard'))
        else:
            error = 'Invalid username or password. Please try again.'
    return render_template('login.html', error=error, success=success, username_val=username_val)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    """Forgot / Change Password endpoint."""
    error = None
    success = None
    if request.method == 'POST':
        identity = request.form.get('identity', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not identity or not new_password:
            error = 'Please provide your username/email and a new password.'
        elif new_password != confirm_password:
            error = 'Passwords do not match.'
        else:
            ok, msg = reset_password(identity, new_password)
            if ok:
                success = msg + ' You can now sign in with your new password.'
            else:
                error = msg
    return render_template('login.html', error=error, success=success, forgot_mode=True)


@app.route('/logout')
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Main dashboard – requires admin login."""
    if 'analyst' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin') != 1:
        return redirect(url_for('member_dashboard'))
    return render_template('index.html')


@app.route('/member')
def member_dashboard():
    """Member dashboard – requires login."""
    if 'analyst' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin') == 1:
        return redirect(url_for('index'))
    return render_template('member.html', username=session['analyst'])


def main():
    init_database()
    print('\n  Insider Threat Detection System')
    print('  ================================')
    print('  Server running at http://127.0.0.1:5000')
    print('  Press Ctrl+C to stop\n')
    app.run(debug=True, host='127.0.0.1', port=5000)


if __name__ == '__main__':
    main()

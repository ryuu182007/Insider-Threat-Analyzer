"""ThreatSim Insider Threat Detection System - Main Application Entry Point."""

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
# Secret key for session management
app.secret_key = 'threatsim-cherry-red-secret-key-2026'

# Register API blueprint
app.register_blueprint(api_bp, url_prefix='/api')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Sign-in page with dark cherry-red aesthetic and realistic security validation."""
    # If already logged in, redirect based on role
    if 'analyst' in session and 'user_id' in session:
        if session.get('is_admin') == 1:
            return redirect(url_for('index'))
        else:
            return redirect(url_for('member_dashboard'))

    error = None
    success = None
    username_val = ''

    if request.method == 'POST':
        username_val = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember_me = bool(request.form.get('remember_me'))

        if not username_val or not password:
            error = 'Please enter both your username and password.'
        else:
            user = verify_login(username_val, password)
            if user:
                if user.get('is_disabled'):
                    error = 'This account has been disabled by a security administrator.'
                else:
                    session.permanent = remember_me
                    session['analyst'] = user['username']
                    session['user_id'] = user['id']
                    session['full_name'] = user['full_name']
                    session['emp_id'] = user.get('emp_id') or f"EMP-{user['id']}"
                    session['is_admin'] = user['is_admin']
                    session['role'] = user['role']
                    session['department'] = user['department']

                    if user['is_admin'] == 1:
                        return redirect(url_for('index'))
                    else:
                        return redirect(url_for('member_dashboard'))
            else:
                error = 'Invalid credentials. Please verify your username and password.'

    return render_template('login.html', error=error, success=success, username_val=username_val)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    """Secure password recovery endpoint."""
    error = None
    success = None
    if request.method == 'POST':
        identity = request.form.get('identity', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not identity or not new_password:
            error = 'Please provide your account username or email, and specify a new password.'
        elif len(new_password) < 8:
            error = 'Password must meet complexity requirements (minimum 8 characters).'
        elif new_password != confirm_password:
            error = 'The password confirmation does not match.'
        else:
            ok, msg = reset_password(identity, new_password)
            if ok:
                success = msg + ' You may now sign in using your updated credentials.'
            else:
                error = msg

    return render_template('login.html', error=error, success=success, forgot_mode=True)


@app.route('/logout')
def logout():
    """Clear session and return to authentication page."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Main administrative ThreatSim dashboard – requires admin role."""
    if 'analyst' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin') != 1:
        return redirect(url_for('member_dashboard'))
    return render_template('index.html')


@app.route('/member')
def member_dashboard():
    """Employee personal security portal – strictly scoped to individual employee."""
    if 'analyst' not in session or 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('is_admin') == 1:
        return redirect(url_for('index'))
    return render_template(
        'member.html',
        username=session['analyst'],
        full_name=session.get('full_name', session['analyst']),
        emp_id=session.get('emp_id', 'EMP'),
        role=session.get('role', 'Employee'),
        department=session.get('department', 'General')
    )


def main():
    init_database()
    print('\n  ThreatSim Insider Threat Detection System')
    print('  =========================================')
    print('  Server running at http://127.0.0.1:5000')
    print('  Default Admin Login: ryuu / ryuu12')
    print('  Default Employee Login: aryan / aryan07')
    print('  Press Ctrl+C to stop\n')
    app.run(debug=True, host='127.0.0.1', port=5000)


if __name__ == '__main__':
    main()

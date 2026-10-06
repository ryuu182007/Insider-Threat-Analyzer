"""ThreatSim Insider Threat Detection System - Main Application Entry Point."""

import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, redirect, request
from backend import config
from backend.routes.api import api_bp
from backend.services.data_service import reset_password
from backend.services import auth_service
from database.init_db import init_database

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Authentication does NOT use Flask's shared cookie session any more.
# Each browser tab holds its own server-side session token (see auth_service),
# which is what lets several users be signed in side by side.

app.register_blueprint(api_bp, url_prefix='/api')


@app.after_request
def _page_headers(resp):
    # Page shells never contain user data, but don't let a stale shell be reused after sign-out.
    if resp.mimetype == 'text/html':
        resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/login')
def login():
    """Sign-in page with separate Employee and Admin sections.
    Sign-in itself is performed by POST /api/auth/login (see static/js/auth.js)."""
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    """Password recovery for employee accounts (the fixed admin account has no recovery)."""
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
    """Signing out is done client-side (clears this tab's token and calls /api/auth/logout)."""
    return render_template('logout.html')


@app.route('/')
def index():
    """Admin dashboard shell. The page verifies this tab's token before showing anything."""
    return render_template('index.html')


@app.route('/member')
def member_dashboard():
    """Employee portal shell. The page verifies this tab's token before showing anything."""
    return render_template('member.html')


def main():
    init_database()
    auth_service.init_session_table()
    print('\n  ThreatSim Insider Threat Detection System')
    print('  =========================================')
    print('  Server running at http://127.0.0.1:5000')
    print('  Admin sign-in:    use the "Admin" tab')
    print('  Employee sign-in: use the "Employee" tab')
    print('  Press Ctrl+C to stop\n')
    # threaded=True so several tabs/browsers are served concurrently
    app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)


if __name__ == '__main__':
    main()

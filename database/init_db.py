"""Database initialization and sample data seeding."""

import sqlite3
import os
import json
from datetime import datetime, timedelta
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')


def create_tables(conn):
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            risk_score INTEGER DEFAULT 0,
            last_activity TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            device TEXT,
            timestamp TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'normal',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            incident_type TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            detected_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')


def seed_users():
    return [
        ('rkumar', 'Rahul Kumar', 'Engineering', 'Developer', 'rkumar@corp.local', 'active', 12, '2026-08-17 14:30:00', None, 0),
        ('ppatel', 'Priya Patel', 'Finance', 'Analyst', 'ppatel@corp.local', 'active', 45, '2026-08-17 13:15:00', None, 0),
        ('asharma', 'Amit Sharma', 'HR', 'Manager', 'asharma@corp.local', 'active', 8, '2026-08-17 11:00:00', None, 0),
        ('ssingh', 'Suresh Singh', 'Engineering', 'Senior Developer', 'ssingh@corp.local', 'active', 72, '2026-08-17 22:45:00', None, 0),
        ('nreddy', 'Neha Reddy', 'IT', 'Sysadmin', 'nreddy@corp.local', 'active', 55, '2026-08-17 09:30:00', None, 0),
        ('mmishra', 'Manish Mishra', 'Marketing', 'Coordinator', 'mmishra@corp.local', 'active', 5, '2026-08-16 16:00:00', None, 0),
        ('agupta', 'Aarti Gupta', 'Finance', 'Accountant', 'agupta@corp.local', 'active', 68, '2026-08-17 03:20:00', None, 0),
        ('rdas', 'Rohan Das', 'Engineering', 'DevOps', 'rdas@corp.local', 'active', 22, '2026-08-17 10:45:00', None, 0),
        ('vjain', 'Vikas Jain', 'Legal', 'Counsel', 'vjain@corp.local', 'active', 15, '2026-08-15 14:00:00', None, 0),
        ('kjoshi', 'Kavita Joshi', 'IT', 'Security Analyst', 'kjoshi@corp.local', 'active', 10, '2026-08-17 15:00:00', None, 0),
        ('ryuu', 'Admin Ryuu', 'Admin', 'Administrator', 'ryuu@corp.local', 'active', 0, '2026-08-17 14:30:00', 'ryuu07', 1),
        ('aryan', 'Aryan', 'Engineering', 'Member', 'aryan@corp.local', 'active', 0, '2026-08-17 14:30:00', 'aryan07', 0),
        ('swara', 'Swara', 'HR', 'Member', 'swara@corp.local', 'active', 0, '2026-08-17 14:30:00', 'swara07', 0)
    ]


def generate_activities(user_ids):
    """Generate realistic activity log entries."""
    activities = []
    activity_templates = [
        ('login', 'User logged in successfully', '10.0.1.{n}', 'WS-{n:03d}', 0, 'normal'),
        ('logout', 'User logged out', '10.0.1.{n}', 'WS-{n:03d}', 0, 'normal'),
        ('file_access', 'Accessed project documentation', '10.0.1.{n}', 'WS-{n:03d}', 5, 'normal'),
        ('email_sent', 'Sent email to team distribution list', '10.0.1.{n}', 'WS-{n:03d}', 3, 'normal'),
        ('print_document', 'Printed quarterly report', '10.0.1.{n}', 'WS-{n:03d}', 5, 'normal'),
        ('failed_login', 'Failed login attempt - incorrect password', '192.168.{n}.{m}', 'WS-{n:03d}', 25, 'suspicious'),
        ('after_hours_login', 'Login detected outside business hours', '10.0.1.{n}', 'WS-{n:03d}', 30, 'suspicious'),
        ('unusual_ip_login', 'Login from unrecognized IP address', '203.45.{n}.{m}', 'WS-{n:03d}', 35, 'suspicious'),
        ('sensitive_file_access', 'Accessed confidential financial records', '10.0.1.{n}', 'WS-{n:03d}', 40, 'suspicious'),
        ('sensitive_file_download', 'Downloaded sensitive HR personnel file', '10.0.1.{n}', 'WS-{n:03d}', 50, 'suspicious'),
        ('bulk_file_download', 'Downloaded 47 files in 15 minutes', '10.0.1.{n}', 'WS-{n:03d}', 45, 'suspicious'),
        ('usb_device_connected', 'USB storage device connected', '10.0.1.{n}', 'WS-{n:03d}', 35, 'suspicious'),
        ('cross_department_access', 'Accessed resources outside assigned department', '10.0.1.{n}', 'WS-{n:03d}', 30, 'suspicious'),
        ('vpn_connection', 'Connected to corporate VPN', '10.0.1.{n}', 'WS-{n:03d}', 10, 'normal'),
        ('privilege_escalation', 'Attempted to access admin privileges', '10.0.1.{n}', 'WS-{n:03d}', 60, 'critical'),
        ('data_exfiltration_attempt', 'Large data transfer to external destination', '10.0.1.{n}', 'WS-{n:03d}', 75, 'critical'),
    ]

    base_time = datetime.now() - timedelta(days=6)
    for i in range(60):
        user_id = random.choice(user_ids)
        template = random.choice(activity_templates)
        act_type, desc, ip_t, dev_t, risk, status = template
        n = random.randint(1, 50)
        m = random.randint(1, 254)
        day_offset = random.randint(0, 7)
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        ts = (base_time + timedelta(days=day_offset, hours=hour, minutes=minute)).strftime('%Y-%m-%d %H:%M:%S')

        activities.append((
            user_id,
            act_type,
            desc.format(n=n, m=m),
            ip_t.format(n=n, m=m),
            dev_t.format(n=n),
            ts,
            risk,
            status
        ))

    return activities


def seed_incidents(user_ids):
    """Generate sample security incidents."""
    incidents = [
        (4, 'After-Hours Access Detected', 'User logged in at 22:45 from internal network during non-business hours', 'HIGH', 72, 'After-Hours Access', 'Investigating', '2026-08-17 22:45:00', None),
        (7, 'Sensitive File Download', 'Downloaded confidential payroll data outside authorized scope', 'HIGH', 68, 'Data Access Violation', 'Open', '2026-08-17 03:20:00', None),
        (4, 'Data Exfiltration Risk', 'Bulk download of 47 engineering source files detected', 'CRITICAL', 85, 'Data Exfiltration Risk', 'Open', '2026-08-17 23:10:00', None),
        (2, 'Multiple Failed Logins', '5 failed login attempts within 10 minutes from external IP', 'MEDIUM', 45, 'Authentication Anomaly', 'Investigating', '2026-08-16 08:15:00', None),
        (5, 'USB Device Connected', 'External USB storage connected to IT admin workstation', 'MEDIUM', 55, 'Removable Media Alert', 'Open', '2026-08-17 09:30:00', None),
        (3, 'Cross-Department Access', 'HR recruiter accessed engineering repository', 'MEDIUM', 38, 'Unauthorized Access', 'Open', '2026-08-17 08:30:00', None),
        (8, 'Privilege Escalation Attempt', 'Attempt to gain admin privileges on production server', 'CRITICAL', 85, 'Privilege Escalation', 'Investigating', '2026-08-16 14:00:00', None),
        (7, 'Unusual IP Login', 'Login from IP 203.45.12.88 not in whitelist', 'HIGH', 68, 'Network Anomaly', 'Open', '2026-08-15 02:30:00', None),
        (9, 'Repeated Suspicious Actions', 'Multiple sensitive file accesses in short timeframe', 'MEDIUM', 42, 'Suspicious Activity', 'Resolved', '2026-08-10 09:00:00', '2026-08-12 16:00:00'),
        (4, 'Sensitive File Access Pattern', 'Accessed 12 confidential documents in 30 minutes', 'HIGH', 72, 'Data Access Violation', 'Investigating', '2026-08-14 11:00:00', None),
        (2, 'After-Hours Financial Access', 'Accessed financial systems at 01:15 AM', 'HIGH', 45, 'After-Hours Access', 'Open', '2026-08-13 01:15:00', None),
        (5, 'Network Anomaly', 'Connection to unauthorized external server detected', 'HIGH', 55, 'Network Anomaly', 'Resolved', '2026-08-08 18:00:00', '2026-08-09 10:00:00'),
    ]
    return incidents


def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)

    count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if count > 0:
        conn.close()
        print('Database already initialized with data.')
        return

    # Seed users
    users = seed_users()
    conn.executemany('''
        INSERT INTO users (username, full_name, department, role, email, status, risk_score, last_activity, password, is_admin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', users)

    user_ids = [row[0] for row in conn.execute('SELECT id FROM users').fetchall()]

    # Seed activities
    activities = generate_activities(user_ids)
    conn.executemany('''
        INSERT INTO activity_logs (user_id, activity_type, description, ip_address, device, timestamp, risk_score, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', activities)

    # Seed incidents
    incidents = seed_incidents(user_ids[:10]) # Only assign incidents to original 10 users
    conn.executemany('''
        INSERT INTO incidents (user_id, title, description, severity, risk_score, incident_type, status, detected_at, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', incidents)

    # Seed initial tasks for aryan and swara
    # We know aryan is user_id 12, swara is 13 based on insertion order (1 to 10 are employees, 11 is ryuu, 12 is aryan, 13 is swara)
    tasks = [
        (12, 'Review Security Policies', 'Read and acknowledge the new Q3 security policies.', 'Pending'),
        (12, 'Update System Dependencies', 'Update npm dependencies for the frontend app.', 'Pending'),
        (12, 'Share a file', 'Share a file with each other.', 'Pending'),
        (13, 'Onboard New Employees', 'Prepare onboarding documents for next week.', 'Pending'),
        (13, 'Quarterly HR Review', 'Complete the HR review forms.', 'Completed'),
        (13, 'Share a file', 'Share a file with each other.', 'Pending')
    ]
    conn.executemany('''
        INSERT INTO tasks (user_id, title, description, status)
        VALUES (?, ?, ?, ?)
    ''', tasks)

    conn.commit()
    conn.close()
    print(f'Database initialized at {DB_PATH}')
    print(f'  - {len(users)} users')
    print(f'  - {len(activities)} activity logs')
    print(f'  - {len(incidents)} incidents')
    print(f'  - {len(tasks)} tasks')


if __name__ == '__main__':
    init_database()

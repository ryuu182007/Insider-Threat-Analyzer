"""Database migration to ensure emp_id and simulations table exist without altering existing data."""

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')

def run_migration():
    if not os.path.exists(DB_PATH):
        print("Database not found, skipping migration.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Check emp_id
    cur.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if 'emp_id' not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN emp_id TEXT")
        print("Added emp_id column to users table.")

    # Backfill emp_id for existing users
    cur.execute("SELECT id, username FROM users WHERE emp_id IS NULL OR emp_id = ''")
    rows = cur.fetchall()
    for row in rows:
        uid, uname = row
        emp_code = f"EMP-{1000 + uid}"
        cur.execute("UPDATE users SET emp_id = ? WHERE id = ?", (emp_code, uid))
    if rows:
        print(f"Updated {len(rows)} users with emp_id.")

    # Create simulations table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS simulations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scenario_type TEXT NOT NULL,
            scenario_name TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT,
            alert_created INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    print("Simulations table verified.")

    # Seed sample simulations if empty
    cur.execute("SELECT COUNT(*) FROM simulations")
    sim_count = cur.fetchone()[0]
    if sim_count == 0:
        sample_sims = [
            (4, 'data_exfiltration', 'Data Exfiltration', 85, 'CRITICAL', 'Bulk archive creation, anomalous outbound transfer attempt', 1, '2026-08-16 14:20:00'),
            (2, 'after_hours_access', 'After-Hours Access', 45, 'MEDIUM', 'Login detected at 02:15 AM outside normal shift window', 1, '2026-08-16 16:45:00'),
            (7, 'credential_misuse', 'Credential Misuse', 68, 'HIGH', '5 failed authentication attempts followed by unknown IP login', 1, '2026-08-17 09:10:00'),
            (8, 'privilege_abuse', 'Privilege Abuse', 82, 'CRITICAL', 'Direct attempt to elevate to root/admin on core database node', 1, '2026-08-17 11:30:00'),
            (5, 'unauthorized_usb', 'Unauthorized USB Activity', 55, 'MEDIUM', 'Removable flash storage device connected to engineering terminal', 1, '2026-08-17 13:00:00'),
            (1, 'normal_behaviour', 'Normal Behaviour', 12, 'LOW', 'Routine file browse and standard departmental communication', 0, '2026-08-17 15:20:00'),
            (3, 'normal_behaviour', 'Normal Behaviour', 8, 'LOW', 'Standard HR portal access and routine timesheet review', 0, '2026-08-17 16:00:00')
        ]
        cur.executemany("""
            INSERT INTO simulations (user_id, scenario_type, scenario_name, risk_score, risk_level, indicators, alert_created, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, sample_sims)
        print(f"Seeded {len(sample_sims)} initial simulations.")

    conn.commit()
    conn.close()
    print("Migration finished successfully.")

if __name__ == '__main__':
    run_migration()

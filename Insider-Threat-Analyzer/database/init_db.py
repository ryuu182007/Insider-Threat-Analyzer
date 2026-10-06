"""Database initialization and sample data seeding."""

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'database', 'insider_threat.db')


def create_tables(conn):
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id TEXT,
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


def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)
    conn.close()

    try:
        from database.migrate import run_migration
        run_migration()
    except Exception as e:
        print('Migration check note:', e)
    # No sample users, activities or incidents are seeded any more.
    print(f'Database ready at {DB_PATH}')


if __name__ == '__main__':
    init_database()

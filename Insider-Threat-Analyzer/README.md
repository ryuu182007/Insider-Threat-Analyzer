# Insider Threat Detection System

A full-stack web application for monitoring user activity within an organization and detecting potentially suspicious insider behavior. Built as a college cybersecurity project using Python Flask, SQLite, and vanilla JavaScript.

## Project Overview

This system simulates a Security Operations Center (SOC) dashboard where security analysts can monitor employee activity, detect rule-based threat indicators, assign risk scores, and manage security incidents. It uses a simple, explainable rule-based detection engine rather than machine learning.

## Features

- **Dashboard** — Summary statistics, threat overview, and recent activity feed
- **User Monitoring** — View all monitored users with risk scores, search and filter capabilities
- **Activity Logs** — Searchable table of all user activities with risk indicators
- **Incident Management** — Create, view, and update security incidents
- **Threat Analysis** — Charts showing risk distribution, incident severity, and activity trends
- **Rule-Based Detection** — Transparent threat detection rules (failed logins, after-hours access, bulk downloads, etc.)

## Technology Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript     |
| Charts   | Chart.js                            |
| Backend  | Python 3, Flask                     |
| Database | SQLite (local file)                 |

## Project Structure

```
insider-threat-detection/
├── app.py                  # Flask application entry point
├── requirements.txt        # Python dependencies
├── README.md
├── database/
│   ├── insider_threat.db   # SQLite database (auto-created)
│   └── init_db.py          # Database schema and sample data
├── backend/
│   ├── routes/
│   │   └── api.py          # REST API endpoints
│   ├── services/
│   │   ├── data_service.py # Data access layer
│   │   └── threat_detector.py  # Rule-based detection engine
│   └── utils/
│       └── db.py           # Database connection helper
├── templates/
│   └── index.html          # Main dashboard page
├── static/
│   ├── css/style.css       # Dark glassmorphism styling
│   └── js/app.js           # Frontend application logic
└── data/
    └── sample_logs.json    # Reference sample log data
```

## Database Structure

### users
| Column        | Type    | Description                    |
|---------------|---------|--------------------------------|
| id            | INTEGER | Primary key                    |
| username      | TEXT    | Unique login name              |
| full_name     | TEXT    | Display name                   |
| department    | TEXT    | Organizational unit            |
| role          | TEXT    | Job role                       |
| email         | TEXT    | Email address                  |
| status        | TEXT    | active / inactive              |
| risk_score    | INTEGER | Current risk score (0-100)     |
| last_activity | TEXT    | Last recorded activity time    |

### activity_logs
| Column        | Type    | Description                    |
|---------------|---------|--------------------------------|
| id            | INTEGER | Primary key                    |
| user_id       | INTEGER | Foreign key to users           |
| activity_type | TEXT    | Type of activity               |
| description   | TEXT    | Human-readable description     |
| ip_address    | TEXT    | Source IP address              |
| device        | TEXT    | Device identifier              |
| timestamp     | TEXT    | When the activity occurred     |
| risk_score    | INTEGER | Risk score for this activity   |
| status        | TEXT    | normal / suspicious / critical |

### incidents
| Column        | Type    | Description                    |
|---------------|---------|--------------------------------|
| id            | INTEGER | Primary key                    |
| user_id       | INTEGER | Foreign key to users           |
| title         | TEXT    | Incident title                 |
| description   | TEXT    | Detailed description           |
| severity      | TEXT    | LOW / MEDIUM / HIGH / CRITICAL |
| risk_score    | INTEGER | Associated risk score          |
| incident_type | TEXT    | Category of incident           |
| status        | TEXT    | Open / Investigating / Resolved|
| detected_at   | TEXT    | Detection timestamp            |
| resolved_at   | TEXT    | Resolution timestamp (nullable)|

## Threat Detection

The detection engine (`backend/services/threat_detector.py`) uses predefined rules:

| Rule                          | Base Risk Score |
|-------------------------------|-----------------|
| Failed login attempts (3+)    | 25 (+25 bonus)  |
| After-hours login             | 30              |
| Unusual IP login              | 35              |
| Sensitive file access         | 40              |
| Bulk file download            | 45              |
| Sensitive file download       | 50              |
| USB device connected          | 35              |
| Cross-department access       | 30              |
| Privilege escalation          | 60              |
| Data exfiltration attempt     | 75              |

**Risk Levels:**
- Low: 0–29
- Medium: 30–59
- High: 60–79
- Critical: 80–100

Incidents are automatically flagged when an activity's risk score reaches 40 or above.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Setup

```bash
# Clone or navigate to the project directory
cd insider-threat-detection

# Install dependencies
pip install -r requirements.txt

# Initialize the database (also runs automatically on first start)
python database/init_db.py

# Start the Flask server
python app.py
```

Open your browser and navigate to: **http://127.0.0.1:5000**

The database file will be created automatically at `database/insider_threat.db` with 15 users, 60 activity logs, and 12 incidents.

## API Endpoints

| Method | Endpoint                  | Description                |
|--------|---------------------------|----------------------------|
| GET    | `/api/dashboard`          | Dashboard summary stats    |
| GET    | `/api/users`              | List all users             |
| GET    | `/api/users/<id>`         | User detail with activity  |
| GET    | `/api/activity`           | Activity logs              |
| GET    | `/api/incidents`          | List incidents             |
| GET    | `/api/incidents/<id>`     | Incident detail            |
| POST   | `/api/incidents`          | Create new incident        |
| PUT    | `/api/incidents/<id>`     | Update incident status     |
| GET    | `/api/threat-analysis`    | Threat analysis data       |

### Query Parameters

- `/api/users?search=john&risk=high`
- `/api/activity?search=login&status=suspicious&limit=50`
- `/api/incidents?severity=HIGH&status=Open`

## Future Improvements

- User authentication and role-based access control
- Real-time activity ingestion via log file parsing
- Email/Slack alerting for critical incidents
- Export incident reports to PDF
- Configurable detection rules via the Settings page
- Activity timeline visualization per user
- Integration with Active Directory / LDAP
- Automated incident response workflows

## License

This project is for educational purposes only. It does not provide enterprise-grade security and should not be used in production environments.

## Sign-in & Sessions

- **Two sign-in sections** on `/login`: **Employee** (credentials stored in the database) and **Admin** (fixed, case-sensitive account `Ryuu` / `Ryuu12`, defined in `backend/config.py`; it is not a database row, so it cannot be edited, disabled or re-created from the dashboard).
- **Per-tab sessions**: each login gets its own server-side token kept in that tab's `sessionStorage` and sent as `Authorization: Bearer ...`. Refreshing keeps you signed in; different tabs and browsers (Chrome, Edge, ...) can hold different users at the same time without overlap.
- Every request re-reads the user from the database, so a disabled employee loses access immediately.
- **Admins can add and remove employees** (Add Employee button and a Remove button per row; removing deletes the account and its records and ends any live session). New accounts are always employees; the admin account is fixed and cannot be created, edited or removed.
- Employee record fields are stored separately: Name (`full_name`), ID (`emp_id`), Username, Password (hashed), Department, Role. Username and ID are unique.
- Run the checks with `python -m backend.test_suite`.

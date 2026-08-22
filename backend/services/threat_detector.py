"""
Rule-based insider threat detection engine.

Evaluates activity logs against predefined security rules and
calculates risk scores. Designed to be simple and explainable
for academic demonstration purposes.
"""

from datetime import datetime, timedelta

# Risk level thresholds
RISK_LOW = (0, 29)
RISK_MEDIUM = (30, 59)
RISK_HIGH = (60, 79)
RISK_CRITICAL = (80, 100)

# Suspicious activity types and their base risk scores
ACTIVITY_RISK = {
    'failed_login': 25,
    'after_hours_login': 30,
    'unusual_ip_login': 35,
    'sensitive_file_access': 40,
    'sensitive_file_download': 50,
    'bulk_file_download': 45,
    'usb_device_connected': 35,
    'cross_department_access': 30,
    'privilege_escalation': 60,
    'data_exfiltration_attempt': 75,
    'repeated_suspicious_action': 40,
    'abnormal_login_location': 35,
    'file_access': 5,
    'login': 0,
    'logout': 0,
    'email_sent': 3,
    'print_document': 5,
    'vpn_connection': 10,
}


def get_risk_level(score):
    """Return risk level label based on numeric score."""
    if score >= RISK_CRITICAL[0]:
        return 'CRITICAL'
    elif score >= RISK_HIGH[0]:
        return 'HIGH'
    elif score >= RISK_MEDIUM[0]:
        return 'MEDIUM'
    return 'LOW'


def calculate_activity_risk(activity_type, context=None):
    """
    Calculate risk score for a single activity.
    Context can include additional flags like hour, ip_changed, etc.
    """
    base_score = ACTIVITY_RISK.get(activity_type, 10)
    score = base_score

    if context:
        if context.get('hour') and (context['hour'] < 6 or context['hour'] > 22):
            score += 15
        if context.get('ip_changed'):
            score += 20
        if context.get('failed_attempts', 0) >= 3:
            score += 25
        if context.get('download_count', 0) >= 10:
            score += 20
        if context.get('cross_department'):
            score += 15
        if context.get('repeated_within_hour', 0) >= 3:
            score += 20

    return min(score, 100)


def analyze_user_activities(activities):
    """
    Analyze a list of user activities and return aggregated risk assessment.
    activities: list of dicts with activity_type, timestamp, risk_score, etc.
    """
    if not activities:
        return {'risk_score': 0, 'risk_level': 'LOW', 'threats': []}

    total_score = 0
    threats = []
    now = datetime.now()

    # Count activity types in last 24 hours
    recent = []
    for act in activities:
        ts = act.get('timestamp', '')
        try:
            act_time = datetime.fromisoformat(ts.replace('Z', ''))
            if now - act_time <= timedelta(hours=24):
                recent.append(act)
        except (ValueError, TypeError):
            recent.append(act)

    failed_logins = sum(1 for a in recent if a.get('activity_type') == 'failed_login')
    if failed_logins >= 3:
        threats.append({
            'type': 'Multiple Failed Logins',
            'description': f'{failed_logins} failed login attempts in last 24 hours',
            'severity': 'HIGH'
        })
        total_score += 30

    sensitive_access = sum(1 for a in recent
                          if a.get('activity_type') in ('sensitive_file_access', 'sensitive_file_download'))
    if sensitive_access >= 2:
        threats.append({
            'type': 'Sensitive File Access',
            'description': f'{sensitive_access} sensitive file operations detected',
            'severity': 'HIGH'
        })
        total_score += 25

    after_hours = sum(1 for a in recent if a.get('activity_type') == 'after_hours_login')
    if after_hours >= 1:
        threats.append({
            'type': 'After-Hours Activity',
            'description': 'Login detected outside normal business hours',
            'severity': 'MEDIUM'
        })
        total_score += 20

    usb_events = sum(1 for a in recent if a.get('activity_type') == 'usb_device_connected')
    if usb_events >= 1:
        threats.append({
            'type': 'USB Device Activity',
            'description': 'External storage device connected to workstation',
            'severity': 'MEDIUM'
        })
        total_score += 15

    bulk_downloads = sum(1 for a in recent if a.get('activity_type') == 'bulk_file_download')
    if bulk_downloads >= 1:
        threats.append({
            'type': 'Bulk Data Download',
            'description': 'Unusually large number of file downloads detected',
            'severity': 'HIGH'
        })
        total_score += 25

    unusual_ip = sum(1 for a in recent if a.get('activity_type') == 'unusual_ip_login')
    if unusual_ip >= 1:
        threats.append({
            'type': 'Unusual IP Login',
            'description': 'Login from unrecognized IP address',
            'severity': 'MEDIUM'
        })
        total_score += 20

    # Factor in individual activity risk scores
    avg_activity_risk = sum(a.get('risk_score', 0) for a in recent) / max(len(recent), 1)
    total_score = int((total_score * 0.6) + (avg_activity_risk * 0.4))
    total_score = min(total_score, 100)

    return {
        'risk_score': total_score,
        'risk_level': get_risk_level(total_score),
        'threats': threats
    }


def evaluate_activity(activity_type, user_data=None, recent_activities=None):
    """
    Evaluate a new activity and determine if an incident should be created.
    Returns dict with risk_score, risk_level, should_create_incident, incident_data.
    """
    context = {}
    if recent_activities:
        failed = sum(1 for a in recent_activities if a.get('activity_type') == 'failed_login')
        context['failed_attempts'] = failed
        context['repeated_within_hour'] = len(recent_activities)

    score = calculate_activity_risk(activity_type, context)
    level = get_risk_level(score)

    result = {
        'risk_score': score,
        'risk_level': level,
        'should_create_incident': score >= 40,
        'incident_data': None
    }

    if result['should_create_incident']:
        incident_types = {
            'failed_login': 'Authentication Anomaly',
            'after_hours_login': 'After-Hours Access',
            'unusual_ip_login': 'Network Anomaly',
            'sensitive_file_download': 'Data Access Violation',
            'bulk_file_download': 'Data Exfiltration Risk',
            'usb_device_connected': 'Removable Media Alert',
            'cross_department_access': 'Unauthorized Access',
            'privilege_escalation': 'Privilege Escalation',
            'data_exfiltration_attempt': 'Data Exfiltration Attempt',
        }
        result['incident_data'] = {
            'incident_type': incident_types.get(activity_type, 'Suspicious Activity'),
            'severity': level,
            'risk_score': score,
            'title': f'{incident_types.get(activity_type, "Suspicious Activity")} Detected',
            'description': f'Rule-based detection triggered for activity: {activity_type.replace("_", " ").title()}'
        }

    return result

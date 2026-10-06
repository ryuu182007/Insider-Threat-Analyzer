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


SIMULATION_SCENARIOS = {
    'normal_behaviour': {
        'key': 'normal_behaviour',
        'name': 'Normal Behaviour',
        'threat_vector': 'Baseline Operations',
        'description': 'Standard routine operations during business hours with expected departmental resource usage.',
        'base_score': 12,
        'severity': 'LOW',
        'indicators': [
            'Authentication recorded within standard operational hours (09:00 - 18:00)',
            'Resource queries strictly confined to assigned departmental access boundaries',
            'Zero anomalous outbound bandwidth or unapproved device connections'
        ],
        'recommended_action': 'No containment required — employee operating within standard behavioral profile.',
        'activities': [
            {'type': 'login', 'desc': 'Standard workstation single sign-on authentication', 'risk': 0, 'status': 'normal'},
            {'type': 'file_access', 'desc': 'Accessed shared departmental project documentation', 'risk': 5, 'status': 'normal'}
        ]
    },
    'after_hours_access': {
        'key': 'after_hours_access',
        'name': 'After-Hours Access',
        'threat_vector': 'Temporal Anomaly',
        'description': 'Authentication and internal repository access detected outside standard working hours (02:30 AM).',
        'base_score': 48,
        'severity': 'MEDIUM',
        'indicators': [
            'Access recorded outside operational window (22:00 - 06:00)',
            'Remote VPN session initiated without scheduled shift authorization',
            'Multiple repository queries executed during off-peak period'
        ],
        'recommended_action': 'Review employee activity timestamps and check on-call schedule authorization.',
        'activities': [
            {'type': 'after_hours_login', 'desc': 'Remote login detected at 02:38 AM via corporate VPN', 'risk': 35, 'status': 'suspicious'},
            {'type': 'file_access', 'desc': 'Queried customer records during off-shift hours', 'risk': 25, 'status': 'suspicious'}
        ]
    },
    'data_exfiltration': {
        'key': 'data_exfiltration',
        'name': 'Data Exfiltration',
        'threat_vector': 'Data Loss Prevention (DLP)',
        'description': 'Mass archive staging and outbound transfer of proprietary documentation to an unapproved endpoint.',
        'base_score': 88,
        'severity': 'CRITICAL',
        'indicators': [
            'Unusually high download volume (>85 sensitive project files in 10 minutes)',
            'Encrypted compressed archive staged in staging directory',
            'Outbound data transfer attempt flagged by perimeter inspection'
        ],
        'recommended_action': 'Check accessed files, isolate host workstation, and escalate to SOC Commander.',
        'activities': [
            {'type': 'bulk_file_download', 'desc': 'Bulk download of 85 confidential project files in 10 minutes', 'risk': 55, 'status': 'critical'},
            {'type': 'data_exfiltration_attempt', 'desc': 'Outbound data transfer to unapproved destination detected', 'risk': 85, 'status': 'critical'}
        ]
    },
    'privilege_abuse': {
        'key': 'privilege_abuse',
        'name': 'Privilege Abuse',
        'threat_vector': 'Privilege Escalation',
        'description': 'Attempted unauthorized elevation to administrative rights and modification of security configurations.',
        'base_score': 74,
        'severity': 'HIGH',
        'indicators': [
            'Attempted sudo / administrative elevation command without authorization ticket',
            'Direct inspection of local credential cache and IAM configuration',
            'Cross-departmental administrative console access request'
        ],
        'recommended_action': 'Revoke active administrative privileges and verify authorization credentials.',
        'activities': [
            {'type': 'privilege_escalation', 'desc': 'Unauthorized administrative credential elevation attempt', 'risk': 65, 'status': 'critical'},
            {'type': 'sensitive_file_access', 'desc': 'Attempted access to root IAM configuration file', 'risk': 40, 'status': 'suspicious'}
        ]
    },
    'credential_misuse': {
        'key': 'credential_misuse',
        'name': 'Credential Misuse',
        'threat_vector': 'Authentication Anomaly',
        'description': 'Multiple failed login attempts followed by sudden successful authentication from an anomalous IP.',
        'base_score': 68,
        'severity': 'HIGH',
        'indicators': [
            '5 rapid failed authentication attempts recorded within 4 minutes',
            'Subsequent login from unrecognized external IP (203.45.12.88)',
            'Behavioral pattern indicates possible credential stuffing or unauthorized session takeover'
        ],
        'recommended_action': 'Force password reset, terminate active sessions, and review logon origin.',
        'activities': [
            {'type': 'failed_login', 'desc': 'Multiple consecutive failed authentication attempts', 'risk': 35, 'status': 'suspicious'},
            {'type': 'unusual_ip_login', 'desc': 'Login authenticated from untrusted IP 203.45.12.88', 'risk': 45, 'status': 'suspicious'}
        ]
    },
    'unauthorized_usb': {
        'key': 'unauthorized_usb',
        'name': 'Unauthorized USB Activity',
        'threat_vector': 'Removable Media Policy',
        'description': 'Physical connection of an unauthorized mass storage peripheral to corporate workstation.',
        'base_score': 58,
        'severity': 'MEDIUM',
        'indicators': [
            'Unregistered USB Mass Storage Device mounted (SanDisk Ultra 64GB)',
            'Endpoint Removable Media Protection policy violation',
            'Direct file copy sequence initiated towards removable drive path'
        ],
        'recommended_action': 'Verify USB device serial ID, quarantine media, and audit transferred file list.',
        'activities': [
            {'type': 'usb_device_connected', 'desc': 'Unregistered USB storage device connected to workstation', 'risk': 40, 'status': 'suspicious'},
            {'type': 'file_access', 'desc': 'Copied 12 internal engineering schematics to external drive', 'risk': 35, 'status': 'suspicious'}
        ]
    },
    'combined_threat': {
        'key': 'combined_threat',
        'name': 'Combined Insider Threat',
        'threat_vector': 'Multi-Vector Attack Sequence',
        'description': 'Coordinated multi-stage insider threat combining off-hours login, privilege escalation, USB mounting, and bulk extraction.',
        'base_score': 95,
        'severity': 'CRITICAL',
        'indicators': [
            'Multi-stage Kill Chain: Off-Hours Ingress -> Privilege Abuse -> Media Mount -> Exfiltration',
            'Connection established at 03:15 AM outside standard window',
            'Root/admin elevation gained without supervisory ticket',
            'Bulk copy of 120 confidential engineering documents to removable mass storage'
        ],
        'recommended_action': 'Immediate Containment: Quarantine subject account, revoke network tokens, initiate forensic review.',
        'activities': [
            {'type': 'after_hours_login', 'desc': 'Off-hours login detected at 03:15 AM via external link', 'risk': 35, 'status': 'suspicious'},
            {'type': 'privilege_escalation', 'desc': 'Elevation to administrator privileges recorded on core server', 'risk': 70, 'status': 'critical'},
            {'type': 'usb_device_connected', 'desc': 'High-capacity external storage SSD mounted to terminal', 'risk': 45, 'status': 'suspicious'},
            {'type': 'data_exfiltration_attempt', 'desc': '120 confidential project archives transferred to removable drive', 'risk': 88, 'status': 'critical'}
        ]
    }
}


def get_simulation_scenarios():
    """Return all available threat simulation scenarios."""
    return list(SIMULATION_SCENARIOS.values())


def simulate_threat(scenario_key, employee):
    """
    Simulate a threat scenario for a specific employee.
    Calculates dynamic risk score, indicators, activities, and alert metadata.
    """
    scenario = SIMULATION_SCENARIOS.get(scenario_key)
    if not scenario:
        raise ValueError(f"Unknown scenario key: {scenario_key}")

    current_emp_risk = employee.get('risk_score', 0) if employee else 0

    # Dynamic calculation based on scenario base score and current baseline
    calculated_score = int(min(100, max(5, (scenario['base_score'] * 0.85) + (current_emp_risk * 0.15))))
    risk_level = get_risk_level(calculated_score)

    alert_title = f"{scenario['name']} Alert — {employee.get('full_name', 'Employee')}"
    alert_description = (
        f"Simulated {scenario['threat_vector']} executed on {employee.get('full_name')} "
        f"({employee.get('emp_id') or employee.get('username')}). "
        f"{scenario['description']}"
    )

    return {
        'scenario_key': scenario['key'],
        'scenario_name': scenario['name'],
        'threat_vector': scenario['threat_vector'],
        'description': scenario['description'],
        'risk_score': calculated_score,
        'risk_level': risk_level,
        'indicators': scenario['indicators'],
        'recommended_action': scenario['recommended_action'],
        'activities': scenario['activities'],
        'alert_data': {
            'title': alert_title,
            'description': alert_description,
            'severity': risk_level,
            'risk_score': calculated_score,
            'incident_type': scenario['threat_vector'],
            'status': 'New'
        }
    }


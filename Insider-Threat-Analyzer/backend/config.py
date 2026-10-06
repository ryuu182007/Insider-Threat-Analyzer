"""Central configuration for authentication and session handling."""

import os

# ---------------------------------------------------------------------------
# Fixed administrator credentials (case-sensitive).
# The admin is NOT stored in the employees table, so it can never be edited,
# disabled, deleted or re-created from the admin dashboard.
# Override with THREATSIM_ADMIN_USER / THREATSIM_ADMIN_PASS if ever needed.
# ---------------------------------------------------------------------------
ADMIN_USERNAME = os.environ.get('THREATSIM_ADMIN_USER', 'Ryuu')
ADMIN_PASSWORD = os.environ.get('THREATSIM_ADMIN_PASS', 'Ryuu12')
ADMIN_DISPLAY_NAME = 'Administrator Ryuu'

# ---------------------------------------------------------------------------
# Session settings
# ---------------------------------------------------------------------------
# A session is dropped after this many seconds WITHOUT any request (sliding).
SESSION_IDLE_TIMEOUT = 8 * 60 * 60
# Hard cap on a session's lifetime regardless of activity.
SESSION_MAX_LIFETIME = 24 * 60 * 60

ROLE_ADMIN = 'admin'
ROLE_EMPLOYEE = 'employee'

"""Dependency-free constants shared by the CLI and the authority."""

NODES = {"node-a": "frontend", "node-b": "billing", "node-c": "secrets"}

# One documented timing range for both detectors (seconds).
MAX_CLOCK_OFFSET = 120      # largest trusted source-clock offset that is corrected, not flagged
MAX_LATENESS = 30           # largest corrected collector delay inside the reorder buffer
MAX_NEGATIVE_SKEW = 1.0     # corrected delay may dip this far below zero (residual offset error)

# Closest MITRE ATT&CK (Enterprise) technique for each alert rule, so an analyst can map an
# alert to the shared vocabulary. This is a labelling aid; the rules do not claim full coverage.
ATTACK_TECHNIQUES = {
    # Main detector over the verified authority log
    "unapproved_privilege_grant": "T1098 Account Manipulation",
    "self_approved_grant": "T1098 Account Manipulation",
    "revoked_credential_use": "T1078 Valid Accounts",
    "unexpected_service_transition": "T1021 Remote Services (TA0008 Lateral Movement)",
    # Toolkit practice-data detector
    "unapproved_role_change": "T1098 Account Manipulation",
    "activity_after_unapproved_role_change": "T1078 Valid Accounts",
    "lateral_movement_sequence": "T1021 Remote Services (TA0008 Lateral Movement)",
    # Grader adapter probing alerts
    "cross_owner_access": "T1078 Valid Accounts",
    "revoked_actor_access": "T1078 Valid Accounts",
    "disabled_actor_access": "T1078 Valid Accounts",
    "malformed_request": "T1190 Exploit Public-Facing Application",
    "request_id_replay": "T1550 Use Alternate Authentication Material",
}

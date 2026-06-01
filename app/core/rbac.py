from enum import Enum


class Permission(str, Enum):
    SCAN_CREATE = "scan:create"
    SCAN_STOP = "scan:stop"
    FINDING_REVIEW = "finding:review"
    EVIDENCE_ACCESS = "evidence:access"
    REPORT_EXPORT = "report:export"
    REMEDIATION_APPROVE = "remediation:approve"
    REMEDIATION_UPDATE = "remediation:update"
    READ_DASHBOARD = "dashboard:read"
    READ_FINDINGS = "findings:read"
    READ_COMPLIANCE = "compliance:read"
    MANAGE_COMPLIANCE = "compliance:manage"
    ADMIN = "admin:*"


class RoleName(str, Enum):
    SUPER_ADMIN = "Super Admin"
    SECURITY_MANAGER = "Security Manager"
    PENTESTER = "Pentester"
    AUDITOR = "Auditor"
    READ_ONLY = "Read Only"


ROLE_PERMISSIONS: dict[RoleName, set[Permission]] = {
    RoleName.SUPER_ADMIN: set(Permission),
    RoleName.SECURITY_MANAGER: {
        Permission.SCAN_CREATE,
        Permission.SCAN_STOP,
        Permission.FINDING_REVIEW,
        Permission.EVIDENCE_ACCESS,
        Permission.REPORT_EXPORT,
        Permission.REMEDIATION_APPROVE,
        Permission.REMEDIATION_UPDATE,
        Permission.READ_DASHBOARD,
        Permission.READ_FINDINGS,
        Permission.READ_COMPLIANCE,
        Permission.MANAGE_COMPLIANCE,
    },
    RoleName.PENTESTER: {
        Permission.SCAN_CREATE,
        Permission.SCAN_STOP,
        Permission.EVIDENCE_ACCESS,
        Permission.REMEDIATION_UPDATE,
        Permission.READ_DASHBOARD,
        Permission.READ_FINDINGS,
        Permission.READ_COMPLIANCE,
        Permission.MANAGE_COMPLIANCE,
    },
    RoleName.AUDITOR: {
        Permission.EVIDENCE_ACCESS,
        Permission.REPORT_EXPORT,
        Permission.READ_DASHBOARD,
        Permission.READ_FINDINGS,
        Permission.READ_COMPLIANCE,
    },
    RoleName.READ_ONLY: {
        Permission.READ_DASHBOARD,
        Permission.READ_FINDINGS,
        Permission.READ_COMPLIANCE,
    },
}


def role_has_permission(role_name: str, permission: Permission) -> bool:
    try:
        role = RoleName(role_name)
    except ValueError:
        return False
    permissions = ROLE_PERMISSIONS[role]
    return Permission.ADMIN in permissions or permission in permissions


def default_permissions_for(role_name: RoleName) -> list[str]:
    return sorted(permission.value for permission in ROLE_PERMISSIONS[role_name])

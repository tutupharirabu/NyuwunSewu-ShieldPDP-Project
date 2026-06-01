"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-24
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("slug", sa.String(length=120), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        *timestamps(),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False, unique=True),
        sa.Column("permissions", sa.JSON(), nullable=False),
        *timestamps(),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "email", name="uq_org_email"),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_role_id", "users", ["role_id"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "name", name="uq_org_project_name"),
    )
    op.create_index("ix_projects_organization_id", "projects", ["organization_id"])
    op.create_index("ix_project_org_owner", "projects", ["organization_id", "owner_id"])

    op.create_table(
        "targets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("allowed_domains", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        *timestamps(),
        sa.UniqueConstraint("organization_id", "project_id", "base_url", name="uq_target_url"),
    )
    op.create_index("ix_targets_organization_id", "targets", ["organization_id"])

    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("max_requests_per_second", sa.Float(), nullable=False, server_default="5"),
        sa.Column("allow_sqli_validation", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allow_auth_validation", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allow_timing_validation", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("excluded_paths", sa.JSON(), nullable=False),
        sa.Column("forbidden_paths", sa.JSON(), nullable=False),
        sa.Column("scope_boundaries", sa.JSON(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("max_pages", sa.Integer(), nullable=False, server_default="500"),
        *timestamps(),
    )
    op.create_index("ix_policies_organization_id", "policies", ["organization_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.String(length=36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("policy_id", sa.String(length=36), sa.ForeignKey("policies.id"), nullable=False),
        sa.Column("started_by_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("stop_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        *timestamps(),
    )
    op.create_index("ix_scans_organization_id", "scans", ["organization_id"])
    op.create_index("ix_scan_org_project_status", "scans", ["organization_id", "project_id", "status"])

    op.create_table(
        "endpoints",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.String(length=36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=12), nullable=False, server_default="GET"),
        sa.Column("normalized_path", sa.String(length=2048), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("query_parameters", sa.JSON(), nullable=False),
        sa.Column("forms", sa.JSON(), nullable=False),
        sa.Column("tech_stack", sa.JSON(), nullable=False),
        sa.Column("classifications", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        *timestamps(),
        sa.UniqueConstraint("scan_id", "method", "url", name="uq_scan_endpoint"),
    )
    op.create_index("ix_endpoints_organization_id", "endpoints", ["organization_id"])
    op.create_index("ix_endpoints_scan_id", "endpoints", ["scan_id"])
    op.create_index("ix_endpoint_org_project", "endpoints", ["organization_id", "project_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target_id", sa.String(length=36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("endpoint_id", sa.String(length=36), sa.ForeignKey("endpoints.id"), nullable=True),
        sa.Column("finding_type", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False, server_default="low"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="Open"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("reasoning", sa.JSON(), nullable=False),
        sa.Column("evidence_summary", sa.JSON(), nullable=False),
        sa.Column("compliance", sa.JSON(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), nullable=False, server_default=sa.false()),
        *timestamps(),
    )
    op.create_index("ix_findings_organization_id", "findings", ["organization_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_finding_org_status_severity", "findings", ["organization_id", "status", "severity"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("immutable_id", sa.String(length=96), nullable=False),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("raw_request", sa.JSON(), nullable=False),
        sa.Column("raw_response", sa.JSON(), nullable=False),
        sa.Column("headers", sa.JSON(), nullable=False),
        sa.Column("reproduction_steps", sa.JSON(), nullable=False),
        sa.Column("curl_reproduction", sa.Text(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("immutable_id", name="uq_evidence_immutable_id"),
    )
    op.create_index("ix_evidence_immutable_id", "evidence", ["immutable_id"])
    op.create_index("ix_evidence_organization_id", "evidence", ["organization_id"])
    op.create_index("ix_evidence_evidence_hash", "evidence", ["evidence_hash"])

    op.create_table(
        "compliance_mapping",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("framework", sa.String(length=120), nullable=False),
        sa.Column("article_or_control", sa.String(length=120), nullable=False),
        sa.Column("privacy_risk", sa.Text(), nullable=False),
        sa.Column("legal_risk", sa.Text(), nullable=False),
        sa.Column("business_risk", sa.Text(), nullable=False),
        *timestamps(),
    )
    op.create_index("ix_compliance_mapping_organization_id", "compliance_mapping", ["organization_id"])
    op.create_index("ix_compliance_org_framework", "compliance_mapping", ["organization_id", "framework"])

    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("generated_by_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("report_type", sa.String(length=64), nullable=False),
        sa.Column("export_format", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("report_hash", sa.String(length=64), nullable=False),
        *timestamps(),
    )
    op.create_index("ix_reports_organization_id", "reports", ["organization_id"])

    op.create_table(
        "remediation_tracking",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("assignee_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="Open"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("retest_scan_id", sa.String(length=36), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        *timestamps(),
        sa.UniqueConstraint("finding_id", name="uq_remediation_finding"),
    )
    op.create_index("ix_remediation_tracking_organization_id", "remediation_tracking", ["organization_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=120), nullable=False),
        sa.Column("resource_id", sa.String(length=120), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_organization_id", "audit_logs", ["organization_id"])
    op.create_index("ix_audit_logs_entry_hash", "audit_logs", ["entry_hash"])
    op.create_index("ix_audit_org_action_time", "audit_logs", ["organization_id", "action", "timestamp"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("remediation_tracking")
    op.drop_table("reports")
    op.drop_table("compliance_mapping")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("endpoints")
    op.drop_table("scans")
    op.drop_table("policies")
    op.drop_table("targets")
    op.drop_table("projects")
    op.drop_table("users")
    op.drop_table("roles")
    op.drop_table("organizations")


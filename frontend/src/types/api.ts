export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
}

export interface UserResponse {
  id: string;
  organization_id: string | null;
  email: string;
  full_name: string;
  role: string;
  permissions: string[];
}

export interface DashboardResponse {
  compliance_score: number;
  security_score: number;
  unresolved_findings: number;
  critical_findings: number;
  remediation_progress: number;
  severity_breakdown: Record<string, number>;
}

export interface FindingResponse {
  id: string;
  project_id: string;
  target_id: string;
  scan_id: string;
  endpoint_id: string | null;
  endpoint_url?: string | null;
  finding_type: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  risk_score: number;
  description: string;
  reasoning: string[];
  evidence_summary: Record<string, unknown>;
  compliance: Array<Record<string, string>>;
  remediation_guidance: string;
  created_at: string;
}

export interface FindingEvidencePeekResponse {
  immutable_id: string;
  raw_request_full: Record<string, unknown>;
  raw_response_full: Record<string, unknown>;
  captured_at: string;
}

export interface FindingEvidenceResponse {
  immutable_id: string;
  finding_id: string | null;
  raw_request: Record<string, unknown>;
  raw_response: Record<string, unknown>;
  headers: Record<string, unknown>;
  reproduction_steps: string[];
  curl_reproduction: string;
  evidence_hash: string;
  captured_at: string;
}

export interface ReportResponse {
  id: string;
  project_id: string;
  scan_id: string | null;
  title: string;
  report_type: string;
  export_format: string;
  report_hash: string;
  content?: string | null;
}

export interface ComplianceRow {
  framework: string;
  article_or_control: string;
  finding_count: number;
}

export interface RemediationMatrixItem {
  priority_rank: number;
  priority_level: string;
  domain: string;
  action: string;
  finding_count: number;
  severity_breakdown: Record<string, number>;
  max_risk_score: number;
  total_effort_score: number;
  effort_estimate: string;
  effort_days: string;
  recommended_timeline: string;
  affected_endpoints: string[];
  finding_titles: string[];
  finding_types: string[];
  compliance_impact: string[];
}

export interface RemediationMatrixResponse {
  organization_id: string;
  matrix: RemediationMatrixItem[];
  total_findings: number;
  total_items: number;
}

export interface ComplianceResponse {
  organization_id: string;
  mappings: ComplianceRow[];
}

export interface ProjectSummary {
  id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  targets: number;
  scans: number;
  findings: number;
  created_at: string;
}

export interface TargetSummary {
  id: string;
  project_id: string;
  base_url: string;
  allowed_domains: string[];
  is_active: boolean;
  scans: number;
  findings: number;
  created_at: string;
}

export interface ScanSummary {
  id: string;
  project_id: string;
  project_name?: string | null;
  target_id: string;
  target_url?: string | null;
  status: string;
  stats: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  error?: string | null;
}

export interface ScanDetail extends ScanSummary {
  policy_id: string;
  stop_requested: boolean;
}

export interface EndpointInventory {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  normalized_path: string;
  status_code: number | null;
  title: string | null;
  content_type: string | null;
  query_parameters: string[];
  forms: Array<{
    action?: string;
    method?: string;
    fields?: Array<{ name?: string; type?: string; value?: string }>;
  }>;
  tech_stack: string[];
  classifications: Array<{
    classification?: string;
    confidence?: number;
    risk?: string;
    risk_score?: number;
    reasoning?: string[];
  }>;
  risk_score: number;
  finding_count: number;
  highest_severity: string | null;
  highest_confidence: number | null;
  finding_types: string[];
  finding_titles: string[];
  created_at: string;
}

export interface RemediationSummary {
  id: string;
  finding_id: string;
  title: string;
  severity: string;
  status: string;
  assignee_id: string | null;
  notes: string | null;
  retest_scan_id: string | null;
  updated_at: string;
}

export interface AuditLogResponse {
  id: string;
  timestamp: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  metadata_json: Record<string, unknown>;
  entry_hash: string;
}

export interface ScanStartPayload {
  target_url: string;
  project_id?: string | null;
  project_name?: string | null;
  allowed_domains: string[];
  initial_paths: string[];
  credential_auth?: {
    login_path: string;
    username: string;
    password: string;
  } | null;
  policy: {
    name?: string | null;
    max_requests_per_second: number;
    allow_sqli_validation: boolean;
    allow_auth_validation: boolean;
    allow_timing_validation: boolean;
    excluded_paths: string[];
    forbidden_paths: string[];
    scope_boundaries: string[];
    max_depth: number;
    max_pages: number;
  };
  primary_headers: Record<string, string>;
  secondary_headers: Record<string, string>;
  admin_headers?: Record<string, string>;
  auditor_headers?: Record<string, string>;
  custom_role_headers?: Record<string, Record<string, string>>;
  exploit_chains?: {
    enabled: boolean;
    username_candidates: string[];
    weak_jwt_secrets: string[];
    admin_paths: string[];
    modern_vuln_bank_probes: boolean;
  };
}

export interface AgentSessionLog {
  timestamp: string;
  level: string;
  message: string;
  action: string | null;
  details: Record<string, unknown>;
}

export interface AgentSessionPendingAction {
  action: string;
  description: string;
  risk_level: string;
  request: Record<string, unknown>;
  requested_at: string;
}

export interface AgentSessionResponse {
  id: string;
  agent_name: string;
  target_url: string;
  status: string;
  current_action: string | null;
  logs: AgentSessionLog[];
  pending_action: AgentSessionPendingAction | null;
  findings_count: number;
  scan_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface AgentApprovalPayload {
  approved: boolean;
  notes?: string;
}

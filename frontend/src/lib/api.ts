import type {
  AgentApprovalPayload,
  AgentSessionResponse,
  AuditLogResponse,
  ComplianceResponse,
  DashboardResponse,
  EndpointInventory,
  FindingEvidencePeekResponse,
  FindingEvidenceResponse,
  FindingResponse,
  ProjectSummary,
  RemediationMatrixResponse,
  RemediationSummary,
  ReportResponse,
  ScanDetail,
  ScanStartPayload,
  ScanSummary,
  TargetSummary,
  TokenResponse,
  UserResponse,
} from "@/types/api";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";
const TOKEN_KEY = "shieldpdp.access_token";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(options.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (options.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail =
        typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail ?? body);
    } catch {
      detail = response.statusText;
    }
    throw new ApiError(detail, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  async login(
    email: string,
    password: string,
    organization_slug = "default-organization",
  ) {
    const token = await request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password, organization_slug }),
    });
    setToken(token.access_token);
    return token;
  },
  me: () => request<UserResponse>("/auth/me"),
  logout: async () => {
    try {
      await request<{ status: string }>("/auth/logout", { method: "POST" });
    } finally {
      clearToken();
    }
  },
  dashboard: (targetId?: string) =>
    request<DashboardResponse>(
      `/dashboard${targetId ? `?target_id=${encodeURIComponent(targetId)}` : ""}`,
    ),
  findings: (scanId?: string, targetId?: string, limit = 500) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (scanId) params.set("scan_id", scanId);
    if (targetId) params.set("target_id", targetId);
    return request<FindingResponse[]>(`/findings?${params.toString()}`);
  },
  findingEvidence: (findingId: string) =>
    request<FindingEvidenceResponse>(
      `/findings/${encodeURIComponent(findingId)}/evidence`,
    ),
  findingEvidencePeek: (findingId: string) =>
    request<FindingEvidencePeekResponse>(
      `/findings/${encodeURIComponent(findingId)}/evidence/peek`,
    ),
  compliance: (targetId?: string) =>
    request<ComplianceResponse>(
      `/compliance${targetId ? `?target_id=${encodeURIComponent(targetId)}` : ""}`,
    ),
  remediationMatrix: (scanId?: string, targetId?: string) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (targetId) params.set("target_id", targetId);
    const qs = params.toString();
    return request<RemediationMatrixResponse>(
      `/compliance/remediation-matrix${qs ? `?${qs}` : ""}`,
    );
  },
  reports: (targetId?: string) =>
    request<ReportResponse[]>(
      `/reports${targetId ? `?target_id=${encodeURIComponent(targetId)}` : ""}`,
    ),
  projects: () => request<ProjectSummary[]>("/projects"),
  targets: () => request<TargetSummary[]>("/targets"),
  scans: () => request<ScanSummary[]>("/scans?limit=50"),
  scan: (scanId: string) =>
    request<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`),
  scanEndpoints: (scanId: string) =>
    request<EndpointInventory[]>(
      `/scans/${encodeURIComponent(scanId)}/endpoints`,
    ),
  remediations: (targetId?: string) =>
    request<RemediationSummary[]>(
      `/remediations${targetId ? `?target_id=${encodeURIComponent(targetId)}` : ""}`,
    ),
  auditLogs: (targetId?: string, limit = 100) =>
    request<AuditLogResponse[]>(
      `/audit-logs?limit=${limit}${targetId ? `&target_id=${encodeURIComponent(targetId)}` : ""}`,
    ),
  startScan: (payload: ScanStartPayload) =>
    request<{ scan_id: string; status: string; message: string }>(
      "/scan/start",
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
  uploadRoe: async (file: File): Promise<{
    roe_document_id: string;
    filename: string;
    char_count: number;
    extraction_warning: boolean;
  }> => {
    const token = getToken();
    const form = new FormData();
    form.append("file", file);
    form.append("engagement_mode", "external");
    const resp = await fetch(`${API_BASE}/scan/roe`, {
      method: "POST",
      headers: token ? { authorization: `Bearer ${token}` } : undefined,
      body: form,
    });
    if (!resp.ok) {
      throw new ApiError((await resp.text()) || resp.statusText, resp.status);
    }
    return resp.json();
  },
  updateRemediation: (findingId: string, status: string, notes?: string) =>
    request<RemediationSummary>(`/remediation/${findingId}`, {
      method: "PUT",
      body: JSON.stringify({ status, notes }),
    }),
  generateReport: (
    project_id: string,
    report_type: string,
    export_format: string,
    scan_id?: string | null,
  ) =>
    request<ReportResponse>("/reports/generate", {
      method: "POST",
      body: JSON.stringify({
        project_id,
        report_type,
        export_format,
        scan_id: scan_id || null,
      }),
    }),
  async downloadReport(reportId: string) {
    const token = getToken();
    const response = await fetch(`${API_BASE}/reports/${reportId}/download`, {
      headers: token ? { authorization: `Bearer ${token}` } : undefined,
    });
    if (!response.ok) {
      throw new ApiError(response.statusText, response.status);
    }
    return response.blob();
  },
  deleteReport: (reportId: string) =>
    request<void>(`/reports/${encodeURIComponent(reportId)}`, {
      method: "DELETE",
    }),
  agentSessions: (scanId?: string, status?: string) => {
    const params = new URLSearchParams({ limit: "50" });
    if (scanId) params.set("scan_id", scanId);
    if (status) params.set("status", status);
    return request<AgentSessionResponse[]>(
      `/agent-sessions?${params.toString()}`,
    );
  },
  agentSession: (sessionId: string) =>
    request<AgentSessionResponse>(
      `/agent-sessions/${encodeURIComponent(sessionId)}`,
    ),
  approveAction: (sessionId: string, payload: AgentApprovalPayload) =>
    request<{ status: string }>(
      `/agent-sessions/${encodeURIComponent(sessionId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
};

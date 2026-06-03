import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BellRing,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Database,
  ExternalLink,
  Eye,
  FileClock,
  FileSearch,
  Fingerprint,
  Gavel,
  GitBranch,
  Layers3,
  LockKeyhole,
  Microscope,
  Radar,
  Scale,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TriangleAlert,
  Upload,
  Workflow,
  X,
  type LucideIcon,
} from "lucide-react";
import { memo, useEffect, useMemo, useState, type ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Progress } from "@/components/ui/progress";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { cn, compactId, formatNumber, severityColor } from "@/lib/utils";
import type {
  AuditLogResponse,
  ComplianceRow,
  DashboardResponse,
  FindingEvidenceResponse,
  FindingResponse,
  RemediationSummary,
  ReportResponse,
  TargetSummary,
} from "@/types/api";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type ReadinessState = "Ready" | "Partial" | "Missing";

interface ComplianceData {
  targetId: string;
  dashboard: DashboardResponse;
  findings: FindingResponse[];
  mappings: ComplianceRow[];
  remediations: RemediationSummary[];
  auditLogs: AuditLogResponse[];
  reports: ReportResponse[];
}

interface RegulatoryArticle {
  title: string;
  description: string;
  source: string;
}

interface IntelligenceRow {
  framework: string;
  control: string;
  findingCount: number;
  findings: FindingResponse[];
  contextual?: boolean;
}

interface Selection {
  framework: string;
  control: string;
  severity: Severity;
  findings: FindingResponse[];
  contextual?: boolean;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const severitySurface: Record<Severity, string> = {
  critical:
    "border-red-500/30 bg-red-500/10 text-red-700 shadow-[0_0_18px_rgba(239,68,68,0.12)] dark:text-red-300",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  medium:
    "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-300",
  low: "border-teal-500/30 bg-teal-500/10 text-teal-700 dark:text-teal-300",
  info: "border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300",
};

const heatCell: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-700 hover:bg-red-500/25 dark:text-red-300",
  high: "bg-orange-500/15 text-orange-700 hover:bg-orange-500/25 dark:text-orange-300",
  medium:
    "bg-yellow-500/15 text-yellow-700 hover:bg-yellow-500/25 dark:text-yellow-300",
  low: "bg-teal-500/15 text-teal-700 hover:bg-teal-500/25 dark:text-teal-300",
  info: "bg-muted text-muted-foreground",
};

const regulations: Record<string, RegulatoryArticle> = {
  "UU PDP|Pasal 35": {
    title: "Protection and Security of Personal Data",
    description:
      "UU PDP Pasal 35 requires a Personal Data Controller to protect and ensure the security of Personal Data it processes through technical and operational measures.",
    source: "UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi, Pasal 35",
  },
  "UU PDP|Pasal 46": {
    title: "Personal Data Protection Failure Notification",
    description:
      "UU PDP Pasal 46 requires written notification no later than 3 x 24 hours after a Personal Data protection failure, subject to confirmation that a qualifying failure occurred.",
    source: "UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi, Pasal 46",
  },
  "OWASP ASVS|V4 Access Control": {
    title: "Access Control Verification",
    description:
      "ASVS V4 provides assurance requirements for server-side authorization, object access control, and protection against unauthorized privilege use.",
    source: "OWASP Application Security Verification Standard",
  },
  "OWASP ASVS|V8 Data Protection": {
    title: "Data Protection Verification",
    description:
      "ASVS V8 focuses on protecting sensitive data in storage and transit and reducing inappropriate disclosure through application responses.",
    source: "OWASP Application Security Verification Standard",
  },
  "OWASP ASVS|V2 Authentication / V3 Session Management": {
    title: "Identity and Session Assurance",
    description:
      "ASVS identity and session controls address authentication quality, token handling, session lifecycle, and resistance to unauthorized account use.",
    source: "OWASP Application Security Verification Standard",
  },
  "OWASP ASVS|V5 Validation, Sanitization and Encoding": {
    title: "Input Validation and Encoding",
    description:
      "ASVS V5 requires trustworthy validation, safe interpreter handling, and output encoding controls for user-influenced inputs.",
    source: "OWASP Application Security Verification Standard",
  },
};

const personalDataCatalog = [
  { name: "NIK", matcher: /nik|national identity/i, icon: Fingerprint },
  { name: "Biometrics", matcher: /biometric/i, icon: Fingerprint },
  { name: "Phone Number", matcher: /phone|telepon|mobile/i, icon: BellRing },
  { name: "Email", matcher: /email/i, icon: ScrollText },
  {
    name: "Financial Data",
    matcher: /financial|bank|account|payment|transfer/i,
    icon: Database,
  },
  {
    name: "Authentication Data",
    matcher: /jwt|token|password|authentication|session/i,
    icon: LockKeyhole,
  },
];

function normalizeSeverity(value: string | null | undefined): Severity {
  const severity = String(value ?? "info").toLowerCase();
  return severityOrder.includes(severity as Severity)
    ? (severity as Severity)
    : "info";
}

function highestSeverity(findings: FindingResponse[]): Severity {
  return findings.reduce<Severity>(
    (highest, finding) =>
      severityRank[normalizeSeverity(finding.severity)] > severityRank[highest]
        ? normalizeSeverity(finding.severity)
        : highest,
    "info",
  );
}

function complianceKey(framework: string, control: string) {
  return `${framework}|${control.replace(" (Readiness Context)", "")}`;
}

function textForFinding(finding: FindingResponse) {
  return JSON.stringify({
    title: finding.title,
    type: finding.finding_type,
    description: finding.description,
    evidence: finding.evidence_summary,
    compliance: finding.compliance,
  });
}

function affectedData(findings: FindingResponse[]) {
  const material = findings.map(textForFinding).join(" ");
  return personalDataCatalog
    .filter((item) => item.matcher.test(material))
    .map((item) => item.name);
}

function findingsForMapping(
  findings: FindingResponse[],
  framework: string,
  control: string,
) {
  const normalizedControl = control.replace(" (Readiness Context)", "");
  return findings.filter((finding) =>
    finding.compliance.some(
      (item) =>
        item.framework === framework &&
        item.article_or_control === normalizedControl,
    ),
  );
}

function mappingRows(mappings: ComplianceRow[], findings: FindingResponse[]) {
  const rows: IntelligenceRow[] = mappings.map((row) => ({
    framework: row.framework,
    control: row.article_or_control,
    findingCount: row.finding_count,
    findings: findingsForMapping(
      findings,
      row.framework,
      row.article_or_control,
    ),
  }));
  if (
    !rows.some(
      (row) => row.framework === "UU PDP" && row.control === "Pasal 35",
    )
  ) {
    rows.unshift({
      framework: "UU PDP",
      control: "Pasal 35",
      findingCount: 0,
      findings: [],
    });
  }
  rows.push({
    framework: "UU PDP",
    control: "Pasal 46 (Readiness Context)",
    findingCount: 0,
    findings: [],
    contextual: true,
  });
  return rows;
}

function mitigationControls(findings: FindingResponse[]) {
  const types = findings
    .map((finding) => finding.finding_type.toLowerCase())
    .join(" ");
  const controls = new Set<string>([
    "Security logging",
    "Monitoring",
    "Evidence retention",
  ]);
  if (/bola|idor|auth|jwt/.test(types)) {
    controls.add("RBAC and object ownership checks");
    controls.add("MFA and hardened sessions");
    controls.add("Least privilege");
  }
  if (/sqli|path|reflected/.test(types)) {
    controls.add("Input validation");
    controls.add("Parameterized queries");
  }
  if (/pii|exposure/.test(types)) {
    controls.add("Field-level data minimization");
    controls.add("Encryption");
  }
  return [...controls];
}

function technicalMappings(findings: FindingResponse[]) {
  const types = findings
    .map((finding) => finding.finding_type.toLowerCase())
    .join(" ");
  if (/bola|idor|missing_authorization/.test(types)) {
    return [
      "OWASP API1:2023 BOLA",
      "OWASP ASVS V4",
      "MITRE T1213",
      "ISO 27001 A.5.15",
      "NIST AC-3",
    ];
  }
  if (/sqli/.test(types)) {
    return [
      "OWASP Top 10 A03 Injection",
      "OWASP ASVS V5",
      "MITRE T1190",
      "ISO 27001 A.8.26",
      "NIST SI-10",
    ];
  }
  if (/pii|exposure/.test(types)) {
    return [
      "OWASP API3:2023",
      "OWASP ASVS V8",
      "MITRE T1213",
      "ISO 27001 A.5.34",
      "NIST PT-2",
    ];
  }
  return ["OWASP ASVS", "ISO 27001 A.5.36", "NIST CA-7"];
}

function readinessControls(
  findings: FindingResponse[],
  auditLogs: AuditLogResponse[],
  reports: ReportResponse[],
) {
  const evidenceCount = findings.filter(
    (item) => item.evidence_summary.evidence_id,
  ).length;
  return [
    {
      name: "Detection capability",
      state: "Ready" as ReadinessState,
      detail: "Validation engines enabled",
    },
    {
      name: "Logging coverage",
      state: (auditLogs.length ? "Ready" : "Partial") as ReadinessState,
      detail: `${auditLogs.length} audit events`,
    },
    {
      name: "SIEM integration",
      state: "Missing" as ReadinessState,
      detail: "Not implemented in MVP scope",
    },
    {
      name: "Notification workflow",
      state: (reports.length ? "Partial" : "Missing") as ReadinessState,
      detail: "Requires incident confirmation",
    },
    {
      name: "Forensics readiness",
      state: (evidenceCount ? "Partial" : "Missing") as ReadinessState,
      detail: `${evidenceCount} evidence records`,
    },
    {
      name: "Evidence retention",
      state: (evidenceCount ? "Ready" : "Partial") as ReadinessState,
      detail: "Immutable hash storage",
    },
  ];
}

function readinessScore(controls: Array<{ state: ReadinessState }>) {
  return Math.round(
    controls.reduce(
      (sum, item) =>
        sum +
        (item.state === "Ready" ? 100 : item.state === "Partial" ? 50 : 0),
      0,
    ) / controls.length,
  );
}

function useAnimatedNumber(value: number) {
  const [shown, setShown] = useState(value);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setShown(value);
      return;
    }
    const started = performance.now();
    const duration = 650;
    let frame = 0;
    const update = (now: number) => {
      const progress = Math.min(1, (now - started) / duration);
      setShown(Math.round(value * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) frame = window.requestAnimationFrame(update);
    };
    frame = window.requestAnimationFrame(update);
    return () => window.cancelAnimationFrame(frame);
  }, [value]);
  return shown;
}

function Sparkline({ value, severity }: { value: number; severity: Severity }) {
  const color = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#14b8a6",
    info: "#3b82f6",
  }[severity];
  const points = [0.74, 0.82, 0.7, 0.88, 0.93, 1].map((factor) =>
    Math.max(0, value * factor),
  );
  const width = 80;
  const height = 36;
  const max = Math.max(...points, 1);
  const min = Math.min(...points);
  const range = max - min || 1;
  const step = width / (points.length - 1);
  const path = points
    .map((point, index) => {
      const x = index * step;
      const y = height - ((point - min) / range) * height;
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <div className="h-9 w-20" aria-hidden="true">
      <svg
        width="100%"
        height="100%"
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
      >
        <path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function SignalCard({
  title,
  value,
  suffix,
  detail,
  severity,
  icon: Icon,
  onClick,
}: {
  title: string;
  value: number;
  suffix?: string;
  detail: string;
  severity: Severity;
  icon: LucideIcon;
  onClick?: () => void;
}) {
  const shown = useAnimatedNumber(value);
  const body = (
    <div className="group flex h-full flex-col justify-between gap-3 p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">{title}</p>
        <div className={cn("rounded-md border p-2", severitySurface[severity])}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="flex items-end justify-between gap-2">
        <div>
          <p className="text-2xl font-semibold">
            {shown}
            {suffix}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
        </div>
        <Sparkline value={value} severity={severity} />
      </div>
    </div>
  );
  return onClick ? (
    <button
      type="button"
      className={cn(
        "min-h-[126px] rounded-lg border bg-card text-left transition hover:border-primary/35 hover:shadow-[0_0_22px_hsl(var(--primary)/0.09)]",
        severity === "critical" &&
          "hover:shadow-[0_0_24px_rgba(239,68,68,0.15)]",
      )}
      onClick={onClick}
    >
      {body}
    </button>
  ) : (
    <div className="min-h-[126px] rounded-lg border bg-card">{body}</div>
  );
}

function ComplianceGaugeImpl({
  score,
  findings,
}: {
  score: number;
  findings: FindingResponse[];
}) {
  const shown = useAnimatedNumber(score);
  const accessPenalty =
    findings.filter((item) =>
      /bola|idor|authorization/i.test(item.finding_type),
    ).length * 12;
  const dataPenalty =
    findings.filter((item) => /pii|exposure/i.test(item.finding_type)).length *
    12;
  const authPenalty =
    findings.filter((item) => /auth|jwt/i.test(item.finding_type)).length * 10;
  const safeguards = [
    { label: "Access Control", score: Math.max(0, score - accessPenalty) },
    {
      label: "Encryption",
      score: Math.max(0, score - Math.round(dataPenalty / 2)),
    },
    { label: "Logging", score: Math.min(100, score + 6) },
    { label: "Monitoring", score: Math.min(100, score + 2) },
    {
      label: "Incident Response",
      score: Math.max(0, score - Math.round(dataPenalty / 3)),
    },
    {
      label: "Data Protection",
      score: Math.max(0, score - dataPenalty - authPenalty),
    },
  ];
  const radius = 74;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <Card className="compliance-surface relative overflow-hidden">
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <CardTitle>PDP Compliance Score</CardTitle>
        </div>
        <CardDescription>
          Control posture derived from accepted regulatory findings.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-[188px_1fr]">
        <div
          className="relative mx-auto flex h-[180px] w-[180px] items-center justify-center"
          title="Weighted UU PDP control posture"
        >
          <svg
            className="h-full w-full -rotate-90"
            viewBox="0 0 180 180"
            aria-label={`Compliance score ${score} out of 100`}
          >
            <defs>
              <linearGradient id="pdp-ring" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#14b8a6" />
                <stop offset="58%" stopColor="#2563eb" />
                <stop offset="100%" stopColor="#f59e0b" />
              </linearGradient>
            </defs>
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke="hsl(var(--muted))"
              strokeWidth="11"
            />
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke="url(#pdp-ring)"
              strokeWidth="11"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className="compliance-ring"
            />
          </svg>
          <div className="absolute text-center">
            <p className="text-4xl font-semibold">{shown}</p>
            <p className="text-xs text-muted-foreground">out of 100</p>
          </div>
        </div>
        <div className="grid content-center gap-3 sm:grid-cols-2">
          {safeguards.map((control) => (
            <div key={control.label}>
              <div className="mb-1.5 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{control.label}</span>
                <span className="font-medium">{control.score}%</span>
              </div>
              <Progress value={control.score} />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ComplianceHeatmapImpl({
  rows,
  onSelect,
}: {
  rows: IntelligenceRow[];
  onSelect: (selection: Selection) => void;
}) {
  return (
    <Card className="compliance-surface">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Layers3 className="h-4 w-4 text-primary" />
          <CardTitle>Compliance Heatmap</CardTitle>
        </div>
        <CardDescription>
          Validated findings by regulatory control and severity. Select a cell
          for context.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <div className="min-w-[540px] space-y-2">
            <div className="grid grid-cols-[minmax(210px,1fr)_repeat(4,70px)] gap-2 px-1 text-xs text-muted-foreground">
              <span>Article / domain</span>
              {severityOrder.map((severity) => (
                <span className="text-center capitalize" key={severity}>
                  {severity}
                </span>
              ))}
            </div>
            {rows.map((row) => (
              <div
                key={`${row.framework}-${row.control}`}
                className="grid grid-cols-[minmax(210px,1fr)_repeat(4,70px)] items-center gap-2 rounded-md border bg-background/40 p-2"
              >
                <button
                  type="button"
                  className="flex min-w-0 items-center gap-2 text-left hover:text-primary"
                  onClick={() =>
                    onSelect({
                      framework: row.framework,
                      control: row.control,
                      severity: highestSeverity(row.findings),
                      findings: row.findings,
                      contextual: row.contextual,
                    })
                  }
                >
                  <Badge
                    variant={row.framework === "UU PDP" ? "default" : "blue"}
                  >
                    {row.framework}
                  </Badge>
                  <span className="truncate text-sm font-medium">
                    {row.control}
                  </span>
                  {row.contextual && (
                    <span className="text-[10px] text-muted-foreground">
                      context
                    </span>
                  )}
                </button>
                {severityOrder.map((severity) => {
                  const matches = row.findings.filter(
                    (finding) =>
                      normalizeSeverity(finding.severity) === severity,
                  );
                  return (
                    <button
                      key={severity}
                      type="button"
                      className={cn(
                        "flex h-9 items-center justify-center rounded-md border text-sm font-semibold transition",
                        heatCell[severity],
                        matches.length === 0 && "opacity-45",
                      )}
                      onClick={() =>
                        onSelect({
                          framework: row.framework,
                          control: row.control,
                          severity,
                          findings: matches,
                          contextual: row.contextual,
                        })
                      }
                      aria-label={`${row.control} ${severity}: ${matches.length} findings`}
                    >
                      {matches.length}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function SensitiveDataPanelImpl({ findings }: { findings: FindingResponse[] }) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-teal-500" />
          <CardTitle>Sensitive Data Exposure</CardTitle>
        </div>
        <CardDescription>
          Personal-data indicators referenced in accepted evidence and mapping
          records.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        {personalDataCatalog.map((type) => {
          const matches = findings.filter((finding) =>
            type.matcher.test(textForFinding(finding)),
          );
          const severity = highestSeverity(matches);
          const Icon = type.icon;
          const status = matches.length
            ? severity === "critical" || severity === "high"
              ? "Priority review"
              : "Monitor"
            : "No observed exposure";
          return (
            <div
              key={type.name}
              className={cn(
                "rounded-md border p-3",
                matches.length && severitySurface[severity],
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4" />
                  <span className="text-sm font-medium">{type.name}</span>
                </div>
                <Badge
                  variant={
                    matches.length
                      ? (severityColor(severity) as never)
                      : "emerald"
                  }
                >
                  {matches.length ? severity : "clear"}
                </Badge>
              </div>
              <div className="mt-3 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Evidence events</span>
                <span className="font-semibold">{matches.length}</span>
              </div>
              <p className="mt-2 text-xs">{status}</p>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function BreachReadinessImpl({
  findings,
  auditLogs,
  reports,
  remediations,
}: {
  findings: FindingResponse[];
  auditLogs: AuditLogResponse[];
  reports: ReportResponse[];
  remediations: RemediationSummary[];
}) {
  const controls = readinessControls(findings, auditLogs, reports);
  const score = readinessScore(controls);
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Siren className="h-4 w-4 text-orange-500" />
            <CardTitle>Breach Notification Readiness</CardTitle>
          </div>
          <Badge variant={score >= 75 ? "emerald" : "amber"}>
            {score}% ready
          </Badge>
        </div>
        <CardDescription>
          Preparedness signals for a potential UU PDP Pasal 46 assessment.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Progress value={score} />
        <div className="grid gap-2 sm:grid-cols-2">
          {controls.map((control) => (
            <div
              key={control.name}
              className="flex items-start gap-2 rounded-md border p-3"
            >
              {control.state === "Ready" ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-teal-500" />
              ) : control.state === "Partial" ? (
                <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-yellow-500" />
              ) : (
                <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
              )}
              <div>
                <p className="text-xs font-medium">{control.name}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {control.detail}
                </p>
              </div>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Open remediation items:{" "}
          {remediations.filter((item) => item.status !== "Closed").length}.
          Notification timing applies only after a qualifying protection failure
          is confirmed.
        </p>
      </CardContent>
    </Card>
  );
}

function ExposurePathImpl({
  findings,
  onSelect,
}: {
  findings: FindingResponse[];
  onSelect: (selection: Selection) => void;
}) {
  const nodes = [
    {
      name: "Discovery",
      icon: Radar,
      matcher: /segmentation|internal/i,
      tactic: "Discovery",
    },
    {
      name: "Authentication",
      icon: LockKeyhole,
      matcher: /jwt|auth/i,
      tactic: "Credential Access",
    },
    {
      name: "Access Control",
      icon: ShieldAlert,
      matcher: /bola|idor|authorization/i,
      tactic: "Collection",
    },
    {
      name: "Data Exposure",
      icon: Database,
      matcher: /pii|exposure|sqli/i,
      tactic: "Collection",
    },
    { name: "UU PDP Impact", icon: Gavel, matcher: /./i, tactic: "Governance" },
  ].map((node) => ({
    ...node,
    findings: findings.filter((finding) =>
      node.name === "UU PDP Impact"
        ? finding.compliance.some((item) => item.framework === "UU PDP")
        : node.matcher.test(finding.finding_type),
    ),
  }));
  return (
    <Card className="compliance-surface">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-primary" />
          <CardTitle>Exposure Path Visualization</CardTitle>
        </div>
        <CardDescription>
          Evidence-backed progression only; unobserved steps remain contextual.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-2 overflow-x-auto pb-2 md:flex-row md:items-center">
          {nodes.map((node, index) => {
            const Icon = node.icon;
            const severity = highestSeverity(node.findings);
            return (
              <div key={node.name} className="contents">
                <button
                  type="button"
                  className={cn(
                    "min-w-[142px] rounded-md border bg-background p-3 text-left transition hover:border-primary/40",
                    node.findings.length && severitySurface[severity],
                  )}
                  onClick={() =>
                    onSelect({
                      framework:
                        node.name === "UU PDP Impact" ? "UU PDP" : "OWASP ASVS",
                      control:
                        node.name === "UU PDP Impact" ? "Pasal 35" : node.name,
                      severity,
                      findings: node.findings,
                    })
                  }
                >
                  <div className="flex items-center justify-between">
                    <Icon className="h-4 w-4" />
                    <span className="text-xs font-semibold">
                      {node.findings.length}
                    </span>
                  </div>
                  <p className="mt-3 text-sm font-medium">{node.name}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {node.tactic}
                  </p>
                </button>
                {index < nodes.length - 1 && (
                  <div className="exposure-link flex h-6 w-6 shrink-0 items-center justify-center self-center text-primary md:h-1 md:w-8">
                    <ArrowRight className="h-4 w-4 rotate-90 md:rotate-0" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function MappingMatrixImpl({
  rows,
  onSelect,
}: {
  rows: IntelligenceRow[];
  onSelect: (selection: Selection) => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(
    rows[0] ? `${rows[0].framework}-${rows[0].control}` : null,
  );
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Scale className="h-4 w-4 text-primary" />
          <CardTitle>Regulatory Mapping</CardTitle>
        </div>
        <CardDescription>
          Cross-framework assurance links for audit preparation.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {rows
          .filter((row) => !row.contextual)
          .map((row) => {
            const key = `${row.framework}-${row.control}`;
            const open = expanded === key;
            const crosswalk = technicalMappings(row.findings);
            return (
              <div key={key} className="rounded-md border">
                <button
                  type="button"
                  className="flex w-full items-center justify-between gap-3 p-3 text-left"
                  onClick={() => setExpanded(open ? null : key)}
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <Badge
                      variant={row.framework === "UU PDP" ? "default" : "blue"}
                    >
                      {row.framework}
                    </Badge>
                    <span className="truncate text-sm font-medium">
                      {row.control}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {row.findingCount} findings
                    </span>
                  </div>
                  {open ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                </button>
                {open && (
                  <div className="border-t p-3">
                    <div className="flex flex-wrap gap-2">
                      {crosswalk.map((item) => (
                        <Badge variant="outline" key={item}>
                          {item}
                        </Badge>
                      ))}
                    </div>
                    <Button
                      className="mt-3"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        onSelect({
                          framework: row.framework,
                          control: row.control,
                          severity: highestSeverity(row.findings),
                          findings: row.findings,
                        })
                      }
                    >
                      <BookOpen className="h-3.5 w-3.5" />
                      Regulatory context
                    </Button>
                  </div>
                )}
              </div>
            );
          })}
      </CardContent>
    </Card>
  );
}

function MitreContextImpl({ findings }: { findings: FindingResponse[] }) {
  const mappings = [
    {
      tactic: "Initial Access",
      technique: "T1190 Exploit Public-Facing App",
      matcher: /sqli|path|reflected/i,
    },
    {
      tactic: "Credential Access",
      technique: "T1550 Use Alternate Authentication Material",
      matcher: /jwt|auth/i,
    },
    {
      tactic: "Discovery",
      technique: "T1087 Account Discovery",
      matcher: /internal|segmentation/i,
    },
    {
      tactic: "Collection",
      technique: "T1213 Data from Information Repositories",
      matcher: /bola|idor|pii|exposure/i,
    },
    {
      tactic: "Exfiltration",
      technique: "Requires analyst confirmation",
      matcher: /no-automatic-match/i,
    },
  ];
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Radar className="h-4 w-4 text-blue-500" />
          <CardTitle>MITRE ATT&amp;CK Context</CardTitle>
        </div>
        <CardDescription>
          Analyst-supporting technique context, not proof of attacker activity.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {mappings.map((mapping) => {
          const related = findings.filter((finding) =>
            mapping.matcher.test(finding.finding_type),
          );
          const severity = highestSeverity(related);
          return (
            <div
              key={mapping.tactic}
              className="grid grid-cols-[112px_1fr_auto] items-center gap-3 rounded-md border p-3 text-xs"
            >
              <span className="font-medium">{mapping.tactic}</span>
              <span className="text-muted-foreground">{mapping.technique}</span>
              <Badge
                variant={
                  related.length
                    ? (severityColor(severity) as never)
                    : "outline"
                }
              >
                {related.length || "context"}
              </Badge>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function WorkflowTimelineImpl({
  remediations,
}: {
  remediations: RemediationSummary[];
}) {
  const states = [
    "Detected",
    "Verified",
    "Risk Accepted",
    "Remediation",
    "Validation",
    "Audit Approved",
    "Closed",
  ];
  const active = remediations.some((item) => item.status !== "Closed");
  const closed = remediations.filter((item) => item.status === "Closed").length;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Workflow className="h-4 w-4 text-primary" />
          <CardTitle>Compliance Workflow Timeline</CardTitle>
        </div>
        <CardDescription>
          Governance lifecycle state across accepted findings and remediation
          records.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <div className="flex min-w-[720px] items-start">
            {states.map((state, index) => {
              const completed =
                index <= 1 || (index === states.length - 1 && closed > 0);
              const current = active && state === "Remediation";
              return (
                <div
                  key={state}
                  className="relative flex flex-1 flex-col items-center text-center"
                >
                  {index > 0 && (
                    <div className="absolute right-1/2 top-3 h-px w-full bg-border" />
                  )}
                  <div
                    className={cn(
                      "relative z-10 flex h-7 w-7 items-center justify-center rounded-full border bg-card",
                      completed &&
                        "border-teal-500 bg-teal-500/10 text-teal-500",
                      current &&
                        "border-yellow-500 bg-yellow-500/10 text-yellow-500 compliance-pulse",
                    )}
                  >
                    {completed ? (
                      <CheckCircle2 className="h-4 w-4" />
                    ) : (
                      <span className="h-2 w-2 rounded-full bg-muted-foreground/30" />
                    )}
                  </div>
                  <p className="mt-3 text-xs font-medium">{state}</p>
                  {current && (
                    <p className="mt-1 text-[11px] text-yellow-600 dark:text-yellow-300">
                      In progress
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EvidenceCollectionImpl({
  findings,
  onSelect,
}: {
  findings: FindingResponse[];
  onSelect: (selection: Selection) => void;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <FileSearch className="h-4 w-4 text-primary" />
          <CardTitle>Evidence Collection</CardTitle>
        </div>
        <CardDescription>
          Immutable artifacts attached to validated findings.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {findings.slice(0, 4).map((finding) => (
          <button
            key={finding.id}
            type="button"
            onClick={() =>
              onSelect({
                framework: String(
                  finding.compliance[0]?.framework ?? "OWASP ASVS",
                ),
                control: String(
                  finding.compliance[0]?.article_or_control ??
                    "V1 Architecture",
                ),
                severity: normalizeSeverity(finding.severity),
                findings: [finding],
              })
            }
            className="flex w-full items-center justify-between gap-3 rounded-md border p-3 text-left transition hover:border-primary/40"
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{finding.title}</p>
              <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                {finding.endpoint_url ?? compactId(finding.endpoint_id)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Badge variant={severityColor(finding.severity) as never}>
                {finding.severity}
              </Badge>
              <Eye className="h-4 w-4 text-muted-foreground" />
            </div>
          </button>
        ))}
        {!findings.length && (
          <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            Evidence becomes available after a finding is validated.
          </div>
        )}
        <div className="grid gap-2 border-t pt-3 sm:grid-cols-2">
          {[
            {
              label: "HTTP request / response",
              icon: FileSearch,
              available: findings.length > 0,
            },
            {
              label: "Evidence hash",
              icon: ShieldCheck,
              available: findings.length > 0,
            },
            {
              label: "Screenshot attachment",
              icon: Microscope,
              available: false,
            },
            {
              label: "Uploaded remediation proof",
              icon: Upload,
              available: false,
            },
          ].map((item) => (
            <div
              key={item.label}
              className="flex items-center gap-2 text-xs text-muted-foreground"
            >
              <item.icon className="h-3.5 w-3.5" />
              <span>{item.label}</span>
              <Badge variant={item.available ? "emerald" : "outline"}>
                {item.available ? "available" : "not attached"}
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ExecutiveSummaryImpl({
  findings,
  rows,
  remediations,
}: {
  findings: FindingResponse[];
  rows: IntelligenceRow[];
  remediations: RemediationSummary[];
}) {
  const severity = highestSeverity(findings);
  const topFinding = [...findings].sort(
    (a, b) => b.risk_score - a.risk_score,
  )[0];
  const topArticle = [...rows]
    .filter((row) => row.framework === "UU PDP" && !row.contextual)
    .sort((a, b) => b.findingCount - a.findingCount)[0];
  const slaRisk = remediations.filter(
    (item) =>
      item.status !== "Closed" &&
      ["critical", "high"].includes(item.severity.toLowerCase()),
  ).length;
  const exposure =
    severity === "critical"
      ? "Material"
      : severity === "high"
        ? "Elevated"
        : findings.length
          ? "Managed"
          : "No validated gap";
  const items = [
    { label: "Estimated regulatory exposure", value: exposure, icon: Gavel },
    {
      label: "Potential affected records",
      value: "Not quantified",
      icon: Fingerprint,
    },
    {
      label: "Most impacted PDP article",
      value: topArticle?.control ?? "No mapped article",
      icon: Scale,
    },
    {
      label: "Highest business risk",
      value: topFinding?.title ?? "No accepted finding",
      icon: TriangleAlert,
    },
    {
      label: "Estimated breach severity",
      value: findings.length ? severity : "Not established",
      icon: Siren,
    },
    {
      label: "Remediation SLA risk",
      value: `${slaRisk} priority items`,
      icon: FileClock,
    },
  ];
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <ScrollText className="h-4 w-4 text-primary" />
          <CardTitle>Executive Regulatory Overview</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="grid gap-3 md:grid-cols-3">
        {items.map((item) => (
          <div
            key={item.label}
            className="rounded-md border bg-background/50 p-3"
          >
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <item.icon className="h-3.5 w-3.5" />
              {item.label}
            </div>
            <p
              className="mt-2 truncate text-sm font-semibold capitalize"
              title={item.value}
            >
              {item.value}
            </p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function RegulatoryDrawer({
  selection,
  onClose,
}: {
  selection: Selection | null;
  onClose: () => void;
}) {
  const [evidence, setEvidence] = useState<FindingEvidenceResponse | null>(
    null,
  );
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const finding = selection?.findings[0];
    setEvidence(null);
    setEvidenceError(null);
    if (!finding) return;
    let active = true;
    setLoading(true);
    void api
      .findingEvidence(finding.id)
      .then((result) => {
        if (active) setEvidence(result);
      })
      .catch((error: unknown) => {
        if (active)
          setEvidenceError(
            error instanceof Error ? error.message : "Evidence unavailable",
          );
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selection]);

  if (!selection) return null;
  const article = regulations[
    complianceKey(selection.framework, selection.control)
  ] ?? {
    title: selection.control,
    description:
      "Control context requires analyst review against the authoritative framework source.",
    source: selection.framework,
  };
  const finding = selection.findings[0];
  const pii = affectedData(selection.findings);
  const impacts = finding?.compliance.find(
    (item) =>
      item.framework === selection.framework &&
      item.article_or_control ===
        selection.control.replace(" (Readiness Context)", ""),
  );
  const controls = mitigationControls(selection.findings);
  const mappings = technicalMappings(selection.findings);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        className="absolute inset-0 bg-background/75 backdrop-blur-sm"
        onClick={onClose}
        aria-label="Close regulatory detail"
      />
      <aside className="regulatory-drawer relative z-10 h-full w-full max-w-2xl overflow-y-auto border-l bg-card shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b bg-card/95 p-5 backdrop-blur">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={selection.framework === "UU PDP" ? "default" : "blue"}
              >
                {selection.framework}
              </Badge>
              <Badge variant={severityColor(selection.severity) as never}>
                {selection.severity}
              </Badge>
              {selection.contextual && (
                <Badge variant="outline">Readiness context</Badge>
              )}
            </div>
            <h2 className="mt-3 text-lg font-semibold">
              {selection.control}: {article.title}
            </h2>
            <p className="mt-1 text-xs text-muted-foreground">
              {selection.findings.length} linked validated findings
            </p>
          </div>
          <Button
            size="icon"
            variant="ghost"
            onClick={onClose}
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="space-y-5 p-5">
          <DrawerSection title="Regulation Description" icon={BookOpen}>
            <p className="text-sm leading-6">{article.description}</p>
            <p className="mt-2 text-xs text-muted-foreground">
              Source: {article.source}
            </p>
          </DrawerSection>
          <DrawerSection title="Why This Was Triggered" icon={CircleAlert}>
            <p className="text-sm leading-6">
              {finding
                ? finding.description.split("\n\n")[0]
                : "No validated finding is mapped to this cell. This regulatory context is presented for readiness review only."}
            </p>
            {finding && (
              <p className="mt-2 text-xs text-muted-foreground">
                Affected endpoint: {finding.endpoint_url ?? finding.endpoint_id}
              </p>
            )}
          </DrawerSection>
          <DrawerSection title="Violation Type" icon={ShieldAlert}>
            <div className="flex flex-wrap gap-2">
              {(selection.findings.length
                ? selection.findings.map((item) =>
                    item.finding_type.replace(/_/g, " "),
                  )
                : ["No established violation"]
              )
                .slice(0, 5)
                .map((item) => (
                  <Badge key={item} variant="outline" className="capitalize">
                    {item}
                  </Badge>
                ))}
            </div>
          </DrawerSection>
          <DrawerSection title="Affected Personal Data" icon={Fingerprint}>
            <div className="flex flex-wrap gap-2">
              {pii.length ? (
                pii.map((item) => (
                  <Badge variant="amber" key={item}>
                    {item}
                  </Badge>
                ))
              ) : (
                <span className="text-sm text-muted-foreground">
                  No personal-data type identified in recorded evidence.
                </span>
              )}
            </div>
          </DrawerSection>
          <DrawerSection title="Compliance Risk" icon={Gavel}>
            <div className="grid gap-3 sm:grid-cols-3">
              {[
                { label: "Regulatory severity", value: selection.severity },
                {
                  label: "Privacy impact",
                  value: impacts?.privacy_risk ?? "Analyst review",
                },
                {
                  label: "Legal risk",
                  value: impacts?.legal_risk ?? "Not determined",
                },
              ].map((risk) => (
                <div className="rounded-md border p-3" key={risk.label}>
                  <p className="text-xs text-muted-foreground">{risk.label}</p>
                  <p className="mt-2 text-xs font-medium capitalize">
                    {risk.value}
                  </p>
                </div>
              ))}
            </div>
          </DrawerSection>
          <DrawerSection title="Business Impact" icon={TriangleAlert}>
            <p className="text-sm">
              {impacts?.business_risk ??
                "No confirmed business impact recorded for this contextual control."}
            </p>
            {finding && (
              <div className="mt-3 flex flex-wrap gap-2">
                {[
                  "Regulatory investigation risk",
                  "Customer trust impact",
                  "Remediation workload",
                ].map((item) => (
                  <Badge key={item} variant="outline">
                    {item}
                  </Badge>
                ))}
              </div>
            )}
          </DrawerSection>
          <DrawerSection title="Technical Mapping" icon={Layers3}>
            <div className="flex flex-wrap gap-2">
              {mappings.map((item) => (
                <Badge variant="blue" key={item}>
                  {item}
                </Badge>
              ))}
            </div>
          </DrawerSection>
          <DrawerSection title="Evidence of Violation" icon={FileSearch}>
            {loading ? (
              <Skeleton className="h-36" />
            ) : evidence ? (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <Badge variant="emerald">Immutable HTTP evidence</Badge>
                  <span className="font-mono">{evidence.immutable_id}</span>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <EvidenceBlock title="Request" data={evidence.raw_request} />
                  <EvidenceBlock
                    title="Response"
                    data={evidence.raw_response}
                  />
                </div>
                <p className="break-all font-mono text-xs text-muted-foreground">
                  SHA-256: {evidence.evidence_hash}
                </p>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                {evidenceError ??
                  "No evidence is attached to this contextual control."}
              </p>
            )}
          </DrawerSection>
          <DrawerSection title="Recommended Controls" icon={ShieldCheck}>
            <div className="flex flex-wrap gap-2">
              {controls.map((item) => (
                <Badge key={item} variant="emerald">
                  {item}
                </Badge>
              ))}
            </div>
          </DrawerSection>
        </div>
      </aside>
    </div>
  );
}

function DrawerSection({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: LucideIcon;
  children: ReactNode;
}) {
  return (
    <section className="rounded-md border bg-background/35 p-4">
      <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <Icon className="h-4 w-4 text-primary" />
        {title}
      </h3>
      {children}
    </section>
  );
}

function EvidenceBlock({
  title,
  data,
}: {
  title: string;
  data: Record<string, unknown>;
}) {
  return (
    <div>
      <p className="mb-1 text-xs font-medium">{title}</p>
      <pre className="scrollbar-subtle h-36 overflow-auto rounded-md bg-muted/60 p-2 font-mono text-[11px] leading-5">
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );
}

function BreachScenarioModal({
  findings,
  rows,
  onClose,
}: {
  findings: FindingResponse[];
  rows: IntelligenceRow[];
  onClose: () => void;
}) {
  const severity = highestSeverity(findings);
  const systems = [
    ...new Set(
      findings.map((item) => {
        try {
          return new URL(item.endpoint_url ?? "").host;
        } catch {
          return "Recorded application endpoint";
        }
      }),
    ),
  ].slice(0, 4);
  const articles = rows
    .filter((row) => row.findingCount > 0)
    .map((row) => `${row.framework} ${row.control}`);
  const path = [
    "Public surface",
    "Validated weakness",
    "Protected data access",
    "Regulatory assessment",
    "Notification review",
  ];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button
        className="absolute inset-0 bg-background/80 backdrop-blur"
        onClick={onClose}
        aria-label="Close simulation"
      />
      <Card className="scenario-modal relative z-10 max-h-[92vh] w-full max-w-4xl overflow-y-auto border-primary/20">
        <CardHeader className="border-b">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-primary">
                <Activity className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase">
                  Scenario model only
                </span>
              </div>
              <CardTitle className="mt-3">
                Data Breach Impact Simulation
              </CardTitle>
              <CardDescription className="mt-2">
                Models regulatory consequences from recorded findings. No
                requests are sent to the target.
              </CardDescription>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-5 p-5">
          <div className="grid gap-3 md:grid-cols-4">
            {[
              {
                label: "Modelled severity",
                value: findings.length ? severity : "unavailable",
              },
              { label: "Impacted systems", value: String(systems.length) },
              { label: "Exposed records", value: "Not enumerated" },
              { label: "Notification review", value: "3 x 24 hours*" },
            ].map((item) => (
              <div
                key={item.label}
                className={cn(
                  "rounded-md border p-3",
                  item.label === "Modelled severity" &&
                    findings.length &&
                    severitySurface[severity],
                )}
              >
                <p className="text-xs text-muted-foreground">{item.label}</p>
                <p className="mt-2 text-sm font-semibold capitalize">
                  {item.value}
                </p>
              </div>
            ))}
          </div>
          <div className="flex flex-col gap-2 md:flex-row md:items-center">
            {path.map((step, index) => (
              <div key={step} className="contents">
                <div className="scenario-node flex-1 rounded-md border bg-background p-3 text-center text-xs font-medium">
                  {step}
                </div>
                {index < path.length - 1 && (
                  <ArrowRight className="h-4 w-4 shrink-0 self-center text-primary rotate-90 md:rotate-0" />
                )}
              </div>
            ))}
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-md border p-4">
              <p className="text-sm font-semibold">Impacted systems</p>
              <div className="mt-3 space-y-2 text-sm">
                {(systems.length
                  ? systems
                  : ["No accepted evidence to model"]
                ).map((item) => (
                  <p
                    key={item}
                    className="flex items-center gap-2 text-muted-foreground"
                  >
                    <Database className="h-3.5 w-3.5 text-primary" />
                    {item}
                  </p>
                ))}
              </div>
            </div>
            <div className="rounded-md border p-4">
              <p className="text-sm font-semibold">
                Regulatory impact under review
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {(articles.length
                  ? articles
                  : ["No mapped violation established"]
                ).map((item) => (
                  <Badge
                    key={item}
                    variant={articles.length ? "amber" : "outline"}
                  >
                    {item}
                  </Badge>
                ))}
              </div>
              <p className="mt-4 text-xs text-muted-foreground">
                * UU PDP Pasal 46 notification timing applies after confirmation
                of a qualifying Personal Data protection failure. This model is
                not a legal determination.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ComplianceScopeHeader({
  targets,
  selectedTargetId,
  priorityCount,
  onTargetChange,
  onSimulate,
}: {
  targets: TargetSummary[];
  selectedTargetId: string;
  priorityCount: number | null;
  onTargetChange: (targetId: string) => void;
  onSimulate: () => void;
}) {
  const selectedTarget = targets.find(
    (target) => target.id === selectedTargetId,
  );

  return (
    <Card className="compliance-surface overflow-hidden">
      <CardContent className="flex flex-col justify-between gap-4 p-5 xl:flex-row xl:items-center">
        <div className="flex items-start gap-3">
          <div className="rounded-md border border-primary/25 bg-primary/10 p-3 text-primary">
            <Scale className="h-6 w-6" />
          </div>
          <div>
            <h2 className="text-xl font-semibold">
              Compliance Intelligence Center
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              UU PDP governance, privacy exposure, regulatory mapping, and audit
              readiness in one evidence-led view.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Badge variant="emerald">
                <ShieldCheck className="mr-1 h-3 w-3" /> Evidence linked
              </Badge>
              <Badge variant="blue">
                <ScrollText className="mr-1 h-3 w-3" /> UU PDP / ASVS
              </Badge>
              <Badge variant={priorityCount ? "amber" : "outline"}>
                <AlertTriangle className="mr-1 h-3 w-3" />{" "}
                {priorityCount === null
                  ? "Loading risks"
                  : `${priorityCount} priority risks`}
              </Badge>
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <label className="min-w-[18rem] space-y-1.5">
            <span className="block text-xs font-medium uppercase text-muted-foreground">
              Target Website Scope
            </span>
            <Select
              value={selectedTargetId}
              onChange={(event) => onTargetChange(event.target.value)}
              aria-label="Select target website for compliance intelligence"
            >
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.base_url} | {compactId(target.id)} | {target.findings}{" "}
                  findings
                </option>
              ))}
            </Select>
            <span className="block max-w-[28rem] truncate text-xs text-muted-foreground">
              Isolated evidence view:{" "}
              {selectedTarget?.base_url ?? "Select a target"}{" "}
              {selectedTarget ? `| ${compactId(selectedTarget.id)}` : ""}
            </span>
          </label>
          <Button
            variant="outline"
            className="shrink-0 border-primary/30"
            disabled={priorityCount === null}
            onClick={onSimulate}
          >
            <Activity className="h-4 w-4 text-primary" />
            Simulate Data Breach
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// Memoized so opening the drawer/modal or switching selection state in
// CompliancePage does not re-render these expensive panels when their data
// props are unchanged.
const ComplianceGauge = memo(ComplianceGaugeImpl);
const ComplianceHeatmap = memo(ComplianceHeatmapImpl);
const SensitiveDataPanel = memo(SensitiveDataPanelImpl);
const BreachReadiness = memo(BreachReadinessImpl);
const ExposurePath = memo(ExposurePathImpl);
const MappingMatrix = memo(MappingMatrixImpl);
const MitreContext = memo(MitreContextImpl);
const WorkflowTimeline = memo(WorkflowTimelineImpl);
const EvidenceCollection = memo(EvidenceCollectionImpl);
const ExecutiveSummary = memo(ExecutiveSummaryImpl);

export { CompliancePage as default };
export function CompliancePage() {
  const {
    data: targets,
    loading: targetsLoading,
    error: targetsError,
  } = useApi(api.targets, [], "targets");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selection, setSelection] = useState<Selection | null>(null);
  const [simulationOpen, setSimulationOpen] = useState(false);

  useEffect(() => {
    if (!targets?.length) return;
    if (
      !selectedTargetId ||
      !targets.some((target) => target.id === selectedTargetId)
    ) {
      setSelectedTargetId(
        (targets.find((target) => target.findings > 0) ?? targets[0]).id,
      );
    }
  }, [selectedTargetId, targets]);

  useEffect(() => {
    setSelection(null);
    setSimulationOpen(false);
  }, [selectedTargetId]);

  const { data, loading, error } =
    useApi(async (): Promise<ComplianceData | null> => {
      if (!selectedTargetId) return null;
      const [
        compliance,
        findings,
        dashboard,
        remediations,
        auditLogs,
        reports,
      ] = await Promise.all([
        api.compliance(selectedTargetId),
        api.findings(undefined, selectedTargetId),
        api.dashboard(selectedTargetId),
        api
          .remediations(selectedTargetId)
          .catch(() => [] as RemediationSummary[]),
        api.auditLogs(selectedTargetId).catch(() => [] as AuditLogResponse[]),
        api.reports(selectedTargetId).catch(() => [] as ReportResponse[]),
      ]);
      return {
        targetId: selectedTargetId,
        dashboard,
        findings,
        mappings: compliance.mappings,
        remediations,
        auditLogs,
        reports,
      };
    }, [selectedTargetId], `compliance-${selectedTargetId}`);

  const rows = useMemo(
    () => mappingRows(data?.mappings ?? [], data?.findings ?? []),
    [data?.findings, data?.mappings],
  );
  const evidenceFindings = useMemo(
    () =>
      [...(data?.findings ?? [])].sort((a, b) => b.risk_score - a.risk_score),
    [data?.findings],
  );

  if (targetsLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-20" />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton key={index} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }
  if (targetsError) {
    return (
      <EmptyState title="Target scope unavailable" description={targetsError} />
    );
  }
  if (!targets?.length) {
    return (
      <EmptyState
        title="No scanned target websites"
        description="Start a scan to create a target-specific compliance intelligence view."
      />
    );
  }
  if (!selectedTargetId) {
    return <Skeleton className="h-80" />;
  }
  if (error) {
    return (
      <div className="space-y-5">
        <ComplianceScopeHeader
          targets={targets}
          selectedTargetId={selectedTargetId}
          priorityCount={null}
          onTargetChange={setSelectedTargetId}
          onSimulate={() => setSimulationOpen(true)}
        />
        <EmptyState
          title="Compliance intelligence unavailable"
          description={error}
        />
      </div>
    );
  }
  if (loading || !data || data.targetId !== selectedTargetId) {
    return (
      <div className="space-y-5">
        <ComplianceScopeHeader
          targets={targets}
          selectedTargetId={selectedTargetId}
          priorityCount={null}
          onTargetChange={setSelectedTargetId}
          onSimulate={() => setSimulationOpen(true)}
        />
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton key={index} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  const privacyFindings = data.findings.filter(
    (finding) =>
      affectedData([finding]).length > 0 ||
      finding.compliance.some((item) => item.framework === "UU PDP"),
  );
  const priorityFindings = data.findings.filter((finding) =>
    ["critical", "high"].includes(finding.severity.toLowerCase()),
  );
  const criticalFindings = data.findings.filter(
    (finding) => finding.severity.toLowerCase() === "critical",
  );
  const openGaps = data.findings.filter(
    (finding) => finding.status !== "Closed",
  ).length;
  const readiness = readinessScore(
    readinessControls(data.findings, data.auditLogs, data.reports),
  );
  return (
    <div className="compliance-grid space-y-5">
      <ComplianceScopeHeader
        targets={targets}
        selectedTargetId={selectedTargetId}
        priorityCount={priorityFindings.length}
        onTargetChange={setSelectedTargetId}
        onSimulate={() => setSimulationOpen(true)}
      />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
        <SignalCard
          title="PDP Compliance Score"
          value={data.dashboard.compliance_score}
          suffix="%"
          detail="Control posture"
          severity={data.dashboard.compliance_score >= 75 ? "low" : "high"}
          icon={ShieldCheck}
        />
        <SignalCard
          title="Privacy Impact"
          value={privacyFindings.length}
          detail="Mapped signals"
          severity={
            privacyFindings.length ? highestSeverity(privacyFindings) : "low"
          }
          icon={Fingerprint}
          onClick={() =>
            setSelection({
              framework: "UU PDP",
              control: "Pasal 35",
              severity: highestSeverity(privacyFindings),
              findings: privacyFindings,
            })
          }
        />
        <SignalCard
          title="Compliance Gaps"
          value={openGaps}
          detail="Open findings"
          severity={openGaps ? highestSeverity(data.findings) : "low"}
          icon={ScrollText}
        />
        <SignalCard
          title="Breach Readiness"
          value={readiness}
          suffix="%"
          detail="Preparedness"
          severity={readiness >= 75 ? "low" : "medium"}
          icon={Siren}
          onClick={() =>
            setSelection({
              framework: "UU PDP",
              control: "Pasal 46 (Readiness Context)",
              severity: "info",
              findings: [],
              contextual: true,
            })
          }
        />
        <SignalCard
          title="Critical Findings"
          value={criticalFindings.length}
          detail="Urgent review"
          severity={criticalFindings.length ? "critical" : "low"}
          icon={ShieldAlert}
        />
        <SignalCard
          title="Regulated Data Exposure"
          value={privacyFindings.length}
          detail="Evidence events"
          severity={
            privacyFindings.length ? highestSeverity(privacyFindings) : "low"
          }
          icon={Database}
        />
      </div>

      <div className="grid items-start gap-4 2xl:grid-cols-[0.9fr_1.2fr]">
        <div className="space-y-4">
          <ComplianceGauge
            score={data.dashboard.compliance_score}
            findings={data.findings}
          />
          <SensitiveDataPanel findings={data.findings} />
        </div>
        <div className="space-y-4">
          <ComplianceHeatmap rows={rows} onSelect={setSelection} />
          <BreachReadiness
            findings={data.findings}
            auditLogs={data.auditLogs}
            reports={data.reports}
            remediations={data.remediations}
          />
        </div>
      </div>

      <ExecutiveSummary
        findings={data.findings}
        rows={rows}
        remediations={data.remediations}
      />

      <ExposurePath findings={data.findings} onSelect={setSelection} />

      <div className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
        <MappingMatrix rows={rows} onSelect={setSelection} />
        <MitreContext findings={data.findings} />
      </div>

      <WorkflowTimeline remediations={data.remediations} />

      <EvidenceCollection findings={evidenceFindings} onSelect={setSelection} />

      <Card>
        <CardContent className="flex flex-col justify-between gap-3 p-4 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <p>
            Regulatory descriptions are operational summaries for assessment
            use. Confirm legal conclusions against the official UU PDP text and
            counsel.
          </p>
          <a
            className="inline-flex shrink-0 items-center gap-1 text-primary hover:underline"
            href="https://peraturan.bpk.go.id/Home/Details/229798/uu-no-27-tahun-2022"
            target="_blank"
            rel="noreferrer"
          >
            Official UU PDP source <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </CardContent>
      </Card>

      <RegulatoryDrawer
        selection={selection}
        onClose={() => setSelection(null)}
      />
      {simulationOpen && (
        <BreachScenarioModal
          findings={data.findings}
          rows={rows}
          onClose={() => setSimulationOpen(false)}
        />
      )}
    </div>
  );
}

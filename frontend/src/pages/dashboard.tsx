import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BellRing,
  BookOpenCheck,
  Boxes,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Database,
  Eye,
  Fingerprint,
  Globe2,
  KeyRound,
  Layers3,
  LockKeyhole,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TimerReset,
  Waypoints,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

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
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import {
  apiDateTimestamp,
  cn,
  compactId,
  formatDate,
  formatNumber,
  formatRelativeTime,
} from "@/lib/utils";
import type {
  AuditLogResponse,
  ComplianceRow,
  DashboardResponse,
  EndpointInventory,
  FindingResponse,
  RemediationSummary,
  ReportResponse,
  ScanSummary,
  TargetSummary,
} from "@/types/api";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface DashboardData {
  dashboard: DashboardResponse;
  findings: FindingResponse[];
  scans: ScanSummary[];
  remediations: RemediationSummary[];
  targets: TargetSummary[];
  mappings: ComplianceRow[];
  auditLogs: AuditLogResponse[];
  reports: ReportResponse[];
  focusEndpoints: EndpointInventory[];
  focusScan: ScanSummary | null;
}

interface PrivacySignal {
  name: string;
  icon: LucideIcon;
  matches: FindingResponse[];
  severity: Severity;
}

interface ActivityItem {
  id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  detail: string;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const severityText: Record<Severity, string> = {
  critical: "text-red-600 dark:text-red-300",
  high: "text-orange-600 dark:text-orange-300",
  medium: "text-yellow-700 dark:text-yellow-300",
  low: "text-teal-700 dark:text-teal-300",
  info: "text-blue-600 dark:text-blue-300",
};

const severityPanel: Record<Severity, string> = {
  critical:
    "border-red-500/35 bg-red-500/10 shadow-[0_0_20px_rgba(239,68,68,0.12)]",
  high: "border-orange-500/30 bg-orange-500/10",
  medium: "border-yellow-500/30 bg-yellow-500/10",
  low: "border-teal-500/25 bg-teal-500/10",
  info: "border-blue-500/25 bg-blue-500/10",
};

function normalizedSeverity(value: string | undefined): Severity {
  const candidate = value?.toLowerCase();
  if (
    candidate === "critical" ||
    candidate === "high" ||
    candidate === "medium" ||
    candidate === "low"
  ) {
    return candidate;
  }
  return "info";
}

function isOpen(finding: FindingResponse) {
  return !["closed", "false positive"].includes(finding.status.toLowerCase());
}

function isExecutiveSignal(finding: FindingResponse) {
  const evidence = finding.evidence_summary;
  const discoveryTypes = new Set([
    "internal_api_discovery",
    "protected_internal_surface",
    "segmentation_exposure",
    "graphql_schema_exposure",
    "modern_vuln_bank_attack_surface",
    "jwt_observed",
  ]);
  const validationMode = String(evidence.validation_mode ?? "");
  return (
    finding.confidence >= 70 &&
    !discoveryTypes.has(finding.finding_type) &&
    evidence.confidence_level !== "LOW_CONFIDENCE" &&
    evidence.false_positive_likelihood !== "HIGH" &&
    evidence.exploitability_assessment !== "HEURISTIC_SIGNAL" &&
    evidence.exploitability_assessment !== "ATTACK_SURFACE_IDENTIFIED" &&
    ![
      "static_javascript_analysis",
      "passive_endpoint_discovery",
      "passive_metadata_discovery",
    ].includes(validationMode)
  );
}

function strongest(findings: FindingResponse[]): Severity {
  return findings.reduce<Severity>((current, finding) => {
    const severity = normalizedSeverity(finding.severity);
    return severityRank[severity] > severityRank[current] ? severity : current;
  }, "info");
}

function severityBadge(severity: Severity) {
  if (severity === "critical") return "destructive" as const;
  if (severity === "high") return "amber" as const;
  if (severity === "medium") return "blue" as const;
  if (severity === "low") return "emerald" as const;
  return "outline" as const;
}

function scanStat(scan: ScanSummary, modernKey: string, legacyKey?: string) {
  return Number(
    scan.stats[modernKey] ?? (legacyKey ? scan.stats[legacyKey] : 0) ?? 0,
  );
}

function scanRisk(scan: ScanSummary, findings: FindingResponse[]): Severity {
  if (findings.length) return strongest(findings);
  const score = scanStat(scan, "risk_score");
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return score > 0 ? "low" : "info";
}

function scannerMode(scan: ScanSummary) {
  const diagnostics = scan.stats.diagnostics as
    | Record<string, unknown>
    | undefined;
  const authentication = diagnostics?.authentication as
    | Record<string, unknown>
    | undefined;
  if (authentication?.status === "authenticated")
    return "Authenticated Grey Box";
  const validators = scan.stats.active_validations as string[] | undefined;
  return validators?.length ? "Safe Validation" : "Discovery";
}

function primaryExposure(findings: FindingResponse[]) {
  const values = findings
    .map((finding) => `${finding.finding_type} ${finding.title}`.toLowerCase())
    .join(" ");
  if (/bola|idor|access control/.test(values)) return "Access Control Failure";
  if (/auth|session|jwt|token|login/.test(values))
    return "Authentication Weakness";
  if (/pii|privacy|nik|npwp|financial/.test(values))
    return "Personal Data Exposure";
  if (/sql/.test(values)) return "Injection Validation";
  return findings.length
    ? "Validated Security Exposure"
    : "No accepted exposure";
}

function highestMapping(mappings: ComplianceRow[]) {
  const selected = [...mappings].sort(
    (a, b) => b.finding_count - a.finding_count,
  )[0];
  return selected
    ? `${selected.framework} ${selected.article_or_control}`
    : "No active mapping";
}

function evidenceCount(findings: FindingResponse[]) {
  return findings.filter((finding) =>
    Boolean(finding.evidence_summary.evidence_id),
  ).length;
}

function privacySignals(findings: FindingResponse[]): PrivacySignal[] {
  const definitions: Array<{ name: string; icon: LucideIcon; tokens: RegExp }> =
    [
      { name: "NIK", icon: Fingerprint, tokens: /\bnik\b|national identity/ },
      {
        name: "Biometrics",
        icon: Fingerprint,
        tokens: /biometric|fingerprint|faceprint/,
      },
      {
        name: "Financial Data",
        icon: Database,
        tokens: /financial|bank account|card number|npwp/,
      },
      { name: "Email", icon: Eye, tokens: /email|e-mail/ },
      {
        name: "Phone Number",
        icon: Eye,
        tokens: /phone|telephone|mobile number/,
      },
      {
        name: "Authentication Data",
        icon: KeyRound,
        tokens: /authentication|token|jwt|session|password|login/,
      },
    ];
  return definitions.map(({ name, icon, tokens }) => {
    const matches = findings.filter((finding) =>
      tokens.test(JSON.stringify(finding).toLowerCase()),
    );
    return {
      name,
      icon,
      matches,
      severity: matches.length ? strongest(matches) : "low",
    };
  });
}

function endpointMatches(endpoint: EndpointInventory, tokens: RegExp) {
  return tokens.test(
    `${endpoint.url} ${JSON.stringify(endpoint.classifications)}`.toLowerCase(),
  );
}

function validationConfidence(findings: FindingResponse[]) {
  if (!findings.length) return 0;
  return Math.round(
    findings.reduce((sum, finding) => sum + finding.confidence, 0) /
      findings.length,
  );
}

function GovernanceMetric({
  title,
  value,
  detail,
  icon: Icon,
  severity = "info",
}: {
  title: string;
  value: string | number;
  detail: string;
  icon: LucideIcon;
  severity?: Severity;
}) {
  return (
    <Card
      className={cn(
        "dashboard-surface dashboard-metric group overflow-hidden",
        severity === "critical" && "dashboard-critical",
      )}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <p className="text-xs font-medium uppercase text-muted-foreground">
            {title}
          </p>
          <div
            className={cn(
              "rounded-md border p-2",
              severityPanel[severity],
              severityText[severity],
            )}
          >
            <Icon className="h-4 w-4" />
          </div>
        </div>
        <p
          className={cn(
            "mt-3 text-2xl font-semibold tabular-nums",
            severity === "critical" && severityText.critical,
          )}
        >
          {value}
        </p>
        <p className="mt-1 truncate text-xs text-muted-foreground">{detail}</p>
        <div
          className={cn(
            "mt-3 h-px w-full bg-gradient-to-r from-transparent via-primary/35 to-transparent",
            severity === "critical" && "via-red-500/55",
          )}
        />
      </CardContent>
    </Card>
  );
}

function RiskPostureBanner({
  risk,
  regulation,
  exposure,
  critical,
}: {
  risk: Severity;
  regulation: string;
  exposure: string;
  critical: number;
}) {
  return (
    <Card
      className={cn(
        "dashboard-risk dashboard-surface overflow-hidden",
        risk === "critical" && "dashboard-critical",
      )}
    >
      <CardContent className="flex flex-col gap-5 p-5 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-start gap-4">
          <div
            className={cn(
              "dashboard-beacon mt-1 rounded-md border p-3",
              severityPanel[risk],
              severityText[risk],
            )}
          >
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <p className="text-xs font-medium uppercase text-muted-foreground">
              Global Risk Posture
            </p>
            <div className="mt-1 flex flex-wrap items-center gap-3">
              <h2 className="text-2xl font-semibold">
                Current Organizational Risk: {risk.toUpperCase()}
              </h2>
              <Badge
                variant={severityBadge(risk)}
                className={
                  risk === "critical" ? "dashboard-alert-pulse" : undefined
                }
              >
                {critical} active critical
              </Badge>
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              Accepted validation findings and regulatory mappings across
              organization-owned assessment targets.
            </p>
          </div>
        </div>
        <div className="grid shrink-0 gap-3 sm:grid-cols-2 xl:min-w-[33rem]">
          <div className="rounded-md border border-border/70 bg-background/45 p-3">
            <p className="text-xs text-muted-foreground">Primary Exposure</p>
            <p className="mt-1 text-sm font-medium">{exposure}</p>
          </div>
          <div className="rounded-md border border-border/70 bg-background/45 p-3">
            <p className="text-xs text-muted-foreground">
              Most Impacted Regulation
            </p>
            <p className="mt-1 text-sm font-medium">{regulation}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ScanExpandedPreview({
  scan,
  findings,
  remediations,
}: {
  scan: ScanSummary;
  findings: FindingResponse[];
  remediations: RemediationSummary[];
}) {
  const { data: endpoints, loading } = useApi(
    () => api.scanEndpoints(scan.id),
    [scan.id],
  );
  const evidence = evidenceCount(findings);
  const privacy = privacySignals(findings).filter(
    (signal) => signal.matches.length > 0,
  ).length;
  const openRemediation = remediations.filter(
    (item) =>
      findings.some((finding) => finding.id === item.finding_id) &&
      item.status !== "Closed",
  ).length;
  const impactedMappings = new Set(
    findings.flatMap((finding) =>
      finding.compliance.map(
        (entry) => `${entry.framework} ${entry.article_or_control}`,
      ),
    ),
  );
  const endpointAssets = new Set(
    (endpoints ?? []).map((endpoint) => endpoint.url),
  ).size;

  return (
    <div className="dashboard-expand grid gap-3 p-4 lg:grid-cols-[1.05fr_1fr]">
      <div className="grid gap-3 sm:grid-cols-3">
        {(["critical", "high", "medium", "low"] as Severity[]).map(
          (severity) => {
            const total = findings.filter(
              (finding) => normalizedSeverity(finding.severity) === severity,
            ).length;
            return (
              <div
                key={severity}
                className={cn("rounded-md border p-3", severityPanel[severity])}
              >
                <p className="text-xs capitalize text-muted-foreground">
                  {severity}
                </p>
                <p
                  className={cn(
                    "mt-1 text-xl font-semibold",
                    severityText[severity],
                  )}
                >
                  {total}
                </p>
              </div>
            );
          },
        )}
        <div className="rounded-md border bg-background/50 p-3">
          <p className="text-xs text-muted-foreground">Affected assets</p>
          <p className="mt-1 text-xl font-semibold">
            {loading ? "-" : formatNumber(endpointAssets)}
          </p>
        </div>
        <div className="rounded-md border bg-background/50 p-3">
          <p className="text-xs text-muted-foreground">Evidence records</p>
          <p className="mt-1 text-xl font-semibold">{evidence}</p>
        </div>
      </div>
      <div className="space-y-3 rounded-md border bg-background/40 p-4">
        <div className="flex items-center justify-between">
          <p className="text-sm font-medium">Validation Preview</p>
          <Badge variant={severityBadge(scanRisk(scan, findings))}>
            {scanRisk(scan, findings)} risk
          </Badge>
        </div>
        <div className="grid gap-2 text-sm sm:grid-cols-2">
          <p className="text-muted-foreground">
            Compliance impact{" "}
            <span className="float-right font-medium text-foreground">
              {impactedMappings.size} controls
            </span>
          </p>
          <p className="text-muted-foreground">
            Privacy signals{" "}
            <span className="float-right font-medium text-foreground">
              {privacy}
            </span>
          </p>
          <p className="text-muted-foreground">
            Open remediation{" "}
            <span className="float-right font-medium text-foreground">
              {openRemediation}
            </span>
          </p>
          <p className="text-muted-foreground">
            Validation confidence{" "}
            <span className="float-right font-medium text-foreground">
              {validationConfidence(findings) || 0}%
            </span>
          </p>
        </div>
        <Button variant="outline" size="sm" asChild className="mt-1">
          <Link to={`/scans/${scan.id}`}>
            <Eye className="h-4 w-4" />
            Inspect endpoints and evidence
          </Link>
        </Button>
      </div>
    </div>
  );
}

function RecentScansConsole({
  scans,
  findings,
  remediations,
}: {
  scans: ScanSummary[];
  findings: FindingResponse[];
  remediations: RemediationSummary[];
}) {
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

  return (
    <Card className="dashboard-surface overflow-hidden">
      <CardHeader className="border-b bg-card/55 pb-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Radar className="h-4 w-4 text-primary" />
              Recent Scans
            </CardTitle>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {scans.length ? (
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead className="pl-5">Scan / Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Progress</TableHead>
                <TableHead>Coverage</TableHead>
                <TableHead>Impact</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Scanner Type</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="pr-5 text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => {
                const scanFindings = findings.filter(
                  (finding) => finding.scan_id === scan.id,
                );
                const risk = scanRisk(scan, scanFindings);
                const progress = scanStat(scan, "progress_percentage");
                const mappings = new Set(
                  scanFindings.flatMap((finding) =>
                    finding.compliance.map((item) => item.article_or_control),
                  ),
                ).size;
                const confidence = validationConfidence(scanFindings);
                const isExpanded = expandedScanId === scan.id;
                return (
                  <Fragment key={scan.id}>
                    <TableRow
                      className={cn(
                        "dashboard-scan-row cursor-pointer",
                        isExpanded && "bg-primary/[0.05]",
                      )}
                      onClick={() =>
                        setExpandedScanId(isExpanded ? null : scan.id)
                      }
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setExpandedScanId(isExpanded ? null : scan.id);
                        }
                      }}
                    >
                      <TableCell className="pl-5">
                        <div className="flex items-center gap-2">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-primary" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                          <div className="min-w-0">
                            <p className="font-mono text-xs font-medium">
                              {compactId(scan.id)}
                            </p>
                            <p className="max-w-44 truncate text-xs text-muted-foreground">
                              {scan.target_url ?? "Target unavailable"}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            scan.status === "completed"
                              ? "emerald"
                              : scan.status === "failed"
                                ? "destructive"
                                : "blue"
                          }
                        >
                          {scan.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={severityBadge(risk)}
                          className={
                            risk === "critical"
                              ? "dashboard-alert-pulse"
                              : undefined
                          }
                        >
                          {risk}
                        </Badge>
                      </TableCell>
                      <TableCell className="min-w-36">
                        <div className="flex items-center gap-2">
                          <Progress
                            value={progress}
                            className="dashboard-progress"
                          />
                          <span className="w-9 text-right text-xs tabular-nums text-muted-foreground">
                            {Math.round(progress)}%
                          </span>
                        </div>
                        <p className="mt-1 truncate text-xs text-muted-foreground">
                          {String(scan.stats.phase ?? "-")}
                        </p>
                      </TableCell>
                      <TableCell className="text-xs">
                        <p className="font-medium">
                          {formatNumber(
                            scanStat(scan, "endpoints_discovered", "endpoints"),
                          )}{" "}
                          endpoints
                        </p>
                        <p className="text-muted-foreground">
                          {formatNumber(
                            scanStat(scan, "findings_discovered", "findings"),
                          )}{" "}
                          findings
                        </p>
                      </TableCell>
                      <TableCell>
                        <p className="text-sm font-medium">
                          {mappings || scanStat(scan, "compliance_impact")}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          controls
                        </p>
                      </TableCell>
                      <TableCell className="text-sm tabular-nums">
                        {confidence ? `${confidence}%` : "-"}
                      </TableCell>
                      <TableCell>
                        <p className="max-w-36 truncate text-xs">
                          {scannerMode(scan)}
                        </p>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs">
                        <p>{formatDate(scan.created_at)}</p>
                        <p className="text-muted-foreground">
                          {formatRelativeTime(scan.created_at)}
                        </p>
                      </TableCell>
                      <TableCell className="pr-5 text-right">
                        <Button
                          variant="outline"
                          size="icon"
                          className="dashboard-open-button"
                          asChild
                          onClick={(event) => event.stopPropagation()}
                        >
                          <Link
                            to={`/scans/${scan.id}`}
                            aria-label={`Open scan ${compactId(scan.id)}`}
                          >
                            <Eye className="h-4 w-4" />
                          </Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="bg-muted/20 hover:bg-muted/20">
                        <TableCell colSpan={10} className="p-0">
                          <ScanExpandedPreview
                            scan={scan}
                            findings={scanFindings}
                            remediations={remediations}
                          />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        ) : (
          <div className="p-10 text-center">
            <p className="font-medium">No validation activity yet</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Create a guarded scan to populate operational telemetry.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ActivityFeed({ items }: { items: ActivityItem[] }) {
  return (
    <Card className="dashboard-surface h-full">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-4 w-4 text-primary" />
          Security Activity Feed
        </CardTitle>
        <CardDescription>
          Latest validation, remediation, and audit signals.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-1">
        {items.length ? (
          items.slice(0, 8).map((item) => (
            <div
              key={item.id}
              className="dashboard-feed flex gap-3 border-l py-2 pl-4"
            >
              <span
                className={cn(
                  "dashboard-feed-dot mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full",
                  severityPanel[item.severity],
                )}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={severityBadge(item.severity)}>
                    {item.severity}
                  </Badge>
                  <p className="truncate text-sm font-medium">{item.title}</p>
                </div>
                <p className="mt-1 truncate text-xs text-muted-foreground">
                  {item.detail}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {formatRelativeTime(item.timestamp)} |{" "}
                  {formatDate(item.timestamp)}
                </p>
              </div>
            </div>
          ))
        ) : (
          <p className="rounded-md border border-dashed p-5 text-sm text-muted-foreground">
            No operational activity available.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function AttackSurfaceOverview({
  endpoints,
  targets,
  scan,
}: {
  endpoints: EndpointInventory[];
  targets: TargetSummary[];
  scan: ScanSummary | null;
}) {
  const surfaces = [
    {
      name: "Public Endpoints",
      icon: Globe2,
      value: endpoints.filter((item) => endpointMatches(item, /public/)).length,
      severity: "medium" as Severity,
    },
    {
      name: "APIs",
      icon: Layers3,
      value: endpoints.filter((item) => endpointMatches(item, /api|graphql/))
        .length,
      severity: "high" as Severity,
    },
    {
      name: "Admin Panels",
      icon: LockKeyhole,
      value: endpoints.filter((item) =>
        endpointMatches(item, /admin|manage|dashboard/),
      ).length,
      severity: "high" as Severity,
    },
    {
      name: "Auth Surfaces",
      icon: KeyRound,
      value: endpoints.filter((item) =>
        endpointMatches(item, /auth|login|register|signin/),
      ).length,
      severity: "medium" as Severity,
    },
    {
      name: "Cloud Signals",
      icon: Boxes,
      value: endpoints.filter((item) =>
        endpointMatches(item, /bucket|storage|cloud|s3|azure|gcp/),
      ).length,
      severity: "medium" as Severity,
    },
    {
      name: "Exposed Services",
      icon: Server,
      value: endpoints.filter((item) =>
        endpointMatches(
          item,
          /debug|health|metrics|swagger|openapi|actuator|status/,
        ),
      ).length,
      severity: "high" as Severity,
    },
    {
      name: "Internet Targets",
      icon: Server,
      value: targets.filter((target) => target.is_active).length,
      severity: "info" as Severity,
    },
  ];
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <Waypoints className="h-4 w-4 text-primary" />
          Attack Surface Overview
        </CardTitle>
        <CardDescription>
          {scan
            ? `Endpoint classification from latest assessed scan ${compactId(scan.id)}.`
            : "No endpoint inventory is available yet."}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-2">
        {surfaces.map(({ name, icon: Icon, value, severity }) => (
          <div
            key={name}
            className="dashboard-mini flex items-center justify-between gap-3 rounded-md border p-3"
          >
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Icon
                className={cn("h-4 w-4", value ? severityText[severity] : "")}
              />
              {name}
            </div>
            <span
              className={cn(
                "text-base font-semibold tabular-nums",
                value && severityText[severity],
              )}
            >
              {formatNumber(value)}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function PrivacyExposure({ signals }: { signals: PrivacySignal[] }) {
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-primary" />
          Privacy Exposure Intelligence
        </CardTitle>
        <CardDescription>
          Personal-data signals observed in accepted finding evidence.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-2">
        {signals.map(({ name, icon: Icon, matches, severity }) => (
          <div
            key={name}
            className={cn(
              "rounded-md border p-3",
              matches.length ? severityPanel[severity] : "bg-background/40",
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <p className="flex items-center gap-2 text-sm font-medium">
                <Icon className="h-4 w-4" />
                {name}
              </p>
              <Badge
                variant={matches.length ? severityBadge(severity) : "emerald"}
              >
                {matches.length ? severity : "clear"}
              </Badge>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Evidence signals{" "}
              <span className="float-right font-medium text-foreground">
                {matches.length}
              </span>
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Records <span className="float-right">Not quantified</span>
            </p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function ExposurePath({
  findings,
  targets,
}: {
  findings: FindingResponse[];
  targets: TargetSummary[];
}) {
  const text = JSON.stringify(findings).toLowerCase();
  const nodes: Array<{
    name: string;
    icon: LucideIcon;
    observed: boolean;
    severity: Severity;
  }> = [
    {
      name: "Internet",
      icon: Globe2,
      observed: targets.length > 0,
      severity: "info",
    },
    {
      name: "Authentication Weakness",
      icon: LockKeyhole,
      observed: /auth|login|session|jwt|sqli_auth/.test(text),
      severity: "high",
    },
    {
      name: "Credential Abuse",
      icon: KeyRound,
      observed: /authentication bypass|token reuse|credential/.test(text),
      severity: "critical",
    },
    {
      name: "Sensitive API Access",
      icon: Server,
      observed: /bola|idor|api|access control/.test(text),
      severity: "high",
    },
    {
      name: "PII Exposure",
      icon: Fingerprint,
      observed: /pii|nik|npwp|personal data|privacy/.test(text),
      severity: "critical",
    },
    {
      name: "PDP Violation",
      icon: BookOpenCheck,
      observed: /uu pdp|pasal 35/.test(text),
      severity: "critical",
    },
  ];
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Workflow className="h-4 w-4 text-primary" />
              Exposure Path Context
            </CardTitle>
            <CardDescription className="mt-1">
              Evidence-linked governance sequence; not a claim of executed
              exploitation.
            </CardDescription>
          </div>
          <Badge variant="outline">Observed validation context</Badge>
        </div>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        <div className="flex min-w-[52rem] items-center gap-2">
          {nodes.map((node, index) => (
            <Fragment key={node.name}>
              <div
                className={cn(
                  "dashboard-node flex min-h-24 w-36 flex-col justify-between rounded-md border p-3",
                  node.observed ? severityPanel[node.severity] : "opacity-55",
                )}
              >
                <node.icon
                  className={cn(
                    "h-4 w-4",
                    node.observed && severityText[node.severity],
                  )}
                />
                <p className="mt-3 text-xs font-medium">{node.name}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {node.observed ? "Observed signal" : "No signal"}
                </p>
              </div>
              {index < nodes.length - 1 && (
                <ArrowRight
                  className={cn(
                    "dashboard-flow h-4 w-4 shrink-0",
                    node.observed && "text-primary",
                  )}
                />
              )}
            </Fragment>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ExecutiveInsights({
  findings,
  mappings,
  confidence,
}: {
  findings: FindingResponse[];
  mappings: ComplianceRow[];
  confidence: number;
}) {
  const openFindings = findings.filter(isOpen);
  const risk = strongest(openFindings);
  const recommendation =
    risk === "critical"
      ? "Prioritize immediate containment and re-validation of critical authorization or authentication findings."
      : openFindings.length
        ? "Assign remediation owners to accepted findings and schedule evidence-backed re-tests."
        : "Maintain scan coverage and evidence retention for audit readiness.";
  const narrative = openFindings.length
    ? `${openFindings.length} accepted unresolved findings indicate ${primaryExposure(openFindings).toLowerCase()} exposure affecting ${highestMapping(mappings)}.`
    : "No accepted unresolved finding currently changes the organizational governance posture.";

  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Executive Intelligence
          </CardTitle>
          <Badge variant="blue">Rules-based summary</Badge>
        </div>
        <CardDescription>
          Executive reading of accepted evidence and compliance mappings.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="rounded-md border border-primary/20 bg-primary/[0.06] p-4 text-sm leading-6">
          {narrative}
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">Priority action</p>
            <p className="mt-2 text-sm">{recommendation}</p>
          </div>
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">
              Evidence confidence indicator
            </p>
            <p className="mt-2 text-2xl font-semibold">{confidence}%</p>
            <p className="text-xs text-muted-foreground">
              Accepted findings; not breach probability
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function RemediationSla({
  findings,
  remediations,
  completion,
}: {
  findings: FindingResponse[];
  remediations: RemediationSummary[];
  completion: number;
}) {
  const openItems = remediations.filter((item) => item.status !== "Closed");
  const unresolvedCritical = findings.filter(
    (finding) =>
      isOpen(finding) && normalizedSeverity(finding.severity) === "critical",
  ).length;
  const statusValues = [
    "Open",
    "Assigned",
    "In Progress",
    "Re-Test",
    "Closed",
  ].map((status) => ({
    status,
    total: remediations.filter((item) => item.status === status).length,
  }));
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <TimerReset className="h-4 w-4 text-primary" />
          Remediation SLA Tracking
        </CardTitle>
        <CardDescription>
          Operational remediation state; SLA due dates are not configured in
          this MVP.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Closure progress</span>
          <span className="font-medium">{completion}%</span>
        </div>
        <Progress value={completion} className="dashboard-progress" />
        <div className="grid gap-2 sm:grid-cols-3">
          <div
            className={cn(
              "rounded-md border p-3",
              unresolvedCritical ? severityPanel.critical : severityPanel.low,
            )}
          >
            <p className="text-xs text-muted-foreground">Unresolved critical</p>
            <p className="mt-1 text-xl font-semibold">{unresolvedCritical}</p>
          </div>
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">Open items</p>
            <p className="mt-1 text-xl font-semibold">{openItems.length}</p>
          </div>
          <div className="rounded-md border p-3">
            <p className="text-xs text-muted-foreground">Overdue</p>
            <p className="mt-1 text-sm font-medium">Not measured</p>
          </div>
        </div>
        <div className="grid grid-cols-5 gap-2">
          {statusValues.map((value) => (
            <div
              key={value.status}
              className="rounded-md bg-muted/60 p-2 text-center"
            >
              <p className="text-sm font-semibold">{value.total}</p>
              <p className="mt-1 truncate text-[11px] text-muted-foreground">
                {value.status}
              </p>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function GovernanceVisibility({
  mappings,
  findings,
  auditLogs,
  reports,
}: {
  mappings: ComplianceRow[];
  findings: FindingResponse[];
  auditLogs: AuditLogResponse[];
  reports: ReportResponse[];
}) {
  const pdpArticles = new Set(
    mappings
      .filter((mapping) => mapping.framework.toLowerCase().includes("pdp"))
      .map((mapping) => mapping.article_or_control),
  ).size;
  const openFindings = findings.filter(isOpen);
  const coverage = findings.length
    ? Math.round((evidenceCount(findings) / findings.length) * 100)
    : 100;
  const auditReadiness = Math.round(
    (coverage + (auditLogs.length ? 100 : 0) + (reports.length ? 100 : 0)) / 3,
  );
  const confidence = validationConfidence(findings);
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <BookOpenCheck className="h-4 w-4 text-primary" />
          Compliance & Governance Visibility
        </CardTitle>
        <CardDescription>
          Audit-facing measurements from mappings, evidence, reports, and audit
          events.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {[
          {
            name: "Impacted PDP articles",
            value: `${pdpArticles}`,
            progress: Math.min(100, pdpArticles * 25),
          },
          {
            name: "Unresolved compliance gaps",
            value: `${openFindings.length}`,
            progress: Math.min(100, openFindings.length * 4),
          },
          {
            name: "Validation confidence",
            value: `${confidence}%`,
            progress: confidence,
          },
          {
            name: "Evidence coverage",
            value: `${coverage}%`,
            progress: coverage,
          },
          {
            name: "Audit readiness indicator",
            value: `${auditReadiness}%`,
            progress: auditReadiness,
          },
        ].map((row) => (
          <div key={row.name}>
            <div className="mb-1.5 flex justify-between text-xs">
              <span className="text-muted-foreground">{row.name}</span>
              <span className="font-medium">{row.value}</span>
            </div>
            <Progress value={row.progress} className="dashboard-progress" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function ExposureEstimate({
  findings,
  mappings,
}: {
  findings: FindingResponse[];
  mappings: ComplianceRow[];
}) {
  const openFindings = findings.filter(isOpen);
  const acceptedConfidence = validationConfidence(openFindings);
  const highestArea = primaryExposure(openFindings);
  return (
    <Card className="dashboard-surface">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <Siren className="h-4 w-4 text-primary" />
          Breach Likelihood & Impact Estimate
        </CardTitle>
        <CardDescription>
          Validation-derived exposure indicator; not a predicted breach event.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-2 sm:grid-cols-2">
        <div className="rounded-md border bg-background/40 p-3">
          <p className="text-xs text-muted-foreground">
            Accepted confidence indicator
          </p>
          <p className="mt-1 text-2xl font-semibold">{acceptedConfidence}%</p>
        </div>
        <div className="rounded-md border bg-background/40 p-3">
          <p className="text-xs text-muted-foreground">
            Potential exposed records
          </p>
          <p className="mt-2 text-sm font-medium">Not quantified</p>
        </div>
        <div className="rounded-md border bg-background/40 p-3">
          <p className="text-xs text-muted-foreground">Regulatory exposure</p>
          <p className="mt-2 truncate text-sm font-medium">
            {highestMapping(mappings)}
          </p>
        </div>
        <div className="rounded-md border bg-background/40 p-3">
          <p className="text-xs text-muted-foreground">Highest affected area</p>
          <p className="mt-2 truncate text-sm font-medium">{highestArea}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export { DashboardPage as default };
export function DashboardPage() {
  const { data, loading, error, refresh } =
    useApi(async (): Promise<DashboardData> => {
      const [
        dashboard,
        findings,
        scans,
        remediations,
        targets,
        compliance,
        auditLogs,
        reports,
      ] = await Promise.all([
        api.dashboard(),
        api.findings(undefined, undefined, 100),
        api.scans(),
        api.remediations().catch(() => [] as RemediationSummary[]),
        api.targets().catch(() => [] as TargetSummary[]),
        api.compliance().catch(() => ({
          organization_id: "",
          mappings: [] as ComplianceRow[],
        })),
        api.auditLogs().catch(() => [] as AuditLogResponse[]),
        api.reports().catch(() => [] as ReportResponse[]),
      ]);
      const focusScan =
        scans.find((scan) =>
          ["queued", "running", "stopping"].includes(scan.status),
        ) ??
        scans[0] ??
        null;
      const focusEndpoints = focusScan
        ? await api
            .scanEndpoints(focusScan.id)
            .catch(() => [] as EndpointInventory[])
        : [];
      return {
        dashboard,
        findings,
        scans,
        remediations,
        targets,
        mappings: compliance.mappings,
        auditLogs,
        reports,
        focusEndpoints,
        focusScan,
      };
    }, []);

  useEffect(() => {
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const activity = useMemo<ActivityItem[]>(() => {
    if (!data) return [];
    const scanById = new Map(data.scans.map((scan) => [scan.id, scan]));
    const findingEvents = data.findings
      .map((finding) => ({
        id: `finding-${finding.id}`,
        timestamp:
          scanById.get(finding.scan_id)?.finished_at ??
          scanById.get(finding.scan_id)?.created_at ??
          "",
        severity: normalizedSeverity(finding.severity),
        title: finding.title,
        detail: finding.endpoint_url ?? finding.finding_type,
      }))
      .filter((item) => Boolean(item.timestamp));
    const remediationEvents = data.remediations.map((item) => ({
      id: `remediation-${item.id}`,
      timestamp: item.updated_at,
      severity: normalizedSeverity(item.severity),
      title: `Remediation ${item.status}`,
      detail: item.title,
    }));
    const auditEvents = data.auditLogs
      .filter((item) => item.action !== "login")
      .map((item) => ({
        id: `audit-${item.id}`,
        timestamp: item.timestamp,
        severity: "info" as Severity,
        title: item.action.replace(/\./g, " "),
        detail: `${item.resource_type} ${compactId(item.resource_id)}`,
      }));
    return [...findingEvents, ...remediationEvents, ...auditEvents].sort(
      (a, b) => apiDateTimestamp(b.timestamp) - apiDateTimestamp(a.timestamp),
    );
  }, [data]);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <div className="grid gap-3 md:grid-cols-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <Skeleton key={index} className="h-28" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }
  if (!data) {
    return (
      <EmptyState
        title="Dashboard unavailable"
        description={error ?? "Unable to load governance telemetry."}
      />
    );
  }

  const openFindings = data.findings.filter(
    (finding) => isOpen(finding) && isExecutiveSignal(finding),
  );
  const critical = openFindings.filter(
    (finding) => normalizedSeverity(finding.severity) === "critical",
  );
  const high = openFindings.filter(
    (finding) => normalizedSeverity(finding.severity) === "high",
  );
  const orgRisk = critical.length
    ? "critical"
    : high.length
      ? "high"
      : openFindings.length
        ? "medium"
        : "low";
  const privacy = privacySignals(openFindings);
  const privacyCount = privacy.reduce(
    (count, signal) => count + signal.matches.length,
    0,
  );
  const privacyRisk = strongest(privacy.flatMap((signal) => signal.matches));
  const confidence = validationConfidence(data.findings);
  const evidenceCoverage = data.findings.length
    ? Math.round((evidenceCount(data.findings) / data.findings.length) * 100)
    : 100;
  const activeScan = data.scans.find((scan) =>
    ["queued", "running", "stopping"].includes(scan.status),
  );
  const scanProgress = activeScan
    ? scanStat(activeScan, "progress_percentage")
    : 100;

  return (
    <div className="dashboard-grid space-y-4">
      {error && (
        <div className="flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-700 dark:text-yellow-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Live update delayed: {error}. Displaying last successfully retrieved
            governance state.
          </span>
        </div>
      )}

      <RiskPostureBanner
        risk={orgRisk}
        regulation={highestMapping(data.mappings)}
        exposure={primaryExposure(openFindings)}
        critical={critical.length}
      />

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4 2xl:grid-cols-8">
        <GovernanceMetric
          title="Compliance Score"
          value={`${data.dashboard.compliance_score}%`}
          detail="UU PDP / ASVS posture"
          icon={BookOpenCheck}
          severity={data.dashboard.compliance_score < 50 ? "high" : "low"}
        />
        <GovernanceMetric
          title="Security Score"
          value={`${data.dashboard.security_score}%`}
          detail="Risk weighted posture"
          icon={ShieldCheck}
          severity={data.dashboard.security_score < 50 ? "high" : "low"}
        />
        <GovernanceMetric
          title="Critical Active"
          value={critical.length}
          detail="Immediate attention"
          icon={ShieldAlert}
          severity={critical.length ? "critical" : "low"}
        />
        <GovernanceMetric
          title="High Active"
          value={high.length}
          detail="Priority queue"
          icon={AlertTriangle}
          severity={high.length ? "high" : "low"}
        />
        <GovernanceMetric
          title="Privacy Signals"
          value={privacyCount}
          detail="Accepted evidence matches"
          icon={Fingerprint}
          severity={privacyCount ? privacyRisk : "low"}
        />
        <GovernanceMetric
          title="Evidence Coverage"
          value={`${evidenceCoverage}%`}
          detail="Findings with proof records"
          icon={CheckCircle2}
          severity={evidenceCoverage >= 80 ? "low" : "medium"}
        />
        <GovernanceMetric
          title="Validation Confidence"
          value={`${confidence}%`}
          detail="Accepted evidence average"
          icon={Radar}
          severity={confidence >= 80 ? "low" : "medium"}
        />
        <GovernanceMetric
          title="Active Validation"
          value={`${Math.round(scanProgress)}%`}
          detail={
            activeScan
              ? String(activeScan.stats.phase ?? "Running")
              : "No running scan"
          }
          icon={ScanLine}
          severity={activeScan ? "info" : "low"}
        />
      </div>

      <RecentScansConsole
        scans={data.scans.slice(0, 8)}
        findings={data.findings}
        remediations={data.remediations}
      />

      <div className="grid items-start gap-4 xl:grid-cols-[1.05fr_0.95fr_0.85fr]">
        <ActivityFeed items={activity} />
        <AttackSurfaceOverview
          endpoints={data.focusEndpoints}
          targets={data.targets}
          scan={data.focusScan}
        />
        <PrivacyExposure signals={privacy} />
      </div>

      <ExposurePath findings={openFindings} targets={data.targets} />

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <ExecutiveInsights
          findings={data.findings}
          mappings={data.mappings}
          confidence={confidence}
        />
        <ExposureEstimate findings={data.findings} mappings={data.mappings} />
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <RemediationSla
          findings={data.findings}
          remediations={data.remediations}
          completion={data.dashboard.remediation_progress}
        />
        <GovernanceVisibility
          mappings={data.mappings}
          findings={data.findings}
          auditLogs={data.auditLogs}
          reports={data.reports}
        />
      </div>

      <div className="flex flex-col justify-between gap-2 rounded-md border bg-card/65 p-3 text-xs text-muted-foreground sm:flex-row">
        <p>
          Indicators are derived from accepted validation evidence, regulatory
          mappings, and recorded workflow activity. Record-volume and
          breach-probability estimates are not asserted without supporting data.
        </p>
        <p className="shrink-0">
          Local time: {Intl.DateTimeFormat().resolvedOptions().timeZone}
        </p>
      </div>
    </div>
  );
}

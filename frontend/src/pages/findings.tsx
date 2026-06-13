import { CalendarDays, Eye, Search, SlidersHorizontal } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { useProgressiveFindings } from "@/hooks/use-progressive-findings";
import { api } from "@/lib/api";
import { compactId, formatNumber, severityColor } from "@/lib/utils";
import type {
  FindingEvidencePeekResponse,
  FindingEvidenceResponse,
  FindingResponse,
} from "@/types/api";

const PAGE_SIZE = 10;

function parseApiDate(value: string) {
  const includesZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  return new Date(includesZone ? value : `${value}Z`);
}

function findingDateKey(value: string | null | undefined) {
  if (!value) return "undated";
  const date = parseApiDate(value);
  if (Number.isNaN(date.getTime())) return "undated";
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function findingDateLabel(value: string | null | undefined) {
  if (!value) return "Date not recorded";
  const date = parseApiDate(value);
  if (Number.isNaN(date.getTime())) return "Date not recorded";
  return new Intl.DateTimeFormat(undefined, {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(date);
}

function findingTimeLabel(value: string | null | undefined) {
  if (!value) return "Time not recorded";
  const date = parseApiDate(value);
  if (Number.isNaN(date.getTime())) return "Time not recorded";
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function toHeaderLines(headers: unknown) {
  if (!headers || typeof headers !== "object") return [];
  return Object.entries(headers as Record<string, unknown>).map(
    ([key, value]) => `${headerLabel(key)}: ${String(value)}`,
  );
}

function headerLabel(key: string) {
  return key
    .split("-")
    .map((item) => item.charAt(0).toUpperCase() + item.slice(1))
    .join("-");
}

function requestParts(evidence: FindingEvidenceResponse) {
  const request = evidence.raw_request;
  const url = String(request.url ?? "");
  try {
    const parsed = new URL(url);
    return {
      target: `${parsed.pathname}${parsed.search}` || "/",
      host: parsed.host,
    };
  } catch {
    return { target: url || "/", host: "" };
  }
}

function formatRequest(evidence: FindingEvidenceResponse) {
  const request = evidence.raw_request;
  const method = String(request.method ?? "GET");
  const version = String(request.http_version ?? "HTTP/1.1");
  const { target, host } = requestParts(evidence);
  const headers = (request.headers ?? {}) as Record<string, unknown>;
  const hasHost = Object.keys(headers).some(
    (key) => key.toLowerCase() === "host",
  );
  const body = String(request.body ?? "");
  return [
    `${method} ${target} ${version}`,
    ...(host && !hasHost ? [`Host: ${host}`] : []),
    ...toHeaderLines(headers),
    "",
    body,
  ]
    .join("\n")
    .trim();
}

function formatResponse(evidence: FindingEvidenceResponse) {
  const response = evidence.raw_response;
  const status = String(response.status ?? "");
  const reason = String(response.reason ?? "");
  const version = String(response.http_version ?? "HTTP/1.1");
  const body = String(response.body_sample ?? "");
  return [
    `${version} ${status}${reason ? ` ${reason}` : ""}`,
    ...toHeaderLines(response.headers),
    "",
    body,
  ]
    .join("\n")
    .trim();
}

// Agent (Phantom) findings carry their request/response in evidence_summary
// instead of a dedicated Evidence record. Reconstruct the raw HTTP view from
// those fields so the Raw HTTP panels are populated for agent findings too.
function formatRequestFromSummary(
  summary: Record<string, unknown>,
): string | null {
  const request = summary.request;
  if (!request || typeof request !== "object") return null;
  const r = request as Record<string, unknown>;
  const method = String(r.method ?? "GET");
  const version = String(r.http_version ?? "HTTP/1.1");
  const url = String(r.url ?? "");
  let target = url || "/";
  let host = "";
  try {
    const parsed = new URL(url);
    target = `${parsed.pathname}${parsed.search}` || "/";
    host = parsed.host;
  } catch {
    /* keep the raw url as the request target */
  }
  const headers = (r.headers ?? {}) as Record<string, unknown>;
  const hasHost = Object.keys(headers).some((k) => k.toLowerCase() === "host");
  const body = String(r.body ?? "");
  return [
    `${method} ${target} ${version}`,
    ...(host && !hasHost ? [`Host: ${host}`] : []),
    ...toHeaderLines(headers),
    "",
    body,
  ]
    .join("\n")
    .trim();
}

function formatResponseFromSummary(
  summary: Record<string, unknown>,
): string | null {
  const response = summary.response;
  if (!response || typeof response !== "object") return null;
  const r = response as Record<string, unknown>;
  const status = String(r.status ?? "");
  const reason = String(r.reason ?? "");
  const version = String(r.http_version ?? "HTTP/1.1");
  const body = String(r.body ?? "");
  return [
    `${version} ${status}${reason ? ` ${reason}` : ""}`,
    ...toHeaderLines(r.headers),
    "",
    body,
  ]
    .join("\n")
    .trim();
}

function evidenceString(finding: FindingResponse, key: string) {
  const value = finding.evidence_summary[key];
  return typeof value === "string" ? value : null;
}

// Pretty-print an evidence value that may be a JSON string or a plain object so
// the enlarged agent evidence panel reads cleanly instead of as a single line.
function prettyJson(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  return JSON.stringify(value, null, 2);
}

function readableRequestUrl(evidence: FindingEvidenceResponse | null) {
  if (!evidence) return null;
  const url = String(evidence.raw_request.url ?? "");
  try {
    return decodeURIComponent(url.replace(/\+/g, " "));
  } catch {
    return url;
  }
}

export function FindingsPage() {
  const { data, loading, error } = useProgressiveFindings();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [dateFilter, setDateFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<FindingResponse | null>(null);
  const [evidence, setEvidence] = useState<FindingEvidenceResponse | null>(
    null,
  );
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [peekData, setPeekData] = useState<FindingEvidencePeekResponse | null>(
    null,
  );
  const [peekLoading, setPeekLoading] = useState(false);
  const [peekTimer, setPeekTimer] = useState<ReturnType<
    typeof setTimeout
  > | null>(null);

  async function viewEvidence(finding: FindingResponse) {
    setSelected(finding);
    setEvidence(null);
    setEvidenceError(null);
    setEvidenceLoading(true);
    try {
      setEvidence(await api.findingEvidence(finding.id));
    } catch (exc) {
      setEvidenceError(
        exc instanceof Error ? exc.message : "Unable to load evidence",
      );
    } finally {
      setEvidenceLoading(false);
    }
  }

  const availableDates = useMemo(() => {
    const dates = new Map<string, string>();
    for (const finding of data ?? []) {
      const key = findingDateKey(finding.created_at);
      if (key !== "undated" && !dates.has(key)) {
        dates.set(key, findingDateLabel(finding.created_at));
      }
    }
    return Array.from(dates.entries())
      .map(([key, label]) => ({ key, label }))
      .sort((left, right) => right.key.localeCompare(left.key));
  }, [data]);

  const filtered = useMemo(() => {
    const search = query.toLowerCase().trim();
    return (data ?? [])
      .filter((finding) => {
        const matchesSearch =
          !search ||
          finding.title.toLowerCase().includes(search) ||
          finding.finding_type.toLowerCase().includes(search) ||
          (finding.endpoint_url ?? finding.endpoint_id ?? "")
            .toLowerCase()
            .includes(search);
        const matchesSeverity =
          severity === "all" || finding.severity === severity;
        const matchesStatus = status === "all" || finding.status === status;
        const matchesDate =
          dateFilter === "all" ||
          findingDateKey(finding.created_at) === dateFilter;
        return matchesSearch && matchesSeverity && matchesStatus && matchesDate;
      })
      .sort((left, right) => {
        const dateDelta =
          parseApiDate(right.created_at).getTime() -
          parseApiDate(left.created_at).getTime();
        if (dateDelta !== 0) return dateDelta;
        return right.risk_score - left.risk_score;
      });
  }, [data, query, severity, status, dateFilter]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const rows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const rowsByDate = useMemo(() => {
    const groups = new Map<
      string,
      { key: string; label: string; items: FindingResponse[] }
    >();
    for (const finding of rows) {
      const key = findingDateKey(finding.created_at);
      const existing = groups.get(key);
      if (existing) {
        existing.items.push(finding);
      } else {
        groups.set(key, {
          key,
          label: findingDateLabel(finding.created_at),
          items: [finding],
        });
      }
    }
    return Array.from(groups.values());
  }, [rows]);
  const payload = selected ? evidenceString(selected, "payload") : null;
  const injectedParameter = selected
    ? (evidenceString(selected, "injected_parameter") ??
      evidenceString(selected, "field"))
    : null;
  const injectionLocation = selected
    ? evidenceString(selected, "injection_location")
    : null;
  // Phantom and other agent-sourced findings carry their proof in the
  // evidence_summary `evidence`/`reasoning` fields. For those we drop the
  // duplicated request/response from Validation Detail and enlarge the
  // evidence + reasoning into a dedicated full-width section below the grid.
  const isAgentFinding = selected
    ? evidenceString(selected, "source") === "agent"
    : false;
  const agentEvidence = selected
    ? selected.evidence_summary["evidence"]
    : undefined;

  if (loading) {
    return <Skeleton className="h-[540px]" />;
  }

  if (error || !data) {
    return (
      <EmptyState
        title="Findings unavailable"
        description={error ?? "Unable to load findings."}
      />
    );
  }

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle>Findings</CardTitle>
              <CardDescription>
                Low-noise validation findings with compliance and remediation
                context.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <SlidersHorizontal className="h-4 w-4" />
              {formatNumber(filtered.length)} of {formatNumber(data.length)}{" "}
              findings
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_180px_180px_220px]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-9"
                placeholder="Search title, endpoint, or finding type"
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
              />
            </div>
            <Select
              value={severity}
              onChange={(event) => {
                setSeverity(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </Select>
            <Select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All statuses</option>
              <option value="Open">Open</option>
              <option value="Assigned">Assigned</option>
              <option value="In Progress">In Progress</option>
              <option value="Re-Test">Re-Test</option>
              <option value="Closed">Closed</option>
              <option value="False Positive">False Positive</option>
            </Select>
            <Select
              value={dateFilter}
              onChange={(event) => {
                setDateFilter(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All dates</option>
              {availableDates.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.label}
                </option>
              ))}
            </Select>
          </div>

          {rows.length ? (
            <>
              <div className="space-y-5">
                {rowsByDate.map((group) => (
                  <section
                    key={group.key}
                    className="rounded-lg border bg-background"
                  >
                    <div className="flex items-center justify-between gap-3 border-b bg-muted/40 px-4 py-3">
                      <div className="flex items-center gap-2">
                        <CalendarDays className="h-4 w-4 text-primary" />
                        <p className="font-medium">{group.label}</p>
                      </div>
                      <Badge variant="outline">
                        {group.items.length} finding(s)
                      </Badge>
                    </div>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Severity</TableHead>
                          <TableHead>Finding</TableHead>
                          <TableHead>Endpoint</TableHead>
                          <TableHead>Compliance</TableHead>
                          <TableHead>Confidence</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="w-28">Evidence</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {group.items.map((finding) => (
                          <TableRow key={finding.id}>
                            <TableCell>
                              <Badge
                                variant={
                                  severityColor(finding.severity) as never
                                }
                              >
                                {finding.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="min-w-64">
                              <p className="font-medium">{finding.title}</p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {finding.finding_type}
                              </p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {findingTimeLabel(finding.created_at)}
                              </p>
                            </TableCell>
                            <TableCell className="max-w-sm">
                              <p className="truncate font-mono text-xs">
                                {finding.endpoint_url ??
                                  compactId(finding.endpoint_id)}
                              </p>
                              <p className="mt-1 text-xs text-muted-foreground">
                                Scan {compactId(finding.scan_id)}
                              </p>
                            </TableCell>
                            <TableCell>
                              <div className="space-y-1">
                                {finding.compliance
                                  .slice(0, 2)
                                  .map((item, index) => (
                                    <Badge
                                      key={`${finding.id}-${index}`}
                                      variant="outline"
                                    >
                                      {item.framework} {item.article_or_control}
                                    </Badge>
                                  ))}
                              </div>
                            </TableCell>
                            <TableCell>
                              {Math.round(finding.confidence)}%
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  finding.status === "Closed"
                                    ? "emerald"
                                    : "secondary"
                                }
                              >
                                {finding.status}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => void viewEvidence(finding)}
                              >
                                <Eye className="h-3.5 w-3.5" />
                                View
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </section>
                ))}
              </div>
              <div className="mt-4 flex items-center justify-between gap-3">
                <p className="text-sm text-muted-foreground">
                  Page {page} of {pageCount}
                </p>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === 1}
                    onClick={() => setPage((value) => value - 1)}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === pageCount}
                    onClick={() => setPage((value) => value + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          ) : (
            <div className="rounded-lg border border-dashed p-10 text-center">
              <p className="font-medium">
                No findings match the current filters
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                Adjust the search or scan another target.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {selected && (
        <Card>
          <CardHeader>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <CardTitle>{selected.title}</CardTitle>
                <CardDescription className="mt-2 break-all">
                  {selected.endpoint_url ?? selected.endpoint_id}
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={severityColor(selected.severity) as never}>
                  {selected.severity}
                </Badge>
                <Badge variant="outline">
                  {Math.round(selected.confidence)}% confidence
                </Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 xl:grid-cols-[0.82fr_1fr_1fr]">
              <div className="space-y-3">
                <p className="text-sm font-medium">Validation Detail</p>
                <div className="rounded-md border p-3 text-sm">
                  <p className="text-xs text-muted-foreground">Attack type</p>
                  <p className="mt-1 font-medium">{selected.finding_type}</p>
                  {payload ? (
                    <div className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
                      <p className="text-xs font-medium text-amber-700 dark:text-amber-300">
                        Payload Tested
                      </p>
                      <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-foreground">
                        {payload}
                      </pre>
                      {injectedParameter && (
                        <p className="mt-3 text-xs text-muted-foreground">
                          Input:{" "}
                          <span className="font-mono text-foreground">
                            {injectedParameter}
                          </span>
                          {injectionLocation
                            ? ` (${injectionLocation.replace(/_/g, " ")})`
                            : ""}
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="mt-4 rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
                      Passive observation or context comparison. No injected
                      payload was required.
                    </div>
                  )}
                  {evidence && payload && (
                    <div className="mt-3">
                      <p className="text-xs text-muted-foreground">
                        Submitted request URL
                      </p>
                      <p className="mt-1 break-all font-mono text-xs">
                        {readableRequestUrl(evidence)}
                      </p>
                    </div>
                  )}
                  {Object.entries(selected.evidence_summary)
                    .filter(([key]) => {
                      if (key.startsWith("evidence_")) return false;
                      // request/response duplicate the Raw HTTP panels.
                      if (
                        [
                          "payload",
                          "injected_parameter",
                          "injection_location",
                          "request",
                          "response",
                        ].includes(key)
                      )
                        return false;
                      // evidence is shown enlarged below for agent findings.
                      if (isAgentFinding && key === "evidence") return false;
                      return true;
                    })
                    .slice(0, 6)
                    .map(([key, value]) => (
                      <div key={key} className="mt-3">
                        <p className="text-xs text-muted-foreground">
                          {key.replace(/_/g, " ")}
                        </p>
                        <p className="mt-1 break-all font-mono text-xs">
                          {typeof value === "string"
                            ? value
                            : JSON.stringify(value)}
                        </p>
                      </div>
                    ))}
                </div>
                {!isAgentFinding && (
                  <div className="rounded-md border p-3">
                    <p className="text-xs text-muted-foreground">Reasoning</p>
                    <div className="mt-2 space-y-2 text-xs">
                      {selected.reasoning.map((item) => (
                        <p key={item}>{item}</p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div className="space-y-3">
                <p className="text-sm font-medium">Raw HTTP Request</p>
                {evidenceLoading ? (
                  <Skeleton className="h-[420px]" />
                ) : (
                  <pre className="h-[420px] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-all">
                    {evidence
                      ? formatRequest(evidence)
                      : (formatRequestFromSummary(selected.evidence_summary) ??
                        evidenceError ??
                        "No request evidence available.")}
                  </pre>
                )}
              </div>
              <div className="space-y-3">
                <p className="text-sm font-medium">Raw HTTP Response</p>
                {evidenceLoading ? (
                  <Skeleton className="h-[420px]" />
                ) : (
                  <pre className="h-[420px] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-all">
                    {evidence
                      ? formatResponse(evidence)
                      : (formatResponseFromSummary(selected.evidence_summary) ??
                        evidenceError ??
                        "No response evidence available.")}
                  </pre>
                )}
              </div>
            </div>
            {isAgentFinding && (
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-md border p-4">
                  <p className="text-sm font-medium">Evidence</p>
                  <pre className="mt-3 max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-4 font-mono text-sm leading-relaxed text-foreground">
                    {prettyJson(agentEvidence) || "No evidence recorded."}
                  </pre>
                </div>
                <div className="rounded-md border p-4">
                  <p className="text-sm font-medium">Reasoning</p>
                  <ol className="mt-3 space-y-3 text-sm leading-relaxed">
                    {selected.reasoning.length ? (
                      selected.reasoning.map((item) => (
                        <li key={item}>{item}</li>
                      ))
                    ) : (
                      <li className="text-muted-foreground">
                        No reasoning recorded.
                      </li>
                    )}
                  </ol>
                </div>
              </div>
            )}
            {evidence && (
              <div className="flex flex-wrap gap-3 rounded-md border p-3 font-mono text-xs text-muted-foreground">
                <span>Evidence ID: {evidence.immutable_id}</span>
                <span>SHA-256: {evidence.evidence_hash}</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export { FindingsPage as default };

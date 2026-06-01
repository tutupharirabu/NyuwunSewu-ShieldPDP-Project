import { AlertTriangle, ExternalLink, Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { compactId, formatDate, formatNumber, severityColor } from "@/lib/utils";
import type { EndpointInventory } from "@/types/api";

const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

function endpointDisplaySeverity(endpoint: EndpointInventory) {
  return endpoint.highest_severity ?? endpoint.classifications[0]?.risk ?? "info";
}

export function ScanDetailPage() {
  const { scanId } = useParams();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data, loading, error } = useApi(async () => {
    if (!scanId) throw new Error("Scan id is missing");
    const [scan, endpoints, findings] = await Promise.all([
      api.scan(scanId),
      api.scanEndpoints(scanId),
      api.findings(scanId)
    ]);
    return { scan, endpoints, findings };
  }, [scanId]);

  const filteredEndpoints = useMemo(() => {
    const search = query.toLowerCase().trim();
    return (data?.endpoints ?? [])
      .filter((endpoint) => {
        const displaySeverity = endpointDisplaySeverity(endpoint).toLowerCase();
        const matchesSeverity = severity === "all" || displaySeverity === severity;
        const matchesSearch =
          !search ||
          endpoint.url.toLowerCase().includes(search) ||
          endpoint.normalized_path.toLowerCase().includes(search) ||
          (endpoint.title ?? "").toLowerCase().includes(search) ||
          endpoint.classifications.some((item) =>
            String(item.classification ?? "").toLowerCase().includes(search)
          );
        return matchesSearch && matchesSeverity;
      })
      .sort((a, b) => {
        const severityDelta =
          (severityRank[endpointDisplaySeverity(b).toLowerCase()] ?? 0) -
          (severityRank[endpointDisplaySeverity(a).toLowerCase()] ?? 0);
        return severityDelta || b.finding_count - a.finding_count || b.risk_score - a.risk_score;
      });
  }, [data?.endpoints, query, severity]);

  if (loading) {
    return <Skeleton className="h-[640px]" />;
  }

  if (error || !data) {
    return <EmptyState title="Scan unavailable" description={error ?? "Unable to load scan inventory."} />;
  }

  const selected = data.endpoints.find((endpoint) => endpoint.id === selectedId) ?? filteredEndpoints[0];
  const progress = Number(data.scan.stats.progress_percentage ?? 0);
  const criticalOrHigh = data.endpoints.filter((endpoint) =>
    ["critical", "high"].includes(endpointDisplaySeverity(endpoint).toLowerCase())
  ).length;
  const diagnostics =
    typeof data.scan.stats.diagnostics === "object" && data.scan.stats.diagnostics !== null
      ? (data.scan.stats.diagnostics as Record<string, unknown>)
      : {};
  const authentication =
    typeof diagnostics.authentication === "object" && diagnostics.authentication !== null
      ? (diagnostics.authentication as Record<string, unknown>)
      : {};
  const contexts =
    typeof diagnostics.contexts === "object" && diagnostics.contexts !== null
      ? (diagnostics.contexts as Record<string, Record<string, unknown>>)
      : {};
  const authenticationStatus = String(authentication.status ?? "not_configured").replace(/_/g, " ");
  const guestEndpoints = Number(contexts.guest?.endpoints_observed ?? 0);
  const authenticatedEndpoints = Number(contexts.authenticated?.endpoints_observed ?? 0);

  return (
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <Card>
          <CardHeader>
            <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <CardTitle className="font-mono text-base">{compactId(data.scan.id)}</CardTitle>
                <CardDescription className="mt-2 break-all">
                  {data.scan.target_url ?? data.scan.target_id}
                </CardDescription>
              </div>
              <Badge variant={data.scan.status === "completed" ? "emerald" : data.scan.status === "failed" ? "destructive" : "blue"}>
                {data.scan.status}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-4">
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Progress</p>
                <p className="mt-1 text-2xl font-semibold">{Math.round(progress)}%</p>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Endpoints</p>
                <p className="mt-1 text-2xl font-semibold">{formatNumber(data.endpoints.length)}</p>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Findings</p>
                <p className="mt-1 text-2xl font-semibold">{formatNumber(data.findings.length)}</p>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">High/Critical</p>
                <p className="mt-1 text-2xl font-semibold">{formatNumber(criticalOrHigh)}</p>
              </div>
            </div>
            <Progress value={progress} />
            <div className="grid gap-3 text-sm md:grid-cols-4">
              <div>
                <p className="text-xs text-muted-foreground">Phase</p>
                <p className="mt-1 font-medium">{String(data.scan.stats.phase ?? "-")}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Authenticated discovery</p>
                <p className="mt-1 capitalize font-medium">{authenticationStatus}</p>
                {(guestEndpoints > 0 || authenticatedEndpoints > 0) && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {guestEndpoints} guest / {authenticatedEndpoints} authenticated
                  </p>
                )}
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Started</p>
                <p className="mt-1 font-medium">{formatDate(data.scan.started_at)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Finished</p>
                <p className="mt-1 font-medium">{formatDate(data.scan.finished_at)}</p>
              </div>
            </div>
            {data.scan.error && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4" />
                <span>{data.scan.error}</span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Validated Findings</CardTitle>
            <CardDescription>Findings accepted for this scan after evidence checks.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {data.findings.length ? (
              data.findings.slice(0, 6).map((finding) => (
                <div key={finding.id} className="rounded-md border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <Badge variant={severityColor(finding.severity) as never}>{finding.severity}</Badge>
                    <span className="text-xs text-muted-foreground">{Math.round(finding.confidence)}%</span>
                  </div>
                  <p className="mt-2 text-sm font-medium">{finding.title}</p>
                  <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                    {finding.endpoint_url ?? compactId(finding.endpoint_id)}
                  </p>
                </div>
              ))
            ) : (
              <div className="rounded-md border border-dashed p-6 text-center">
                <ShieldAlert className="mx-auto h-5 w-5 text-muted-foreground" />
                <p className="mt-2 text-sm font-medium">No accepted findings for this scan</p>
                <p className="mt-1 text-xs text-muted-foreground">Review endpoint inventory and validation policy below.</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <CardTitle>Endpoint Inventory</CardTitle>
              <CardDescription>Every crawled endpoint with classifications and finding linkage.</CardDescription>
            </div>
            <div className="grid gap-2 sm:grid-cols-[280px_170px]">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-9"
                  placeholder="Search endpoints"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </div>
              <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                <option value="all">All risk levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredEndpoints.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Classification</TableHead>
                  <TableHead>Inputs</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEndpoints.map((endpoint) => {
                  const displaySeverity = endpointDisplaySeverity(endpoint);
                  const primaryClass = endpoint.classifications[0];
                  return (
                    <TableRow
                      key={endpoint.id}
                      className="cursor-pointer"
                      onClick={() => setSelectedId(endpoint.id)}
                    >
                      <TableCell className="max-w-xl">
                        <p className="truncate font-mono text-xs">{endpoint.url}</p>
                        <p className="mt-1 truncate text-xs text-muted-foreground">{endpoint.title ?? endpoint.content_type ?? "-"}</p>
                      </TableCell>
                      <TableCell>{endpoint.status_code ?? "-"}</TableCell>
                      <TableCell>
                        <Badge variant={severityColor(displaySeverity) as never}>{displaySeverity}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span>{endpoint.finding_count}</span>
                          {endpoint.highest_confidence !== null && (
                            <span className="text-xs text-muted-foreground">{Math.round(endpoint.highest_confidence)}%</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <Badge variant="outline">{primaryClass?.classification ?? "public"}</Badge>
                          <p className="text-xs text-muted-foreground">
                            Risk {Math.round(endpoint.risk_score)}
                          </p>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {endpoint.query_parameters.length} params / {endpoint.forms.length} forms
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="rounded-lg border border-dashed p-10 text-center">
              <p className="font-medium">No endpoints match the current filters</p>
              <p className="mt-1 text-sm text-muted-foreground">Clear the search or risk filter.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {selected && (
        <Card>
          <CardHeader>
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <CardTitle>Endpoint Detail</CardTitle>
                <CardDescription className="mt-2 break-all">{selected.url}</CardDescription>
              </div>
              <Button variant="outline" asChild>
                <a href={selected.url} target="_blank" rel="noreferrer">
                  <ExternalLink className="h-4 w-4" />
                  Open
                </a>
              </Button>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-3">
            <div className="space-y-3">
              <p className="text-sm font-medium">Classifications</p>
              {selected.classifications.map((item, index) => (
                <div key={`${selected.id}-${index}`} className="rounded-md border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <Badge variant={severityColor(String(item.risk ?? "info")) as never}>
                      {item.classification ?? "public"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{item.confidence ?? 0}%</span>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {(item.reasoning ?? []).slice(0, 2).join("; ") || "Heuristic classification"}
                  </p>
                </div>
              ))}
            </div>
            <div className="space-y-3">
              <p className="text-sm font-medium">Inputs</p>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Query parameters</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {selected.query_parameters.length ? (
                    selected.query_parameters.map((item) => <Badge key={item} variant="outline">{item}</Badge>)
                  ) : (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </div>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Forms</p>
                <div className="mt-2 space-y-2">
                  {selected.forms.length ? (
                    selected.forms.map((form, index) => (
                      <div key={`${selected.id}-form-${index}`} className="rounded border p-2">
                        <p className="truncate text-xs font-medium">{form.method ?? "GET"} {form.action ?? selected.url}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {(form.fields ?? []).map((field) => field.name).filter(Boolean).join(", ")}
                        </p>
                      </div>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </div>
              </div>
              <div className="rounded-md border p-3">
                <p className="text-xs text-muted-foreground">Technologies and API profile</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {selected.tech_stack.length ? (
                    selected.tech_stack.map((item) => <Badge key={item} variant="outline">{item}</Badge>)
                  ) : (
                    <span className="text-xs text-muted-foreground">No passive signature identified</span>
                  )}
                </div>
              </div>
            </div>
            <div className="space-y-3">
              <p className="text-sm font-medium">Finding Linkage</p>
              {selected.finding_titles.length ? (
                selected.finding_titles.map((title) => (
                  <div key={title} className="rounded-md border p-3">
                    <p className="text-sm font-medium">{title}</p>
                  </div>
                ))
              ) : (
                <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
                  No finding is linked to this endpoint.
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <div>
        <Button variant="outline" asChild>
          <Link to="/dashboard">Back to Dashboard</Link>
        </Button>
      </div>
    </div>
  );
}

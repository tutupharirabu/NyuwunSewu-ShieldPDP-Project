import {
  ArrowRight,
  CheckCircle2,
  RotateCcw,
  Shield,
  Clock,
  Target,
  AlertTriangle,
  Wrench,
} from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { compactId, severityColor } from "@/lib/utils";
import type { RemediationMatrixItem, RemediationSummary } from "@/types/api";

const workflow = ["Open", "Assigned", "In Progress", "Re-Test", "Closed"];

function priorityColor(level: string) {
  if (level.includes("Critical")) return "destructive";
  if (level.includes("High")) return "default";
  if (level.includes("Medium")) return "secondary";
  return "outline";
}

function effortBadge(effort: string) {
  const map: Record<string, string> = {
    Simple:
      "bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200",
    Moderate: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
    Complex:
      "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200",
    Major: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  };
  return map[effort] || "bg-gray-100 text-gray-800";
}

function RemediationMatrixView() {
  const { data, loading, error } = useApi(api.remediationMatrix, []);

  if (loading) return <Skeleton className="h-[560px]" />;
  if (error || !data) {
    return (
      <EmptyState
        title="Remediation matrix unavailable"
        description={error ?? "Unable to load matrix data."}
      />
    );
  }

  const items = data.matrix ?? [];
  if (!items.length) {
    return (
      <EmptyState
        title="No remediation items"
        description="No findings available to generate a remediation plan."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-muted-foreground">
            {data.total_findings} findings grouped into {data.total_items}{" "}
            action items
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {items.map((item: RemediationMatrixItem) => (
          <Card key={item.domain} className="overflow-hidden">
            <div className="flex items-start gap-4 p-5">
              {/* Priority badge */}
              <div className="flex-shrink-0">
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-full text-sm font-bold text-white ${
                    item.priority_level.includes("Critical")
                      ? "bg-red-600"
                      : item.priority_level.includes("High")
                        ? "bg-orange-500"
                        : item.priority_level.includes("Medium")
                          ? "bg-amber-500"
                          : "bg-teal-600"
                  }`}
                >
                  #{item.priority_rank}
                </div>
              </div>

              <div className="flex-1 min-w-0">
                {/* Domain + priority row */}
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-semibold">{item.domain}</h3>
                  <Badge variant={priorityColor(item.priority_level) as never}>
                    {item.priority_level}
                  </Badge>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full ${effortBadge(item.effort_estimate)}`}
                  >
                    {item.effort_estimate} ({item.effort_days} days)
                  </span>
                </div>

                {/* Stats row */}
                <div className="mt-2 flex flex-wrap gap-4 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Shield className="h-3.5 w-3.5" />
                    {item.finding_count} findings
                  </span>
                  <span className="flex items-center gap-1">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Risk {item.max_risk_score}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    {item.recommended_timeline}
                  </span>
                  {item.affected_endpoints.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Target className="h-3.5 w-3.5" />
                      {item.affected_endpoints.length} endpoints
                    </span>
                  )}
                </div>

                {/* Severity breakdown */}
                <div className="mt-2 flex gap-2 text-xs">
                  {Object.entries(item.severity_breakdown)
                    .filter(([, count]) => count > 0)
                    .map(([sev, count]) => (
                      <Badge
                        key={sev}
                        variant={severityColor(sev) as never}
                        className="text-xs"
                      >
                        {sev}: {count}
                      </Badge>
                    ))}
                </div>

                {/* Action description */}
                <p className="mt-3 text-sm text-muted-foreground leading-relaxed">
                  {item.action}
                </p>

                {/* Finding types */}
                {item.finding_types.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {item.finding_types.map((ft) => (
                      <span
                        key={ft}
                        className="rounded bg-muted px-2 py-0.5 text-xs font-mono text-muted-foreground"
                      >
                        {ft}
                      </span>
                    ))}
                  </div>
                )}

                {/* UU PDP compliance impact */}
                {item.compliance_impact.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {item.compliance_impact.map((article) => (
                      <span
                        key={article}
                        className="rounded bg-purple-50 px-2 py-0.5 text-xs text-purple-700 dark:bg-purple-900/30 dark:text-purple-300"
                      >
                        {article}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function RemediationKanbanView() {
  const { data, loading, error, refresh } = useApi(api.remediations, []);

  if (loading) return <Skeleton className="h-[560px]" />;
  if (error || !data) {
    return (
      <EmptyState
        title="Remediation unavailable"
        description={error ?? "Unable to load remediation data."}
      />
    );
  }

  async function advance(item: RemediationSummary) {
    const currentIndex = workflow.indexOf(item.status);
    const next = workflow[Math.min(workflow.length - 1, currentIndex + 1)];
    if (next && next !== item.status) {
      await api.updateRemediation(item.finding_id, next);
      await refresh();
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Remediation Workflow</CardTitle>
          <CardDescription>
            Track findings from intake through validated closure.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-5">
            {workflow.map((step, index) => (
              <div key={step} className="rounded-lg border bg-background p-4">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium">{step}</p>
                  {index < workflow.length - 1 ? (
                    <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  )}
                </div>
                <p className="mt-3 text-2xl font-semibold">
                  {data.filter((item) => item.status === step).length}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-5">
        {workflow.map((step) => {
          const items = data.filter((item) => item.status === step);
          return (
            <Card key={step} className="xl:min-h-[420px]">
              <CardHeader className="pb-3">
                <CardTitle>{step}</CardTitle>
                <CardDescription>{items.length} items</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {items.map((item) => (
                  <div
                    key={item.id}
                    className="rounded-lg border bg-background p-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <Badge variant={severityColor(item.severity) as never}>
                        {item.severity}
                      </Badge>
                      <span className="font-mono text-xs text-muted-foreground">
                        {compactId(item.finding_id)}
                      </span>
                    </div>
                    <p className="mt-3 text-sm font-medium">{item.title}</p>
                    <p className="mt-2 text-xs text-muted-foreground">
                      Updated {item.updated_at}
                    </p>
                    {item.status !== "Closed" && (
                      <Button
                        className="mt-3 w-full"
                        variant="outline"
                        size="sm"
                        onClick={() => void advance(item)}
                      >
                        <RotateCcw className="h-4 w-4" />
                        Advance
                      </Button>
                    )}
                  </div>
                ))}
                {!items.length && (
                  <div className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">
                    No items
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export { RemediationPage as default };
export function RemediationPage() {
  const [tab, setTab] = useState("matrix");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Remediation</h1>
        <p className="text-sm text-muted-foreground">
          Prioritized action plan and workflow for security finding remediation.
        </p>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="grid w-full max-w-md grid-cols-2">
          <TabsTrigger value="matrix" className="flex items-center gap-2">
            <Wrench className="h-4 w-4" />
            Matrix View
          </TabsTrigger>
          <TabsTrigger value="kanban" className="flex items-center gap-2">
            <ArrowRight className="h-4 w-4" />
            Kanban Board
          </TabsTrigger>
        </TabsList>

        <TabsContent value="matrix" className="mt-6">
          <RemediationMatrixView />
        </TabsContent>
        <TabsContent value="kanban" className="mt-6">
          <RemediationKanbanView />
        </TabsContent>
      </Tabs>
    </div>
  );
}

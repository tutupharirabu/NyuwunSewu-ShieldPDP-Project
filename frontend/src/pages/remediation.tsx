import { ArrowRight, CheckCircle2, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { compactId, formatDate, severityColor } from "@/lib/utils";
import type { RemediationSummary } from "@/types/api";

const workflow = ["Open", "Assigned", "In Progress", "Re-Test", "Closed"];

export function RemediationPage() {
  const { data, loading, error, refresh } = useApi(api.remediations, []);

  if (loading) return <Skeleton className="h-[560px]" />;
  if (error || !data) {
    return <EmptyState title="Remediation unavailable" description={error ?? "Unable to load remediation data."} />;
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
          <CardDescription>Track findings from intake through validated closure.</CardDescription>
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
                  <div key={item.id} className="rounded-lg border bg-background p-3">
                    <div className="flex items-start justify-between gap-2">
                      <Badge variant={severityColor(item.severity) as never}>{item.severity}</Badge>
                      <span className="font-mono text-xs text-muted-foreground">{compactId(item.finding_id)}</span>
                    </div>
                    <p className="mt-3 text-sm font-medium">{item.title}</p>
                    <p className="mt-2 text-xs text-muted-foreground">Updated {formatDate(item.updated_at)}</p>
                    {item.status !== "Closed" && (
                      <Button className="mt-3 w-full" variant="outline" size="sm" onClick={() => void advance(item)}>
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


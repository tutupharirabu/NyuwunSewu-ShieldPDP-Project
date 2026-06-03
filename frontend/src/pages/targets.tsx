import { ExternalLink, Target } from "lucide-react";

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
import { compactId, formatDate } from "@/lib/utils";

export { TargetsPage as default };
export function TargetsPage() {
  const { data, loading, error } = useApi(api.targets, [], "targets");

  if (loading) return <Skeleton className="h-[520px]" />;
  if (error || !data)
    return (
      <EmptyState
        title="Targets unavailable"
        description={error ?? "Unable to load targets."}
      />
    );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Targets</CardTitle>
        <CardDescription>
          Scoped target inventory and validation activity.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Scans</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((target) => (
              <TableRow key={target.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Target className="h-4 w-4 text-muted-foreground" />
                    <div className="min-w-0">
                      <a
                        href={target.base_url}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 truncate font-medium text-primary"
                      >
                        {target.base_url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                      <p className="font-mono text-xs text-muted-foreground">
                        {compactId(target.id)}
                      </p>
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {(target.allowed_domains.length
                      ? target.allowed_domains
                      : ["base host"]
                    )
                      .slice(0, 3)
                      .map((domain) => (
                        <Badge key={domain} variant="outline">
                          {domain}
                        </Badge>
                      ))}
                  </div>
                </TableCell>
                <TableCell>{target.scans}</TableCell>
                <TableCell>{target.findings}</TableCell>
                <TableCell>
                  <Badge variant={target.is_active ? "emerald" : "secondary"}>
                    {target.is_active ? "Active" : "Inactive"}
                  </Badge>
                </TableCell>
                <TableCell>{formatDate(target.created_at)}</TableCell>
              </TableRow>
            ))}
            {!data.length && (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className="py-10 text-center text-muted-foreground"
                >
                  Targets will appear after a scan is created.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

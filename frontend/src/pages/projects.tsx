import { Fingerprint, FolderKanban, History, Radar, Target, TriangleAlert } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { compactId, formatDate, formatNumber } from "@/lib/utils";

export function ProjectsPage() {
  const navigate = useNavigate();
  const { data, loading, error } = useApi(async () => {
    const [projects, auditLogs] = await Promise.all([
      api.projects(),
      api.auditLogs().catch(() => [])
    ]);
    return { projects, auditLogs };
  }, []);

  if (loading) return <Skeleton className="h-[520px]" />;
  if (error || !data) return <EmptyState title="Projects unavailable" description={error ?? "Unable to load projects."} />;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="flex items-center gap-3 p-5">
            <FolderKanban className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-semibold">{formatNumber(data.projects.length)}</p>
              <p className="text-sm text-muted-foreground">Projects</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-5">
            <Target className="h-5 w-5 text-blue-600" />
            <div>
              <p className="text-2xl font-semibold">
                {formatNumber(data.projects.reduce((total, project) => total + project.targets, 0))}
              </p>
              <p className="text-sm text-muted-foreground">Targets</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-5">
            <TriangleAlert className="h-5 w-5 text-amber-600" />
            <div>
              <p className="text-2xl font-semibold">
                {formatNumber(data.projects.reduce((total, project) => total + project.findings, 0))}
              </p>
              <p className="text-sm text-muted-foreground">Findings</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle>Organization Projects</CardTitle>
              <CardDescription>Project ownership, target count, and scan history.</CardDescription>
            </div>
            <Button onClick={() => navigate("/scan")}>
              <Radar className="h-4 w-4" />
              Create Scan
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Project</TableHead>
                <TableHead>Targets</TableHead>
                <TableHead>Scans</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.projects.map((project) => (
                <TableRow key={project.id}>
                  <TableCell>
                    <p className="font-medium">{project.name}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">{compactId(project.id)}</p>
                  </TableCell>
                  <TableCell>{project.targets}</TableCell>
                  <TableCell>{project.scans}</TableCell>
                  <TableCell>{project.findings}</TableCell>
                  <TableCell>
                    <Badge variant={project.is_active ? "emerald" : "secondary"}>
                      {project.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatDate(project.created_at)}</TableCell>
                </TableRow>
              ))}
              {!data.projects.length && (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">
                    Projects will be created automatically when scans are started.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Project Activity Trail</CardTitle>
          <CardDescription>Recent project, scan, report, and remediation events with audit integrity metadata.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>User</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Entry Hash</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.auditLogs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>{formatDate(log.timestamp)}</TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      <History className="mr-1 h-3 w-3" />
                      {log.action}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <p className="font-medium">{log.resource_type}</p>
                    <p className="font-mono text-xs text-muted-foreground">{compactId(log.resource_id)}</p>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{compactId(log.user_id)}</TableCell>
                  <TableCell>{log.ip_address ?? "-"}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <Fingerprint className="h-3.5 w-3.5 text-muted-foreground" />
                      {compactId(log.entry_hash)}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {!data.auditLogs.length && (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">
                    Activity events will appear after user, scan, report, or remediation actions.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

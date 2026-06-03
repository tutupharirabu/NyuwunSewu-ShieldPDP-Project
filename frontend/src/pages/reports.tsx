import { Download, FilePlus2, FileText, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";

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
import { Label } from "@/components/ui/label";
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
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { compactId } from "@/lib/utils";

export { ReportsPage as default };
export function ReportsPage() {
  const { data, loading, error, refresh } = useApi(async () => {
    const [reports, projects, scans] = await Promise.all([
      api.reports(),
      api.projects(),
      api.scans(),
    ]);
    return { reports, projects, scans };
  }, []);
  const [projectId, setProjectId] = useState("");
  const [scanId, setScanId] = useState("");
  const [reportType, setReportType] = useState("Compliance Report");
  const [format, setFormat] = useState("html");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const selectedProject = projectId || data?.projects[0]?.id || "";
  const projectScans = useMemo(
    () =>
      data?.scans.filter((scan) => scan.project_id === selectedProject) ?? [],
    [data?.scans, selectedProject],
  );

  if (loading) return <Skeleton className="h-[520px]" />;
  if (error || !data)
    return (
      <EmptyState
        title="Reports unavailable"
        description={error ?? "Unable to load reports."}
      />
    );

  async function generateReport() {
    if (!selectedProject) return;
    setBusy("generate");
    setNotice(null);
    setActionError(null);
    try {
      await api.generateReport(selectedProject, reportType, format, scanId);
      await refresh();
      setNotice("Report generated.");
    } catch (exc) {
      setActionError(
        exc instanceof Error ? exc.message : "Unable to generate report",
      );
    } finally {
      setBusy(null);
    }
  }

  async function download(reportId: string, extension: string) {
    setBusy(reportId);
    setActionError(null);
    try {
      const blob = await api.downloadReport(reportId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${reportId}.${extension}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (exc) {
      setActionError(
        exc instanceof Error ? exc.message : "Unable to download report",
      );
    } finally {
      setBusy(null);
    }
  }

  async function deleteReport(reportId: string) {
    const confirmed = window.confirm(
      "Delete this generated report? This only removes the report export, not scans or findings.",
    );
    if (!confirmed) return;
    setBusy(`delete-${reportId}`);
    setNotice(null);
    setActionError(null);
    try {
      await api.deleteReport(reportId);
      await refresh();
      setNotice("Report deleted.");
    } catch (exc) {
      setActionError(
        exc instanceof Error ? exc.message : "Unable to delete report",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Generate Report</CardTitle>
          <CardDescription>
            Create audit-ready executive, technical, compliance, or remediation
            reports.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {notice && (
            <div className="mb-4 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-700 dark:text-emerald-300">
              {notice}
            </div>
          )}
          {actionError && (
            <div className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {actionError}
            </div>
          )}
          <div className="grid gap-4 lg:grid-cols-[1fr_1fr_220px_160px_auto] lg:items-end">
            <div className="space-y-2">
              <Label>Project</Label>
              <Select
                value={selectedProject}
                onChange={(event) => {
                  setProjectId(event.target.value);
                  setScanId("");
                }}
              >
                {data.projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Scan scope</Label>
              <Select
                value={scanId}
                onChange={(event) => setScanId(event.target.value)}
              >
                <option value="">All project scans</option>
                {projectScans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {compactId(scan.id)} - {scan.status} -{" "}
                    {scan.target_url ?? "target"}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Report type</Label>
              <Select
                value={reportType}
                onChange={(event) => setReportType(event.target.value)}
              >
                <option>Executive Summary</option>
                <option>Technical Report</option>
                <option>Compliance Report</option>
                <option>Remediation Roadmap</option>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Format</Label>
              <Select
                value={format}
                onChange={(event) => setFormat(event.target.value)}
              >
                <option value="html">HTML</option>
                <option value="pdf">PDF</option>
              </Select>
            </div>
            <Button
              disabled={!selectedProject || busy === "generate"}
              onClick={generateReport}
            >
              <FilePlus2 className="h-4 w-4" />
              Generate
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Generated Reports</CardTitle>
          <CardDescription>
            Reports are exported with hash metadata for audit traceability.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {data.reports.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Report</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Scan</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        <div>
                          <p className="font-medium">{report.title}</p>
                          <p className="font-mono text-xs text-muted-foreground">
                            {compactId(report.id)}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>{report.report_type}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {report.scan_id ? compactId(report.scan_id) : "Project"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="emerald">Generated</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {compactId(report.report_hash)}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={
                            busy === report.id || busy === `delete-${report.id}`
                          }
                          onClick={() =>
                            void download(report.id, report.export_format)
                          }
                        >
                          <Download className="h-4 w-4" />
                          Download
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={
                            busy === report.id || busy === `delete-${report.id}`
                          }
                          onClick={() => void deleteReport(report.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="rounded-lg border border-dashed p-10 text-center">
              <p className="font-medium">No reports generated</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Generate a report after scan findings are available.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

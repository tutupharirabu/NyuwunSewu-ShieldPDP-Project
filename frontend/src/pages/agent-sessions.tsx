import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bot,
  CheckCircle,
  Clock,
  ExternalLink,
  Eye,
  MessageSquare,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Terminal,
  XCircle,
  type LucideIcon
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { cn, compactId, formatRelativeTime } from "@/lib/utils";

interface AgentSession {
  id: string;
  agent_name: string;
  target_url: string;
  status: string;
  current_action: string | null;
  logs: Array<{
    timestamp: string;
    level: string;
    message: string;
    action: string | null;
    details: Record<string, unknown>;
  }>;
  pending_action: {
    action: string;
    description: string;
    risk_level: string;
    request: Record<string, unknown>;
    requested_at: string;
  } | null;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

type Severity = "critical" | "high" | "medium" | "low" | "info";

const statusColors: Record<string, string> = {
  idle: "bg-gray-500",
  exploring: "bg-blue-500",
  pending_approval: "bg-yellow-500",
  approved: "bg-green-500",
  denied: "bg-red-500",
  completed: "bg-green-600",
  failed: "bg-red-600"
};

const statusIcons: Record<string, LucideIcon> = {
  idle: Clock,
  exploring: Bot,
  pending_approval: ShieldAlert,
  approved: CheckCircle,
  denied: XCircle,
  completed: CheckCircle,
  failed: XCircle
};

const logLevelColors: Record<string, string> = {
  info: "text-blue-600 dark:text-blue-300",
  warning: "text-yellow-600 dark:text-yellow-300",
  error: "text-red-600 dark:text-red-300",
  success: "text-green-600 dark:text-green-300"
};

const logLevelIcons: Record<string, string> = {
  info: "📝",
  warning: "⚠️",
  error: "❌",
  success: "✅"
};

export function AgentSessionsPage() {
  const { data: sessions, loading, error, refresh } = useApi<AgentSession[]>("/agent-sessions");
  const [selectedSession, setSelectedSession] = useState<AgentSession | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [approvalNotes, setApprovalNotes] = useState("");

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(refresh, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh, refresh]);

  const handleApprove = async (sessionId: string, approved: boolean) => {
    try {
      await api.post(`/agent-sessions/${sessionId}/approve`, {
        approved,
        notes: approvalNotes || undefined
      });
      setApprovalNotes("");
      refresh();
    } catch (err) {
      console.error("Failed to approve action:", err);
    }
  };

  const handleStartSession = async () => {
    // In a real app, this would open a modal to start a new session
    // For now, just refresh
    refresh();
  };

  if (loading && !sessions) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <EmptyState
        icon={XCircle}
        title="Failed to load agent sessions"
        description={error.message}
        action={<Button onClick={refresh}>Retry</Button>}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agent Sessions</h1>
          <p className="text-muted-foreground">
            Monitor and control Phantom agent exploration sessions
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <RefreshCw className={cn("mr-2 h-4 w-4", autoRefresh && "animate-spin")} />
            {autoRefresh ? "Auto-refresh ON" : "Auto-refresh"}
          </Button>
          <Button onClick={refresh} size="sm" variant="outline">
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Session List */}
      <Card>
        <CardHeader>
          <CardTitle>Active Sessions</CardTitle>
          <CardDescription>
            {sessions?.length || 0} session(s) found
          </CardDescription>
        </CardHeader>
        <CardContent>
          {sessions?.length === 0 ? (
            <EmptyState
              icon={Bot}
              title="No agent sessions"
              description="Agent sessions will appear when scans complete and trigger the Phantom agent."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Current Action</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions?.map((session) => {
                  const StatusIcon = statusIcons[session.status] || Clock;
                  return (
                    <TableRow
                      key={session.id}
                      className={cn(
                        "cursor-pointer hover:bg-muted/50",
                        selectedSession?.id === session.id && "bg-muted"
                      )}
                      onClick={() => setSelectedSession(session)}
                    >
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <StatusIcon className="h-4 w-4" />
                          <code className="text-xs">{compactId(session.id)}</code>
                        </div>
                      </TableCell>
                      <TableCell>{session.agent_name}</TableCell>
                      <TableCell>
                        <a
                          href={session.target_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-blue-600 hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="truncate max-w-xs">{session.target_url}</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={cn(
                            "capitalize",
                            statusColors[session.status] && "bg-opacity-20"
                          )}
                        >
                          {session.status.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">
                        {session.current_action || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{session.findings_count}</Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {session.started_at ? formatRelativeTime(session.started_at) : "—"}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedSession(session);
                          }}
                        >
                          <Eye className="h-4 w-4 mr-1" />
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Session Details */}
      {selectedSession && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              Session Details: {compactId(selectedSession.id)}
            </CardTitle>
            <CardDescription>
              {selectedSession.target_url} • Started {selectedSession.started_at ? formatRelativeTime(selectedSession.started_at) : "N/A"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Pending Approval */}
            {selectedSession.pending_action && (
              <Card className="border-yellow-200 bg-yellow-50 dark:bg-yellow-900/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-yellow-800 dark:text-yellow-300">
                    <ShieldAlert className="h-5 w-5" />
                    Pending Approval Required
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <p className="font-medium">{selectedSession.pending_action.action}</p>
                    <p className="text-sm text-muted-foreground">
                      {selectedSession.pending_action.description}
                    </p>
                  </div>
                  <div>
                    <Badge
                      className={cn(
                        selectedSession.pending_action.risk_level === "critical" && "bg-red-500",
                        selectedSession.pending_action.risk_level === "high" && "bg-orange-500",
                        selectedSession.pending_action.risk_level === "medium" && "bg-yellow-500",
                        selectedSession.pending_action.risk_level === "low" && "bg-green-500"
                      )}
                    >
                      Risk: {selectedSession.pending_action.risk_level}
                    </Badge>
                  </div>
                  <div className="space-y-2">
                    <Textarea
                      placeholder="Add notes (optional)..."
                      value={approvalNotes}
                      onChange={(e) => setApprovalNotes(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Button
                        variant="default"
                        onClick={() => handleApprove(selectedSession.id, true)}
                      >
                        <CheckCircle className="mr-2 h-4 w-4" />
                        Approve
                      </Button>
                      <Button
                        variant="destructive"
                        onClick={() => handleApprove(selectedSession.id, false)}
                      >
                        <XCircle className="mr-2 h-4 w-4" />
                        Deny
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Logs */}
            <div>
              <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <MessageSquare className="h-5 w-5" />
                Session Logs ({selectedSession.logs.length})
              </h3>
              <div className="space-y-2 max-h-96 overflow-y-auto rounded-lg border bg-muted/50 p-4">
                {selectedSession.logs.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No logs yet</p>
                ) : (
                  selectedSession.logs.map((log, index) => (
                    <div
                      key={index}
                      className="flex items-start gap-2 text-sm p-2 rounded hover:bg-muted"
                    >
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                      <span className={logLevelColors[log.level] || logLevelColors.info}>
                        {logLevelIcons[log.level] || "📝"}
                      </span>
                      <span className="flex-1">{log.message}</span>
                      {log.action && (
                        <Badge variant="outline" className="text-xs">
                          {log.action}
                        </Badge>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-2">
              <Link to={`/findings?scan_id=${selectedSession.scan_id || ""}`}>
                <Button variant="outline">
                  <Search className="mr-2 h-4 w-4" />
                  View Findings
                </Button>
              </Link>
              <Button variant="outline" onClick={refresh}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh Session
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

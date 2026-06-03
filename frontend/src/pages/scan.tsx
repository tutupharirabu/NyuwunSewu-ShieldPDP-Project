import { FormEvent, useMemo, useState } from "react";
import { Play, ShieldAlert } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api";
import type { ScanStartPayload } from "@/types/api";

function lines(value: string) {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

const DEFAULT_USERNAME_CANDIDATES = "admin\nadministrator\njeruk\ntest\nuser";
const DEFAULT_JWT_SECRETS =
  "secret\njwtsecret\njwt_secret\nsupersecret\nadmin123\nvuln-bank";
const DEFAULT_ADMIN_PATHS =
  "/admin\n/admin/dashboard\n/dashboard\n/api/admin\n/api/admin/analytics\n/sup3r_s3cr3t_admin\n/manage";

export { ScanPage as default };
export function ScanPage() {
  const navigate = useNavigate();
  const { data: projects, loading } = useApi(api.projects, []);
  const [targetUrl, setTargetUrl] = useState("");
  const [projectId, setProjectId] = useState("");
  const [projectName, setProjectName] = useState(
    "Default Security Validation Project",
  );
  const [allowedDomains, setAllowedDomains] = useState("");
  const [excludedPaths, setExcludedPaths] = useState(
    "/payment/live\n/admin/delete",
  );
  const [scopeBoundaries, setScopeBoundaries] = useState("");
  const [rate, setRate] = useState(3);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(100);
  const [allowSqli, setAllowSqli] = useState(true);
  const [allowAuth, setAllowAuth] = useState(true);
  const [allowTiming, setAllowTiming] = useState(false);
  const [initialPaths, setInitialPaths] = useState("");
  const [loginPath, setLoginPath] = useState("/login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const selectedProject = useMemo(
    () => projects?.find((project) => project.id === projectId),
    [projectId, projects],
  );

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const requestedPaths = lines(initialPaths);
      const seededPaths =
        loginPath.trim() && username && password
          ? Array.from(new Set([loginPath.trim(), ...requestedPaths]))
          : requestedPaths;
      const payload: ScanStartPayload = {
        target_url: targetUrl,
        project_id: selectedProject ? selectedProject.id : null,
        project_name: selectedProject ? null : projectName,
        allowed_domains: lines(allowedDomains),
        initial_paths: seededPaths,
        credential_auth:
          username && password
            ? { login_path: loginPath.trim() || "/login", username, password }
            : null,
        policy: {
          name: "Frontend Safe Scan Policy",
          max_requests_per_second: rate,
          allow_sqli_validation: allowSqli,
          allow_auth_validation: allowAuth,
          allow_timing_validation: allowTiming,
          excluded_paths: lines(excludedPaths),
          forbidden_paths: lines(excludedPaths),
          scope_boundaries: lines(scopeBoundaries),
          max_depth: maxDepth,
          max_pages: maxPages,
        },
        primary_headers: {},
        secondary_headers: {},
        admin_headers: {},
        auditor_headers: {},
        custom_role_headers: {},
        exploit_chains: {
          enabled: true,
          username_candidates: lines(DEFAULT_USERNAME_CANDIDATES),
          weak_jwt_secrets: lines(DEFAULT_JWT_SECRETS),
          admin_paths: lines(DEFAULT_ADMIN_PATHS),
          modern_vuln_bank_probes: true,
        },
      };
      const result = await api.startScan(payload);
      setMessage(`Scan ${result.scan_id} queued. Status: ${result.status}.`);
      navigate("/dashboard");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to start scan");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <Skeleton className="h-[620px]" />;

  return (
    <form className="space-y-6" onSubmit={submit}>
      <Card>
        <CardHeader>
          <CardTitle>Create Scan</CardTitle>
          <CardDescription>
            Start a scoped, policy-enforced validation run against an authorized
            target.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-5 xl:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="target">Target URL</Label>
            <Input
              id="target"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(event) => setTargetUrl(event.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label>Project</Label>
            <Select
              value={projectId}
              onChange={(event) => setProjectId(event.target.value)}
            >
              <option value="">Create or use project name</option>
              {(projects ?? []).map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </Select>
          </div>
          {!selectedProject && (
            <div className="space-y-2">
              <Label htmlFor="projectName">Project name</Label>
              <Input
                id="projectName"
                value={projectName}
                onChange={(event) => setProjectName(event.target.value)}
              />
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="domains">Allowed domains</Label>
            <Textarea
              id="domains"
              placeholder="example.com"
              value={allowedDomains}
              onChange={(event) => setAllowedDomains(event.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle>Scan Policy</CardTitle>
            <CardDescription>
              Bound request rate, crawl depth, validation families, and excluded
              paths.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label>Requests per second</Label>
                <Input
                  type="number"
                  min={0.2}
                  max={20}
                  step={0.2}
                  value={rate}
                  onChange={(event) => setRate(Number(event.target.value))}
                />
              </div>
              <div className="space-y-2">
                <Label>Max depth</Label>
                <Input
                  type="number"
                  min={0}
                  max={5}
                  value={maxDepth}
                  onChange={(event) => setMaxDepth(Number(event.target.value))}
                />
              </div>
              <div className="space-y-2">
                <Label>Max pages</Label>
                <Input
                  type="number"
                  min={1}
                  max={5000}
                  value={maxPages}
                  onChange={(event) => setMaxPages(Number(event.target.value))}
                />
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              <label className="flex items-center gap-2 rounded-lg border bg-background p-3 text-sm">
                <input
                  type="checkbox"
                  checked={allowSqli}
                  onChange={(event) => setAllowSqli(event.target.checked)}
                />
                Injection / path validation
              </label>
              <label className="flex items-center gap-2 rounded-lg border bg-background p-3 text-sm">
                <input
                  type="checkbox"
                  checked={allowAuth}
                  onChange={(event) => setAllowAuth(event.target.checked)}
                />
                Auth / API exposure validation
              </label>
              <label className="flex items-center gap-2 rounded-lg border bg-background p-3 text-sm">
                <input
                  type="checkbox"
                  checked={allowTiming}
                  onChange={(event) => setAllowTiming(event.target.checked)}
                />
                Timing probes
              </label>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Excluded and forbidden paths</Label>
                <Textarea
                  value={excludedPaths}
                  onChange={(event) => setExcludedPaths(event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Scope boundaries</Label>
                <Textarea
                  placeholder="example.com"
                  value={scopeBoundaries}
                  onChange={(event) => setScopeBoundaries(event.target.value)}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Authenticated Discovery</CardTitle>
            <CardDescription>
              Optionally start from known entry paths and establish a normal
              application session before crawling deeper.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="initialPaths">Initial entry paths</Label>
              <Textarea
                id="initialPaths"
                value={initialPaths}
                onChange={(event) => setInitialPaths(event.target.value)}
                placeholder={"/login\n/dashboard\n/graphql\n/api/cors-test"}
              />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="loginPath">Login path</Label>
                <Input
                  id="loginPath"
                  value={loginPath}
                  onChange={(event) => setLoginPath(event.target.value)}
                  placeholder="/login"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="authUsername">Username</Label>
                <Input
                  id="authUsername"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="off"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="authPassword">Password</Label>
              <Input
                id="authPassword"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
              />
            </div>
            <div className="rounded-lg border bg-muted/60 p-3 text-sm">
              <div className="flex items-center gap-2 font-medium">
                <ShieldAlert className="h-4 w-4 text-amber-600" />
                Production safety
              </div>
              <p className="mt-2 text-muted-foreground">
                Credentials establish an in-scope session only for this scan and
                are not saved with evidence. Token storage, CORS,
                username-differential, and JWT integrity checks are bounded and
                do not modify account data.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {message && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-700 dark:text-emerald-300">
          {message}
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="flex justify-end">
        <Button type="submit" size="lg" disabled={submitting}>
          <Play className="h-4 w-4" />
          {submitting ? "Starting..." : "Start Scan"}
        </Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <Badge variant="outline">Rate limited</Badge>
        <Badge variant="outline">Tenant scoped</Badge>
        <Badge variant="outline">No destructive payloads</Badge>
        <Badge variant="outline">No off-site token exfiltration</Badge>
      </div>
    </form>
  );
}

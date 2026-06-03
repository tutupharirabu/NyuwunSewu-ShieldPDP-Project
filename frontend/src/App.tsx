import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/layout/app-shell";
import { ProtectedRoute } from "@/components/layout/protected-route";
import { Skeleton } from "@/components/ui/skeleton";

// Lazy load pages - only loaded when route is accessed
const LoginPage = lazy(() => import("@/pages/login"));
const DashboardPage = lazy(() => import("@/pages/dashboard"));
const ProjectsPage = lazy(() => import("@/pages/projects"));
const TargetsPage = lazy(() => import("@/pages/targets"));
const FindingsPage = lazy(() => import("@/pages/findings"));
const CompliancePage = lazy(() => import("@/pages/compliance"));
const ReportsPage = lazy(() => import("@/pages/reports"));
const RemediationPage = lazy(() => import("@/pages/remediation"));
const AgentSessionsPage = lazy(() => import("@/pages/agent-sessions"));
const SettingsPage = lazy(() => import("@/pages/settings"));
const ScanPage = lazy(() => import("@/pages/scan"));
const ScanDetailPage = lazy(() => import("@/pages/scan-detail"));

function PageSkeleton() {
  return (
    <div className="space-y-4 p-6">
      <Skeleton className="h-8 w-48" />
      <div className="grid gap-3 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}

function LazyPage({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageSkeleton />}>{children}</Suspense>;
}

export default function App() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <LazyPage>
            <LoginPage />
          </LazyPage>
        }
      />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route
            path="/dashboard"
            element={
              <LazyPage>
                <DashboardPage />
              </LazyPage>
            }
          />
          <Route
            path="/projects"
            element={
              <LazyPage>
                <ProjectsPage />
              </LazyPage>
            }
          />
          <Route
            path="/targets"
            element={
              <LazyPage>
                <TargetsPage />
              </LazyPage>
            }
          />
          <Route
            path="/findings"
            element={
              <LazyPage>
                <FindingsPage />
              </LazyPage>
            }
          />
          <Route
            path="/compliance"
            element={
              <LazyPage>
                <CompliancePage />
              </LazyPage>
            }
          />
          <Route
            path="/reports"
            element={
              <LazyPage>
                <ReportsPage />
              </LazyPage>
            }
          />
          <Route
            path="/remediation"
            element={
              <LazyPage>
                <RemediationPage />
              </LazyPage>
            }
          />
          <Route
            path="/agent-sessions"
            element={
              <LazyPage>
                <AgentSessionsPage />
              </LazyPage>
            }
          />
          <Route
            path="/audit-logs"
            element={<Navigate to="/projects" replace />}
          />
          <Route
            path="/settings"
            element={
              <LazyPage>
                <SettingsPage />
              </LazyPage>
            }
          />
          <Route
            path="/scan"
            element={
              <LazyPage>
                <ScanPage />
              </LazyPage>
            }
          />
          <Route
            path="/scans/:scanId"
            element={
              <LazyPage>
                <ScanDetailPage />
              </LazyPage>
            }
          />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

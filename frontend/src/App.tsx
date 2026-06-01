import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/layout/app-shell";
import { ProtectedRoute } from "@/components/layout/protected-route";
import { CompliancePage } from "@/pages/compliance";
import { DashboardPage } from "@/pages/dashboard";
import { FindingsPage } from "@/pages/findings";
import { LoginPage } from "@/pages/login";
import { ProjectsPage } from "@/pages/projects";
import { RemediationPage } from "@/pages/remediation";
import { ReportsPage } from "@/pages/reports";
import { ScanPage } from "@/pages/scan";
import { ScanDetailPage } from "@/pages/scan-detail";
import { SettingsPage } from "@/pages/settings";
import { TargetsPage } from "@/pages/targets";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/remediation" element={<RemediationPage />} />
          <Route path="/audit-logs" element={<Navigate to="/projects" replace />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/scan" element={<ScanPage />} />
          <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

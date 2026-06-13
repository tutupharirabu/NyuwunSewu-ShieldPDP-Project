import { useCallback, useEffect, useRef, useState } from "react";

import { primeApiCache } from "@/hooks/use-api";
import { usePoll } from "@/hooks/use-poll";
import { api } from "@/lib/api";
import type {
  AuditLogResponse,
  ComplianceRow,
  DashboardResponse,
  EndpointInventory,
  FindingResponse,
  RemediationSummary,
  ReportResponse,
  ScanSummary,
  TargetSummary,
} from "@/types/api";

export interface DashboardData {
  dashboard: DashboardResponse;
  findings: FindingResponse[];
  scans: ScanSummary[];
  remediations: RemediationSummary[];
  targets: TargetSummary[];
  mappings: ComplianceRow[];
  auditLogs: AuditLogResponse[];
  reports: ReportResponse[];
  focusEndpoints: EndpointInventory[];
  focusScan: ScanSummary | null;
}

const TIER1_POLL_MS = 30_000;
const TIER2_POLL_MS = 90_000;

function whenIdle(cb: () => void): void {
  const ric = (window as unknown as {
    requestIdleCallback?: (cb: () => void) => number;
  }).requestIdleCallback;
  if (ric) ric(cb);
  else window.setTimeout(cb, 200);
}

/**
 * Loads the dashboard in tiers so the page paints on the critical data and the
 * heavier panels stream in, instead of one `Promise.all` blocking on the
 * slowest endpoint and re-polling everything every 30s.
 *
 * - Tier 1 (dashboard, scans + focus endpoints): gates first paint, polls 30s.
 * - Tier 2 (findings, remediations, targets, compliance): fills panels, polls 90s.
 * - Tier 3 (audit-logs trimmed, reports): feeds the activity feed, fetched once.
 *
 * After first paint it also warms the cache for other pages (findings, targets,
 * projects) on idle so navigating there is instant.
 */
export function useDashboardData() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prefetched = useRef(false);

  // Merge a partial update onto the existing data. No-op until Tier 1 has
  // established the base object (so a stray Tier 2/3 result is simply ignored
  // and picked up on the next poll).
  const merge = useCallback((patch: Partial<DashboardData>) => {
    setData((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const loadTier1 = useCallback(async () => {
    try {
      const [dashboard, scans] = await Promise.all([api.dashboard(), api.scans()]);
      const focusScan =
        scans.find((scan) =>
          ["queued", "running", "stopping"].includes(scan.status),
        ) ??
        scans[0] ??
        null;
      const focusEndpoints = focusScan
        ? await api
            .scanEndpoints(focusScan.id)
            .catch(() => [] as EndpointInventory[])
        : [];
      setData((prev) => ({
        findings: prev?.findings ?? [],
        remediations: prev?.remediations ?? [],
        targets: prev?.targets ?? [],
        mappings: prev?.mappings ?? [],
        auditLogs: prev?.auditLogs ?? [],
        reports: prev?.reports ?? [],
        ...prev,
        dashboard,
        scans,
        focusScan,
        focusEndpoints,
      }));
      setError(null);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTier2 = useCallback(async () => {
    const [findings, remediations, targets, compliance] = await Promise.all([
      api.findings(undefined, undefined, 100),
      api.remediations().catch(() => [] as RemediationSummary[]),
      api.targets().catch(() => [] as TargetSummary[]),
      api.compliance().catch(() => ({
        organization_id: "",
        mappings: [] as ComplianceRow[],
      })),
    ]);
    merge({ findings, remediations, targets, mappings: compliance.mappings });
  }, [merge]);

  const loadTier3 = useCallback(async () => {
    const [auditLogs, reports] = await Promise.all([
      api.auditLogs(undefined, 20).catch(() => [] as AuditLogResponse[]),
      api.reports().catch(() => [] as ReportResponse[]),
    ]);
    merge({ auditLogs, reports });
  }, [merge]);

  const prefetchOtherPages = useCallback(() => {
    if (prefetched.current) return;
    prefetched.current = true;
    void api
      .findings()
      .then((res) => primeApiCache("findings", res))
      .catch(() => undefined);
    void api
      .targets()
      .then((res) => primeApiCache("targets", res))
      .catch(() => undefined);
    void api
      .projects()
      .then((res) => primeApiCache("projects", res))
      .catch(() => undefined);
  }, []);

  // Initial staggered sequence: paint on Tier 1, then Tier 2, then Tier 3 +
  // background prefetch on idle.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await loadTier1();
      if (cancelled) return;
      void loadTier2();
      whenIdle(() => {
        if (cancelled) return;
        void loadTier3();
        prefetchOtherPages();
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [loadTier1, loadTier2, loadTier3, prefetchOtherPages]);

  // Keep live data fresh; Tier 3 is one-shot (no poll).
  usePoll(loadTier1, TIER1_POLL_MS, true, true);
  usePoll(loadTier2, TIER2_POLL_MS, true, false);

  const refresh = useCallback(async () => {
    await loadTier1();
    void loadTier2();
  }, [loadTier1, loadTier2]);

  return { data, loading, error, refresh };
}

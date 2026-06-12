import { useCallback, useEffect, useRef } from "react";

// Periodically calls `refresh`, but never lets two refreshes overlap: while one
// is in flight, ticks are skipped. Without this guard a slow/saturated backend
// gets buried under a backlog of periodic requests that arrive faster than it
// can answer them — each tick piles another full batch onto a single worker,
// so per-request latency climbs unbounded (seconds -> minutes).
//
// Ticks are also skipped while the tab is hidden. Pass `refreshOnVisible` to
// trigger one (guarded) refresh when the tab becomes visible again.
export function usePoll(
  refresh: () => Promise<unknown>,
  intervalMs: number,
  enabled = true,
  refreshOnVisible = false,
) {
  const inFlight = useRef(false);

  const guarded = useCallback(async () => {
    if (inFlight.current || document.hidden) return;
    inFlight.current = true;
    try {
      await refresh();
    } finally {
      inFlight.current = false;
    }
  }, [refresh]);

  useEffect(() => {
    if (!enabled) return;
    const timer = window.setInterval(() => void guarded(), intervalMs);
    const onVisible = refreshOnVisible ? () => void guarded() : null;
    if (onVisible) document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      if (onVisible) document.removeEventListener("visibilitychange", onVisible);
    };
  }, [guarded, intervalMs, enabled, refreshOnVisible]);
}

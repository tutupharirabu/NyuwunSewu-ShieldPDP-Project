import { useEffect, useState } from "react";

import { primeApiCache, readApiCache } from "@/hooks/use-api";
import { api } from "@/lib/api";
import type { FindingResponse } from "@/types/api";

// The backend caps a single /findings response at 500 rows, so a full page is
// our signal that more findings may exist beyond this offset.
const PAGE_LIMIT = 500;
// Small gap between background batches so the trailing pages trickle in instead
// of hammering the API right after the first page lands.
const BATCH_DELAY_MS = 400;

function whenIdle(cb: () => void): void {
  const ric = (
    window as unknown as {
      requestIdleCallback?: (cb: () => void) => number;
    }
  ).requestIdleCallback;
  if (ric) ric(cb);
  else window.setTimeout(cb, 200);
}

/**
 * Loads findings in 500-row pages. The first page gates the loading state and
 * paints exactly like the old single fetch; any further pages are appended
 * silently in the background (on idle, spaced out) until a short page signals
 * the end. The growing list is mirrored into the shared `findings` cache so
 * navigating away and back renders instantly from the last result.
 */
export function useProgressiveFindings() {
  const cached = readApiCache<FindingResponse[]>("findings");
  const [data, setData] = useState<FindingResponse[] | null>(cached ?? null);
  const [loading, setLoading] = useState(cached === undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const timers: number[] = [];

    async function loadFrom(offset: number, accumulated: FindingResponse[]) {
      let batch: FindingResponse[];
      try {
        batch = await api.findings(undefined, undefined, PAGE_LIMIT, offset);
      } catch (exc) {
        if (cancelled) return;
        // Only surface an error when the first page fails; a background page
        // failing leaves the already-rendered findings in place and stops.
        if (offset === 0) {
          setError(exc instanceof Error ? exc.message : "Request failed");
          setLoading(false);
        }
        return;
      }
      if (cancelled) return;

      const merged = offset === 0 ? batch : [...accumulated, ...batch];
      setData(merged);
      primeApiCache("findings", merged);
      if (offset === 0) setLoading(false);

      // A full page means there may be more — fetch the next once the browser
      // is idle, after a short delay, so the rest streams in quietly.
      if (batch.length === PAGE_LIMIT) {
        whenIdle(() => {
          if (cancelled) return;
          const timer = window.setTimeout(() => {
            void loadFrom(offset + PAGE_LIMIT, merged);
          }, BATCH_DELAY_MS);
          timers.push(timer);
        });
      }
    }

    void loadFrom(0, []);

    return () => {
      cancelled = true;
      for (const timer of timers) window.clearTimeout(timer);
    };
  }, []);

  return { data, loading, error };
}

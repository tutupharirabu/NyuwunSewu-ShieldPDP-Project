import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";

// Module-level cache shared across mounts so revisiting a page can render
// instantly from the last response while a fresh request revalidates in the
// background (stale-while-revalidate).
const apiCache = new Map<string, unknown>();

export function clearApiCache(cacheKey?: string) {
  if (cacheKey) apiCache.delete(cacheKey);
  else apiCache.clear();
}

// Pre-seed the cache so a later useApi(loader, deps, key) renders instantly from
// it (stale-while-revalidate). Used to warm other pages' data in the background
// after the dashboard's critical content has painted.
export function primeApiCache(cacheKey: string, value: unknown) {
  apiCache.set(cacheKey, value);
}

export function useApi<T>(
  loader: () => Promise<T>,
  deps: DependencyList = [],
  cacheKey?: string,
) {
  const cached = cacheKey
    ? (apiCache.get(cacheKey) as T | undefined)
    : undefined;
  const [data, setData] = useState<T | null>(cached ?? null);
  // Skip the loading skeleton when we already have a cached value to show.
  const [loading, setLoading] = useState(cached === undefined);
  const [error, setError] = useState<string | null>(null);
  const loadedRef = useRef(cached !== undefined);
  const requestRef = useRef(0);

  const run = useCallback(async () => {
    const requestId = ++requestRef.current;
    if (!loadedRef.current) {
      setLoading(true);
    }
    setError(null);
    try {
      const response = await loader();
      if (requestId !== requestRef.current) return;
      setData(response);
      loadedRef.current = true;
      if (cacheKey) apiCache.set(cacheKey, response);
    } catch (exc) {
      if (requestId !== requestRef.current) return;
      setError(exc instanceof Error ? exc.message : "Request failed");
    } finally {
      if (requestId === requestRef.current) {
        setLoading(false);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    void run();
  }, [run]);

  return { data, loading, error, refresh: run };
}

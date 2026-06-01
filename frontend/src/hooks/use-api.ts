import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";

export function useApi<T>(loader: () => Promise<T>, deps: DependencyList = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const loadedRef = useRef(false);
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
    } catch (exc) {
      if (requestId !== requestRef.current) return;
      setError(exc instanceof Error ? exc.message : "Request failed");
    } finally {
      if (requestId === requestRef.current) {
        setLoading(false);
      }
    }
  }, deps);

  useEffect(() => {
    void run();
  }, [run]);

  return { data, loading, error, refresh: run };
}

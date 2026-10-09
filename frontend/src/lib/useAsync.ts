/** Minimal async-data hook.
 *
 * Deliberately not a cache. Every panel reads one analysis snapshot that
 * changes only when the user re-runs the analysis, so the useful primitive is
 * "fetch this, tell me if it failed, let me refetch" — nothing more.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "./api";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: { message: string; hint?: string } | null;
  reload: () => void;
}

export function useAsync<T>(fetcher: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{ message: string; hint?: string } | null>(null);
  const [nonce, setNonce] = useState(0);
  // Guards against a slow response from a previous dependency set landing
  // after a newer one and overwriting it.
  const generation = useRef(0);

  useEffect(() => {
    const mine = ++generation.current;
    setLoading(true);
    setError(null);
    fetcher()
      .then((result) => {
        if (generation.current === mine) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((caught: unknown) => {
        if (generation.current !== mine) return;
        setError(
          caught instanceof ApiError
            ? { message: caught.message, hint: caught.hint }
            : { message: caught instanceof Error ? caught.message : String(caught) },
        );
        setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  return { data, loading, error, reload };
}

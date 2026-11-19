import { useCallback, useEffect, useState } from "react";
import { describeError } from "./api";
import { useAuth } from "./auth";

export interface Loadable<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Load once on mount and whenever `key` changes, with a manual reload. */
export function useLoad<T>(load: () => Promise<T>, key: string, intervalMs?: number): Loadable<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  // A new token, or a sign-out, runs every loader again.
  const { version: authVersion } = useAuth();

  // A manual retry drops the old error so the loading state shows instead of a stale failure.
  const reload = useCallback(() => {
    setError(null);
    setTick((value) => value + 1);
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    load()
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setError(describeError(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
    // `load` is intentionally keyed by `key` and `tick`, not by identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick, authVersion]);

  useEffect(() => {
    if (!intervalMs) return undefined;
    // A background refresh keeps any shown error until it succeeds, so the banner does not flicker.
    const timer = window.setInterval(() => setTick((value) => value + 1), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);

  return { data, error, loading, reload };
}

export type Route =
  | { name: "triage" }
  | { name: "new-scan" }
  | { name: "cache" }
  | { name: "skill"; skillId: string };

export function parseRoute(hash: string): Route {
  const path = hash.replace(/^#\/?/, "");
  if (path === "new") return { name: "new-scan" };
  if (path === "cache") return { name: "cache" };
  const match = /^skill\/([0-9a-f-]{36})$/i.exec(path);
  if (match) return { name: "skill", skillId: match[1] };
  return { name: "triage" };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

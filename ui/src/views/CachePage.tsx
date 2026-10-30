import { useState } from "react";
import { api } from "../api";
import { Card, ErrorBox, Loading } from "../components";
import { useLoad } from "../hooks";

export function CachePage() {
  const stats = useLoad(api.cacheStats, "cache");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function clear() {
    if (!window.confirm("Remove all cached verdicts? Scans will run again on the next request.")) return;
    setBusy(true);
    setFailure(null);
    try {
      const result = await api.clearCache();
      setMessage(`Removed ${result.deleted} cached verdict(s); ${result.retained} retained.`);
      stats.reload();
    } catch (err) {
      setFailure(err instanceof Error ? err.message : "Could not clear the cache.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page">
      <div className="page-head">
        <h1>Cache</h1>
      </div>
      {stats.error ? <ErrorBox error={stats.error} /> : null}
      {stats.loading && !stats.data ? <Loading /> : null}
      {stats.data ? (
        <Card
          title="Verdict cache"
          actions={
            <button type="button" className="danger" onClick={clear} disabled={busy}>
              Clear cache
            </button>
          }
        >
          <dl className="facts">
            <dt>Entries</dt>
            <dd>{stats.data.entries}</dd>
            <dt>Database size</dt>
            <dd>{formatBytes(stats.data.dbSizeBytes)}</dd>
            <dt>Engine</dt>
            <dd className="mono">{stats.data.engineVersion}</dd>
            <dt>Model</dt>
            <dd className="mono">{stats.data.modelVersion}</dd>
          </dl>
          <p className="muted">
            A cache entry is keyed on the skill's content hash and the engine and model versions, so changing either
            one invalidates old verdicts.
          </p>
          {message ? <p role="status">{message}</p> : null}
          {failure ? <ErrorBox error={failure} /> : null}
        </Card>
      ) : null}
    </section>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

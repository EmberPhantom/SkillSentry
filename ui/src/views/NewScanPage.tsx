import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, openScanStream, type ScanOptions, type WSMessage } from "../api";
import { ErrorBox, formatTime } from "../components";

const DEFAULT_OPTIONS: ScanOptions = { noCache: false, sandbox: true, poisonedWell: true, timeoutS: 60 };

export function NewScanPage() {
  const [path, setPath] = useState("");
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [events, setEvents] = useState<WSMessage[]>([]);
  const [streamOpen, setStreamOpen] = useState(false);
  const closeStream = useRef<(() => void) | null>(null);

  useEffect(() => () => closeStream.current?.(), []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!path.trim()) {
      setError("Enter a path to a skill folder.");
      return;
    }
    setSubmitting(true);
    setError(null);
    setEvents([]);
    closeStream.current?.();
    try {
      const started = await api.startScan(path.trim(), options);
      setScanId(started.scanId);
      setStreamOpen(true);
      closeStream.current = openScanStream(
        started.scanId,
        (message) => setEvents((prior) => [...prior, message]),
        () => setStreamOpen(false),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the scan.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="page">
      <div className="page-head">
        <h1>New scan</h1>
      </div>

      <form className="scan-form" onSubmit={submit}>
        <label className="field">
          <span>Skill folder</span>
          <input
            type="text"
            value={path}
            placeholder="C:\\path\\to\\skill"
            onChange={(event) => setPath(event.target.value)}
            required
          />
          <small className="muted">The server reads this path, so it must be reachable from the server.</small>
        </label>

        <fieldset className="options">
          <legend>Options</legend>
          <label>
            <input
              type="checkbox"
              checked={options.sandbox}
              onChange={(event) => setOptions({ ...options, sandbox: event.target.checked })}
            />
            Run in the Docker sandbox
          </label>
          <label>
            <input
              type="checkbox"
              checked={options.poisonedWell}
              onChange={(event) => setOptions({ ...options, poisonedWell: event.target.checked })}
            />
            Active defense (Poisoned Well)
          </label>
          <label>
            <input
              type="checkbox"
              checked={options.noCache}
              onChange={(event) => setOptions({ ...options, noCache: event.target.checked })}
            />
            Ignore the cache
          </label>
          <label className="field inline">
            <span>Timeout (s)</span>
            <input
              type="number"
              min={5}
              max={600}
              value={options.timeoutS}
              onChange={(event) => setOptions({ ...options, timeoutS: Number(event.target.value) })}
            />
          </label>
        </fieldset>

        <div className="actions">
          <button type="submit" disabled={submitting}>
            {submitting ? "Starting…" : "Start scan"}
          </button>
        </div>
      </form>

      {error ? <ErrorBox error={error} /> : null}

      {scanId ? (
        <section className="card" aria-live="polite">
          <div className="card-head">
            <h2>Live console</h2>
            <span className={`pill ${streamOpen ? "ok" : ""}`}>{streamOpen ? "streaming" : "finished"}</span>
          </div>
          <ol className="console">
            {events.length === 0 ? <li className="muted">Waiting for the first stage…</li> : null}
            {events.map((message, index) => (
              <li key={`${message.ts}-${index}`}>
                <span className="muted nowrap">{formatTime(message.ts)}</span>{" "}
                <strong>{message.stage}</strong> <span>{message.event}</span>
                {message.detail?.message ? <span> — {String(message.detail.message)}</span> : null}
              </li>
            ))}
          </ol>
          {!streamOpen ? (
            <p>
              <a href="#/">Back to triage</a> once the verdict appears in the table.
            </p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}

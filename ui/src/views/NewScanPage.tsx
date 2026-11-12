import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, openScanStream, verdictSkillId, type ScanOptions, type ScanStream, type WSMessage } from "../api";
import { ErrorBox, formatTime } from "../components";
import { TIMEOUT_MAX_S, TIMEOUT_MIN_S, parseTimeout } from "../scanOptions";

const DEFAULT_OPTIONS: ScanOptions = { noCache: false, sandbox: true, poisonedWell: true };
const DEFAULT_TIMEOUT_TEXT = "60";

type RunStatus = "running" | "cancelling" | "completed" | "cancelled" | "closed";

const STATUS_PILL: Record<RunStatus, { label: string; tone: string }> = {
  running: { label: "streaming", tone: "ok" },
  cancelling: { label: "cancelling", tone: "warn" },
  completed: { label: "completed", tone: "ok" },
  cancelled: { label: "cancelled", tone: "warn" },
  closed: { label: "finished", tone: "" },
};

export function NewScanPage() {
  const [path, setPath] = useState("");
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [timeoutText, setTimeoutText] = useState(DEFAULT_TIMEOUT_TEXT);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [events, setEvents] = useState<WSMessage[]>([]);
  const [status, setStatus] = useState<RunStatus>("closed");
  const [skillId, setSkillId] = useState<string | null>(null);
  const stream = useRef<ScanStream | null>(null);
  // Bumped on every new run and on unmount, so callbacks from an old socket are ignored.
  const runToken = useRef(0);

  useEffect(
    () => () => {
      runToken.current += 1;
      stream.current?.close();
    },
    [],
  );

  function handleMessage(message: WSMessage) {
    setEvents((prior) => [...prior, message]);
    if (message.event === "error" && message.detail?.code === "cancelled") {
      setStatus("cancelled");
    } else if (message.event === "completed") {
      setStatus("completed");
      setSkillId(verdictSkillId(message));
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!path.trim()) {
      setError("Enter a path to a skill folder.");
      return;
    }
    const timeout = parseTimeout(timeoutText);
    if (!timeout.ok) {
      setError(timeout.error);
      return;
    }

    const token = runToken.current + 1;
    runToken.current = token;
    stream.current?.close();
    stream.current = null;
    setSubmitting(true);
    setError(null);
    setEvents([]);
    setScanId(null);
    setSkillId(null);
    setStatus("closed");
    try {
      // A blank timeout leaves timeoutS undefined, so the request omits timeout_s.
      const started = await api.startScan(path.trim(), { ...options, timeoutS: timeout.value });
      if (runToken.current !== token) return;
      setScanId(started.scanId);
      setStatus("running");
      stream.current = openScanStream(
        started.scanId,
        (message) => {
          if (runToken.current === token) handleMessage(message);
        },
        () => {
          if (runToken.current !== token) return;
          // A cancel the server acknowledges by closing the socket has no separate event.
          setStatus((prior) => (prior === "cancelling" ? "cancelled" : prior === "running" ? "closed" : prior));
        },
      );
    } catch (err) {
      // Server validation errors arrive as readable "field: message" strings; show them unchanged.
      setError(err instanceof Error ? err.message : "Could not start the scan.");
    } finally {
      setSubmitting(false);
    }
  }

  function cancelScan() {
    if (!stream.current) return;
    setStatus("cancelling");
    stream.current.cancel();
  }

  const running = status === "running" || status === "cancelling";

  return (
    <section className="page">
      <div className="page-head">
        <h1>New scan</h1>
      </div>

      {/* noValidate: the timeout bounds are checked in submit() so the message is ours, not the browser's. */}
      <form className="scan-form" onSubmit={submit} noValidate>
        <label className="field">
          <span>Skill folder</span>
          <input
            type="text"
            value={path}
            placeholder="/path/to/skill-folder"
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
              inputMode="numeric"
              min={TIMEOUT_MIN_S}
              max={TIMEOUT_MAX_S}
              step={1}
              placeholder="Server default"
              value={timeoutText}
              onChange={(event) => setTimeoutText(event.target.value)}
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
            <div className="head-meta">
              <span className={`pill ${STATUS_PILL[status].tone}`}>{STATUS_PILL[status].label}</span>
              {running ? (
                <button type="button" className="danger" disabled={status === "cancelling"} onClick={cancelScan}>
                  {status === "cancelling" ? "Cancelling…" : "Cancel scan"}
                </button>
              ) : null}
            </div>
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

          {status === "completed" ? (
            <p>
              {skillId ? <a href={`#/skill/${skillId}`}>Open verdict</a> : <span>Verdict recorded.</span>}
              {" · "}
              <a href="#/">Back to triage</a>
            </p>
          ) : null}
          {status === "cancelled" ? (
            <p>
              Scan cancelled before a verdict was produced. <a href="#/">Back to triage</a>
            </p>
          ) : null}
          {status === "closed" ? (
            <p>
              The stream ended. <a href="#/">Back to triage</a> to check the table.
            </p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}

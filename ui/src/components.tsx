import type { ReactNode } from "react";
import type { Severity, VerdictTier } from "./api";

export function VerdictPill({ verdict }: { verdict: VerdictTier | null }) {
  if (!verdict) return <span className="pill">pending</span>;
  const tone = verdict === "SAFE" ? "ok" : verdict === "SUSPICIOUS" ? "warn" : "bad";
  return <span className={`pill ${tone}`}>{verdict}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  const tone =
    severity === "critical" || severity === "high"
      ? "bad"
      : severity === "medium"
        ? "warn"
        : "";
  return <span className={`pill ${tone}`}>{severity}</span>;
}

/** Risk score 0-100 with the verdict thresholds marked (SAFE < 30, MALICIOUS > 70). */
export function RiskBar({ score }: { score: number | null }) {
  if (score === null) return <span className="muted">n/a</span>;
  const clamped = Math.max(0, Math.min(100, score));
  return (
    <div
      className="risk"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      aria-label={`risk ${clamped} of 100`}
    >
      <div className="risk-fill" style={{ width: `${clamped}%` }} />
      <span className="risk-value">{clamped}</span>
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <p className="muted" role="status">{label}…</p>;
}

export function ErrorBox({ error }: { error: string }) {
  return (
    <div className="error" role="alert">
      {error}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

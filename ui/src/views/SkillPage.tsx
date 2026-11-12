import { useState } from "react";
import { api, type Finding, type SkillDetail } from "../api";
import { Card, Empty, ErrorBox, Loading, RiskBar, SeverityPill, VerdictPill, formatTime } from "../components";
import { useLoad } from "../hooks";

type Tab = "overview" | "findings" | "vision" | "sandbox" | "defense" | "export";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "vision", label: "Vision" },
  { id: "sandbox", label: "Sandbox" },
  { id: "defense", label: "Poisoned Well" },
  { id: "export", label: "Export" },
];

export function SkillPage({ skillId }: { skillId: string }) {
  const detail = useLoad<SkillDetail>(() => api.skill(skillId), skillId);
  const [tab, setTab] = useState<Tab>("overview");

  if (detail.error) {
    return (
      <section className="page">
        <a className="back" href="#/">
          ← Triage
        </a>
        <ErrorBox error={detail.error} />
      </section>
    );
  }
  if (!detail.data) return <Loading label="Loading skill" />;
  const data = detail.data;
  const verdict = data.verdict;

  return (
    <section className="page">
      <a className="back" href="#/">
        ← Triage
      </a>
      <div className="page-head">
        <h1>{verdict.skill}</h1>
        <div className="head-meta">
          <VerdictPill verdict={verdict.verdict} />
          <RiskBar score={verdict.riskScore} />
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label="Skill sections">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={`tab-${item.id}`}
            aria-selected={tab === item.id}
            aria-controls={`panel-${item.id}`}
            className={tab === item.id ? "tab active" : "tab"}
            onClick={() => setTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "overview" ? (
          <Card title="Verdict">
            <dl className="facts">
              <dt>Confidence</dt>
              <dd>{verdict.confidence.toFixed(2)}</dd>
              <dt>Cached</dt>
              <dd>{verdict.cached ? "yes" : "no"}</dd>
              <dt>Scan time</dt>
              <dd>{verdict.scanDurationMs} ms</dd>
              <dt>Scan ID</dt>
              <dd className="mono">{verdict.scanId}</dd>
            </dl>
            <h3>Findings</h3>
            <FindingList findings={verdict.findings} />
          </Card>
        ) : null}

        {tab === "findings" ? (
          <Card title="Static findings">
            {data.staticFindings.length === 0 ? (
              <Empty>No static findings for this skill.</Empty>
            ) : (
              <ul className="code-findings">
                {data.staticFindings.map((item, index) => (
                  <li key={`${item.file}-${item.line}-${index}`} className={item.highlight ? "highlight" : ""}>
                    <div className="code-head">
                      <SeverityPill severity={item.severity} />
                      <span className="mono">
                        {item.file}:{item.line}
                      </span>
                      <span className="muted">{item.stage}</span>
                    </div>
                    <p>{item.message}</p>
                    {item.code ? <pre className="code">{item.code}</pre> : null}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        ) : null}

        {tab === "vision" ? (
          <Card title="Vision evidence">
            {data.visionEvidence.length === 0 ? (
              <Empty>No images were scanned for this skill.</Empty>
            ) : (
              data.visionEvidence.map((item, index) => (
                <article key={index} className="vision">
                  <h3>{item.imageName ?? `image ${index + 1}`}</h3>
                  {item.positionNote ? <p className="muted">{item.positionNote}</p> : null}
                  {item.ocr ? <pre className="code">{item.ocr}</pre> : <p className="muted">No text recovered.</p>}
                  <p className="muted">
                    {item.bboxes?.length ?? 0} region(s) flagged
                    {item.confidence !== undefined ? `, confidence ${item.confidence.toFixed(2)}` : ""}
                  </p>
                  <FindingList findings={item.findings ?? []} />
                </article>
              ))
            )}
          </Card>
        ) : null}

        {tab === "sandbox" ? (
          <Card title="Sandbox trace">
            <p className="muted">
              {data.sandboxTrace.resourceUsage.durationMs} ms, peak {data.sandboxTrace.resourceUsage.peakMemoryMb} MB,
              CPU {data.sandboxTrace.resourceUsage.cpuPercent}%
            </p>
            <h3>Events</h3>
            {data.sandboxTrace.events.length === 0 ? (
              <Empty>No sandbox events were recorded.</Empty>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Event</th>
                      <th scope="col">Path or channel</th>
                      <th scope="col">Marker</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sandboxTrace.events.map((row, index) => (
                      <tr key={index}>
                        <td className="muted nowrap">{formatTime(row.ts)}</td>
                        <td>{row.eventType}</td>
                        <td className="mono">{row.pathOrChannel}</td>
                        <td className="mono">{row.marker ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <h3>Network</h3>
            {data.sandboxTrace.netLogs.length === 0 ? (
              <Empty>No outbound requests were captured.</Empty>
            ) : (
              <ul className="plain">
                {data.sandboxTrace.netLogs.map((row, index) => (
                  <li key={index}>
                    <span className="pill">{row.protocol}</span> <span className="mono">{row.queryOrUrl}</span>{" "}
                    <span className="muted">→ {row.responderAction}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        ) : null}

        {tab === "defense" ? (
          <Card title="Poisoned Well">
            {data.poisonedWell.confirmed ? (
              <p>
                <span className="pill bad">Exfiltration confirmed</span>
              </p>
            ) : (
              <Empty>No canary exfiltration was observed.</Empty>
            )}
            {data.poisonedWell.activeDefense ? (
              <dl className="facts">
                <dt>Exfil channel</dt>
                <dd>{data.poisonedWell.activeDefense.exfilChannel ?? "none"}</dd>
                <dt>Canary marker</dt>
                <dd className="mono">{data.poisonedWell.activeDefense.canaryMarker ?? "none"}</dd>
                <dt>C2 indicators</dt>
                <dd className="mono">{data.poisonedWell.activeDefense.c2Indicators.join(", ") || "none"}</dd>
              </dl>
            ) : null}
            <h3>Timeline</h3>
            {data.poisonedWell.timeline.length === 0 ? (
              <Empty>No timeline recorded.</Empty>
            ) : (
              <ol className="timeline">
                {data.poisonedWell.timeline.map((row, index) => (
                  <li key={index}>
                    <span className="muted nowrap">{formatTime(row.ts)}</span> {row.label}
                    {row.marker ? <span className="mono"> [{row.marker}]</span> : null}
                  </li>
                ))}
              </ol>
            )}
            <h3>Relationships</h3>
            {data.poisonedWell.graph.edges.length === 0 ? (
              <Empty>No relationships to show.</Empty>
            ) : (
              <ul className="plain">
                {data.poisonedWell.graph.edges.map((edge, index) => {
                  const from = data.poisonedWell.graph.nodes.find((node) => node.id === edge.source);
                  const to = data.poisonedWell.graph.nodes.find((node) => node.id === edge.target);
                  return (
                    <li key={index}>
                      <span className="mono">{from?.label ?? edge.source}</span>{" "}
                      <span className="muted">{edge.label}</span>{" "}
                      <span className="mono">{to?.label ?? edge.target}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        ) : null}

        {tab === "export" ? (
          <Card title="Export">
            <p className="muted">Reports are rendered from the stored scan. Nothing is re-run.</p>
            <div className="actions">
              <a className="button" href={data.reportLinks.markdown}>
                Markdown
              </a>
              <a className="button" href={data.reportLinks.sarif}>
                SARIF 2.1.0
              </a>
              {data.reportLinks.stix ? (
                <a className="button" href={data.reportLinks.stix}>
                  STIX 2.1
                </a>
              ) : (
                <span className="muted">STIX is available only when indicators were captured.</span>
              )}
            </div>
          </Card>
        ) : null}
      </div>
    </section>
  );
}

function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return <Empty>No findings.</Empty>;
  return (
    <ul className="plain findings">
      {findings.map((finding, index) => (
        <li key={index}>
          <SeverityPill severity={finding.severity} />{" "}
          <span className="muted">{finding.stage}</span> {finding.message}
          {finding.evidence.file ? (
            <div className="mono muted">
              {finding.evidence.file}
              {finding.evidence.line ? `:${finding.evidence.line}` : ""}
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

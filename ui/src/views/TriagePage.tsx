import { useMemo, useState } from "react";
import { api, type ScanSummary, type VerdictTier } from "../api";
import { Empty, ErrorBox, Loading, RiskBar, VerdictPill, formatTime } from "../components";
import { useLoad } from "../hooks";

type Filter = "all" | VerdictTier;
type SortKey = "risk" | "name" | "time";

export function TriagePage() {
  const scans = useLoad(api.scans, "scans", 5000);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortKey>("risk");

  const rows = useMemo(() => {
    const list: ScanSummary[] = scans.data?.scans ?? [];
    const needle = query.trim().toLowerCase();
    const filtered = list.filter(
      (row) =>
        (filter === "all" || row.verdict === filter) &&
        (needle === "" || row.skill.toLowerCase().includes(needle)),
    );
    return [...filtered].sort((a, b) => {
      if (sort === "name") return a.skill.localeCompare(b.skill);
      if (sort === "time") return b.startedAt.localeCompare(a.startedAt);
      return (b.riskScore ?? -1) - (a.riskScore ?? -1);
    });
  }, [scans.data, filter, query, sort]);

  return (
    <section className="page">
      <div className="page-head">
        <h1>Triage</h1>
        <button type="button" className="ghost" onClick={scans.reload}>
          Refresh
        </button>
      </div>

      <div className="toolbar">
        <div className="chips" role="group" aria-label="Filter by verdict">
          {(["all", "MALICIOUS", "SUSPICIOUS", "SAFE"] as const).map((value) => (
            <button
              key={value}
              type="button"
              className={`chip ${filter === value ? "active" : ""}`}
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
            >
              {value === "all" ? "All" : value}
            </button>
          ))}
        </div>
        <input
          type="search"
          placeholder="Search skills"
          aria-label="Search skills"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <label className="sort">
          Sort
          <select value={sort} onChange={(event) => setSort(event.target.value as SortKey)}>
            <option value="risk">Risk</option>
            <option value="name">Name</option>
            <option value="time">Newest</option>
          </select>
        </label>
      </div>

      {scans.error ? <ErrorBox error={scans.error} /> : null}
      {scans.loading && !scans.data ? <Loading label="Loading scans" /> : null}
      {scans.data && rows.length === 0 ? (
        <Empty>
          No scans match. <a href="#/new">Start a scan</a> to add a skill.
        </Empty>
      ) : null}

      {rows.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Skill</th>
                <th scope="col">Verdict</th>
                <th scope="col">Risk</th>
                <th scope="col">Key finding</th>
                <th scope="col">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.scanId}>
                  <td>
                    {row.skillId && row.verdict ? (
                      <a href={`#/skill/${row.skillId}`}>{row.skill}</a>
                    ) : (
                      <span>{row.skill}</span>
                    )}
                    {row.cached ? <span className="pill cached">cached</span> : null}
                  </td>
                  <td>
                    <VerdictPill verdict={row.verdict} />
                  </td>
                  <td className="risk-cell">
                    <RiskBar score={row.riskScore} />
                  </td>
                  <td className="finding-cell">{row.keyFinding ?? <span className="muted">none</span>}</td>
                  <td className="muted nowrap">{formatTime(row.startedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

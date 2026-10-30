import { api, type Health, type Meta } from "./api";
import { useLoad, useRoute } from "./hooks";
import { CachePage } from "./views/CachePage";
import { NewScanPage } from "./views/NewScanPage";
import { SkillPage } from "./views/SkillPage";
import { TriagePage } from "./views/TriagePage";

export function App() {
  const route = useRoute();
  const meta = useLoad<Meta>(api.meta, "meta");
  const health = useLoad<Health>(api.health, "health", 15000);

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/">
          SkillSentry
        </a>
        <nav aria-label="Main">
          <a href="#/" aria-current={route.name === "triage" || route.name === "skill" ? "page" : undefined}>
            Triage
          </a>
          <a href="#/new" aria-current={route.name === "new-scan" ? "page" : undefined}>
            New scan
          </a>
          <a href="#/cache" aria-current={route.name === "cache" ? "page" : undefined}>
            Cache
          </a>
        </nav>
        <div className="status" aria-label="Server status">
          {meta.data ? (
            <span className="pill">
              {meta.data.backendActive} · v{meta.data.version}
            </span>
          ) : null}
          {meta.data?.demoMode ? <span className="pill warn">DEMO</span> : null}
          {health.data ? (
            <>
              <Dot label="Model" state={health.data.ollama} />
              <Dot label="Docker" state={health.data.docker} />
              <Dot label="Database" state={health.data.db} />
            </>
          ) : null}
        </div>
      </header>

      <main>
        {route.name === "triage" ? <TriagePage /> : null}
        {route.name === "new-scan" ? <NewScanPage /> : null}
        {route.name === "cache" ? <CachePage /> : null}
        {route.name === "skill" ? <SkillPage skillId={route.skillId} /> : null}
      </main>
    </div>
  );
}

function Dot({ label, state }: { label: string; state: string }) {
  const ok = state === "ok";
  return (
    <span className={`dot ${ok ? "ok" : "bad"}`} title={`${label}: ${state}`}>
      {label}
    </span>
  );
}

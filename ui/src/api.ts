// Typed client for the SkillSentry server. Shapes mirror the camelCase payloads
// in schemas/api.v1.json and the live/demo backends.

export type VerdictTier = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
export type Severity = "low" | "medium" | "high" | "critical" | "note";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cached-hit";

export interface Evidence {
  file?: string | null;
  line?: number | null;
  code?: string | null;
  c2?: string | null;
  marker?: string | null;
  channel?: string | null;
  url?: string | null;
  domain?: string | null;
}

export interface Finding {
  stage: string;
  severity: Severity;
  message: string;
  type?: string | null;
  evidence: Evidence;
}

export interface ActiveDefense {
  triggered: boolean;
  targetedAssets: string[];
  exfilChannel?: string | null;
  canaryMarker?: string | null;
  secondaryCanary?: string | null;
  c2Indicators: string[];
  encoding?: string | null;
  sandboxEvasionDetected: boolean;
  declaredIntent?: string | null;
}

export interface VerdictRecord {
  skill: string;
  skillId: string;
  scanId: string;
  verdict: VerdictTier;
  riskScore: number;
  confidence: number;
  cached: boolean;
  scanDurationMs: number;
  findings: Finding[];
  activeDefense?: ActiveDefense | null;
}

export interface ScanSummary {
  scanId: string;
  skill: string;
  skillId: string;
  startedAt: string;
  status: ScanStatus;
  cached: boolean;
  durationMs: number;
  verdict: VerdictTier | null;
  riskScore: number | null;
  keyFinding: string | null;
}

export interface StaticFinding {
  file: string;
  line: number;
  code: string;
  stage: string;
  severity: Severity;
  message: string;
  anchor: boolean;
  highlight: boolean;
}

export interface VisionEvidence {
  image?: string;
  imageName?: string;
  ocr?: string;
  bboxes?: number[][];
  confidence?: number;
  positionNote?: string | null;
  findings?: Finding[];
}

export interface SandboxEvent {
  ts: string;
  eventType: string;
  pathOrChannel: string;
  marker: string | null;
  process: string | null;
  detail: string | null;
}

export interface NetLog {
  ts: string;
  protocol: string;
  queryOrUrl: string;
  bodyB64?: string | null;
  responderAction: string;
}

export interface SandboxTrace {
  events: SandboxEvent[];
  netLogs: NetLog[];
  resourceUsage: { durationMs: number; peakMemoryMb: number; cpuPercent: number };
}

export interface GraphNode {
  id: string;
  label: string;
  kind: string;
  evidence: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface TimelineRow {
  ts: string;
  label: string;
  kind: string;
  marker: string | null;
  detail: string | null;
}

export interface PoisonedWellView {
  activeDefense: ActiveDefense | null;
  confirmed: boolean;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  timeline: TimelineRow[];
}

export interface SkillDetail {
  verdict: VerdictRecord;
  staticFindings: StaticFinding[];
  visionEvidence: VisionEvidence[];
  sandboxTrace: SandboxTrace;
  poisonedWell: PoisonedWellView;
  reportLinks: { sarif: string; markdown: string; stix: string | null };
}

export interface Meta {
  version: string;
  backendActive: string;
  gemmaBadge: string;
  demoMode: boolean;
  contractVersion: string;
}

export interface Health {
  ollama: string;
  docker: string;
  db: string;
  demoMode: boolean;
}

export interface CacheStats {
  entries: number;
  hitRate: number;
  dbSizeBytes: number;
  engineVersion: string;
  modelVersion: string;
}

export interface WSMessage {
  stage: string;
  skill: string;
  event: "started" | "progress" | "finding" | "override" | "completed" | "error" | "cached";
  ts: string;
  detail: Record<string, unknown> | null;
}

export interface ScanOptions {
  noCache: boolean;
  sandbox: boolean;
  poisonedWell: boolean;
  /** Omitted (undefined) lets the server apply its default. */
  timeoutS?: number;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { error?: { message?: string } };
      if (body.error?.message) message = body.error.message;
    } catch {
      // Non-JSON error bodies keep the status text.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  meta: () => request<Meta>("/meta"),
  health: () => request<Health>("/health"),
  scans: () => request<{ scans: ScanSummary[] }>("/scans?limit=100"),
  skill: (skillId: string) => request<SkillDetail>(`/skills/${encodeURIComponent(skillId)}`),
  cacheStats: () => request<CacheStats>("/cache/stats"),
  clearCache: () => request<{ deleted: number; retained: number }>("/cache", { method: "DELETE" }),
  startScan: (path: string, options: ScanOptions) =>
    request<{ scanId: string; status: ScanStatus; stream: string }>("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path,
        options: {
          no_cache: options.noCache,
          sandbox: options.sandbox,
          poisoned_well: options.poisonedWell,
          timeout_s: options.timeoutS,
        },
      }),
    }),
};

export interface ScanStream {
  /** Ask the server to stop the scan. Sent as soon as the socket is open. */
  cancel: () => void;
  /** Close the socket locally. */
  close: () => void;
}

/** Stream stage events for one scan. */
export function openScanStream(
  scanId: string,
  onMessage: (message: WSMessage) => void,
  onClose: () => void,
): ScanStream {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${scheme}://${window.location.host}/scan/${scanId}/stream`);
  socket.onmessage = (event: MessageEvent<string>) => {
    try {
      onMessage(JSON.parse(event.data) as WSMessage);
    } catch {
      // Malformed frames are ignored; the stream continues.
    }
  };
  socket.onclose = () => onClose();
  const cancelPayload = JSON.stringify({ op: "cancel" });
  return {
    cancel: () => {
      if (socket.readyState === WebSocket.CONNECTING) {
        socket.addEventListener("open", () => socket.send(cancelPayload), { once: true });
      } else if (socket.readyState === WebSocket.OPEN) {
        socket.send(cancelPayload);
      }
    },
    close: () => socket.close(),
  };
}

/** Skill ID of the verdict carried by a completed event, if the event has one. */
export function verdictSkillId(message: WSMessage): string | null {
  const verdict = message.detail?.verdict;
  if (verdict && typeof verdict === "object" && "skillId" in verdict) {
    const skillId = (verdict as { skillId: unknown }).skillId;
    if (typeof skillId === "string" && skillId !== "") return skillId;
  }
  return null;
}

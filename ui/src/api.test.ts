import { afterEach, describe, expect, it, vi } from "vitest";
import { api, openScanStream, verdictSkillId, type WSMessage } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("request error handling", () => {
  it("surfaces the server's untrusted_host message and status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: { code: "untrusted_host", message: "request refused: host 'evil.test' is not allowed" },
          }),
          { status: 400, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    await expect(api.meta()).rejects.toMatchObject({
      message: "request refused: host 'evil.test' is not allowed",
      status: 400,
    });
  });

  it("falls back to the status line for non-JSON errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("boom", { status: 502, statusText: "Bad Gateway" })));
    await expect(api.health()).rejects.toMatchObject({ message: "502 Bad Gateway", status: 502 });
  });
});

describe("openScanStream", () => {
  it("sends a cancel op over the open socket", () => {
    const sent: string[] = [];
    class FakeSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      readyState = 1;
      onmessage: unknown = null;
      onclose: unknown = null;
      send(payload: string) {
        sent.push(payload);
      }
      close() {}
    }
    vi.stubGlobal("WebSocket", FakeSocket);
    const stream = openScanStream("abc", () => {}, () => {});
    stream.cancel();
    expect(sent).toEqual([JSON.stringify({ op: "cancel" })]);
  });
});

describe("verdictSkillId", () => {
  const base: WSMessage = { stage: "verdict", skill: "demo", event: "completed", ts: "2026-11-12T10:00:00Z", detail: null };

  it("reads the skill ID from a completed verdict", () => {
    const message = { ...base, detail: { verdict: { skillId: "22222222-2222-4222-8222-222222222222" } } };
    expect(verdictSkillId(message)).toBe("22222222-2222-4222-8222-222222222222");
  });

  it("returns null when the event carries no verdict", () => {
    expect(verdictSkillId(base)).toBeNull();
  });
});

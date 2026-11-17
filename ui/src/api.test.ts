import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, NetworkError, api, describeError, openScanStream, verdictSkillId, type WSMessage } from "./api";

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

describe("describeError", () => {
  it("tells the user how to start the server when it cannot be reached", () => {
    expect(describeError(new NetworkError("Failed to fetch"))).toMatch(/skill-sentry-cli serve/);
  });

  it("turns a rejected fetch into the unreachable-server message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const failure = await api.meta().catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(NetworkError);
    expect(describeError(failure)).toMatch(/cannot reach the skillsentry server/i);
  });

  it("does not report a TypeError from elsewhere as an unreachable server", () => {
    const bug = new TypeError("Cannot read properties of undefined (reading 'map')");
    expect(describeError(bug)).toBe("Cannot read properties of undefined (reading 'map')");
  });

  it("does not double the period on a 404 message that already ends with one", () => {
    expect(describeError(new ApiError("skill not found.", 404))).toBe("skill not found. It may have been removed.");
  });

  it("explains a 5xx without exposing the raw status line", () => {
    const text = describeError(new ApiError("502 Bad Gateway", 502));
    expect(text).toMatch(/server hit an error \(502\)/i);
    expect(text).not.toContain("Bad Gateway");
  });

  it("keeps a 4xx server message and adds a hint for 404", () => {
    expect(describeError(new ApiError("path is not allowed", 403))).toBe("path is not allowed");
    expect(describeError(new ApiError("skill not found", 404))).toBe("skill not found. It may have been removed.");
  });

  it("handles an unreadable body and unknown values", () => {
    expect(describeError(new SyntaxError("Unexpected token"))).toMatch(/could not read/i);
    expect(describeError("nope")).toMatch(/request failed/i);
    expect(describeError(new Error("plain"))).toBe("plain");
  });
});

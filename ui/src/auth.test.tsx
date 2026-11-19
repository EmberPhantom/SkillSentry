import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { api, openScanStream, verifyToken } from "./api";
import { App } from "./App";
import { getToken, resetAuthForTests, setToken } from "./auth";

const TOKEN = "s3cret-token-value";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const unauthorized = () =>
  jsonResponse(401, { error: { code: "unauthorized", message: "a valid bearer token is required" } });

beforeEach(() => {
  resetAuthForTests();
  window.location.hash = "#/";
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  resetAuthForTests();
});

/** A fake server that wants TOKEN on everything except /meta and /health. */
function stubServer() {
  const calls: { url: string; auth: string | null }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      const auth = headers.get("Authorization");
      calls.push({ url, auth });
      if (url.startsWith("/meta")) {
        return jsonResponse(200, {
          version: "2.1.1",
          backendActive: "mock",
          gemmaBadge: "Badge",
          demoMode: false,
          contractVersion: "1",
        });
      }
      if (url.startsWith("/health")) return jsonResponse(200, { ollama: "ok", docker: "ok", db: "ok", demoMode: false });
      if (auth !== `Bearer ${TOKEN}`) return unauthorized();
      if (url.startsWith("/scans")) return jsonResponse(200, { scans: [] });
      if (url.startsWith("/cache/stats")) {
        return jsonResponse(200, { entries: 0, dbSizeBytes: 0, hitRate: 0, engineVersion: "e", modelVersion: "m" });
      }
      return jsonResponse(404, { error: { code: "not_found", message: "nope" } });
    }),
  );
  return calls;
}

describe("the access token prompt", () => {
  it("shows the prompt when the server answers 401, and nothing else", async () => {
    stubServer();
    render(<App />);

    expect(await screen.findByRole("heading", { name: /access token needed/i })).toBeTruthy();
    expect(screen.queryByText(/no scans yet/i)).toBeNull();
    expect(screen.queryByRole("button", { name: /sign out/i })).toBeNull();
  });

  it("says so when the token is wrong, keeps the prompt, and stores nothing", async () => {
    stubServer();
    render(<App />);
    const field = (await screen.findByLabelText(/access token/i, { selector: "input" })) as HTMLInputElement;

    fireEvent.change(field, { target: { value: "not-the-token" } });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/not accepted/i);
    expect(getToken()).toBeNull();
    expect(window.sessionStorage.getItem("skillsentry.token")).toBeNull();
    expect(screen.getByRole("heading", { name: /access token needed/i })).toBeTruthy();
  });

  it("loads the dashboard with the right token and sends it as a bearer header", async () => {
    const calls = stubServer();
    render(<App />);
    const field = await screen.findByLabelText(/access token/i, { selector: "input" });

    fireEvent.change(field, { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect(await screen.findByText(/no scans yet/i)).toBeTruthy();
    expect(getToken()).toBe(TOKEN);
    const scansCall = [...calls].reverse().find((call) => call.url.startsWith("/scans"));
    expect(scansCall?.auth).toBe(`Bearer ${TOKEN}`);
    expect(screen.getByRole("button", { name: /sign out/i })).toBeTruthy();
  });

  it("keeps the token in sessionStorage only, never localStorage, never in the URL or the page", async () => {
    stubServer();
    render(<App />);
    fireEvent.change(await screen.findByLabelText(/access token/i, { selector: "input" }), { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    await screen.findByText(/no scans yet/i);

    expect(window.sessionStorage.getItem("skillsentry.token")).toBe(TOKEN);
    expect(window.localStorage.length).toBe(0);
    expect(window.location.href).not.toContain(TOKEN);
    expect(document.body.innerHTML).not.toContain(TOKEN);
  });

  it("signs out: forgets the token everywhere and asks for it again", async () => {
    stubServer();
    render(<App />);
    fireEvent.change(await screen.findByLabelText(/access token/i, { selector: "input" }), { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    await screen.findByText(/no scans yet/i);

    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    expect(await screen.findByRole("heading", { name: /access token needed/i })).toBeTruthy();
    expect(getToken()).toBeNull();
    expect(window.sessionStorage.getItem("skillsentry.token")).toBeNull();
    expect(screen.queryByRole("button", { name: /sign out/i })).toBeNull();
  });

  it("asks again when a kept token stops working (the server was restarted with another)", async () => {
    stubServer();
    setToken("old-token");
    render(<App />);

    expect(await screen.findByRole("heading", { name: /access token needed/i })).toBeTruthy();
    expect(getToken()).toBeNull();
    expect(window.sessionStorage.getItem("skillsentry.token")).toBeNull();
  });

  it("does not show a prompt, or a sign-out button, for a server with no token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.startsWith("/scans")) return jsonResponse(200, { scans: [] });
        return jsonResponse(200, { ollama: "ok", docker: "ok", db: "ok", demoMode: false });
      }),
    );
    render(<App />);

    expect(await screen.findByText(/no scans yet/i)).toBeTruthy();
    expect(screen.queryByLabelText(/access token/i, { selector: "input" })).toBeNull();
    expect(screen.queryByRole("button", { name: /sign out/i })).toBeNull();
  });

  it("does not leave the typed token in the field after it is accepted", async () => {
    stubServer();
    render(<App />);
    const field = (await screen.findByLabelText(/access token/i, { selector: "input" })) as HTMLInputElement;
    fireEvent.change(field, { target: { value: TOKEN } });

    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    await waitFor(() => expect(getToken()).toBe(TOKEN));
    expect(document.querySelector("input[type=password]")).toBeNull();
  });

  it("tells the user when the server cannot be reached while checking a token", async () => {
    stubServer();
    render(<App />);
    const field = await screen.findByLabelText(/access token/i, { selector: "input" });
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));

    fireEvent.change(field, { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/cannot reach the skillsentry server/i);
  });

  it("the field is a password field with a label", async () => {
    stubServer();
    render(<App />);

    const field = (await screen.findByLabelText(/access token/i, { selector: "input" })) as HTMLInputElement;

    expect(field.type).toBe("password");
  });
});

describe("requests and the stream", () => {
  it("sends no Authorization header when there is no token", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { scans: [] }));
    vi.stubGlobal("fetch", fetchMock);

    await api.scans();

    const init = (fetchMock.mock.calls[0] as unknown[])[1] as RequestInit | undefined;
    expect(new Headers(init?.headers).get("Authorization")).toBeNull();
  });

  it("verifyToken is true for an accepted token and false for a refused one", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        new Headers(init?.headers).get("Authorization") === `Bearer ${TOKEN}`
          ? jsonResponse(200, {})
          : unauthorized(),
      ),
    );

    expect(await verifyToken(TOKEN)).toBe(true);
    expect(await verifyToken("wrong")).toBe(false);
  });

  it("opens the WebSocket with the token as a subprotocol, never in the URL", () => {
    const created: { url: string; protocols?: string | string[] }[] = [];
    class FakeSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      readyState = 0;
      onmessage: unknown = null;
      onclose: unknown = null;
      constructor(url: string, protocols?: string | string[]) {
        created.push({ url, protocols });
      }
      addEventListener() {}
      send() {}
      close() {}
    }
    vi.stubGlobal("WebSocket", FakeSocket);
    setToken(TOKEN);

    openScanStream("abc", () => {}, () => {});

    expect(created[0].protocols).toEqual(["skillsentry.v1", `bearer.${TOKEN}`]);
    expect(created[0].url).not.toContain(TOKEN);
    expect(created[0].url).toMatch(/\/scan\/abc\/stream$/);
  });

  it("opens the WebSocket with no subprotocol when there is no token", () => {
    const created: { protocols?: string | string[] }[] = [];
    class FakeSocket {
      static CONNECTING = 0;
      static OPEN = 1;
      readyState = 0;
      onmessage: unknown = null;
      onclose: unknown = null;
      constructor(_url: string, protocols?: string | string[]) {
        created.push({ protocols });
      }
      addEventListener() {}
      send() {}
      close() {}
    }
    vi.stubGlobal("WebSocket", FakeSocket);

    openScanStream("abc", () => {}, () => {});

    expect(created[0].protocols).toBeUndefined();
  });
});

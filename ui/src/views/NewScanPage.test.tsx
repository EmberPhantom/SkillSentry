import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { openScanStream, type WSMessage } from "../api";
import { NewScanPage } from "./NewScanPage";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, openScanStream: vi.fn() };
});

const SCAN_ID = "11111111-1111-4111-8111-111111111111";
const SKILL_ID = "22222222-2222-4222-8222-222222222222";
const TS = "2026-11-12T10:00:00Z";

let emit: (message: WSMessage) => void;
let end: () => void;
let cancelMock: Mock;

beforeEach(() => {
  cancelMock = vi.fn();
  vi.mocked(openScanStream).mockImplementation((_id, onMessage, onClose) => {
    emit = onMessage;
    end = onClose;
    return { cancel: cancelMock, close: vi.fn() };
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function stubFetch(response: Response) {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function fillPath(value = "/opt/skills/demo") {
  fireEvent.change(screen.getByLabelText(/skill folder/i), { target: { value } });
}

function setTimeoutField(value: string) {
  fireEvent.change(screen.getByLabelText(/timeout/i), { target: { value } });
}

function submit() {
  fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
}

function acceptedScan() {
  return jsonResponse(202, { scanId: SCAN_ID, status: "queued", stream: `/scan/${SCAN_ID}/stream` });
}

function message(event: WSMessage["event"], detail: WSMessage["detail"] = null): WSMessage {
  return { stage: "verdict", skill: "demo", event, ts: TS, detail };
}

function requestBody(fetchMock: Mock): { options: Record<string, unknown> } {
  const init = fetchMock.mock.calls[0][1] as RequestInit;
  return JSON.parse(init.body as string);
}

describe("NewScanPage timeout", () => {
  it("omits timeout_s when the field is blank so the server default applies", async () => {
    const fetchMock = stubFetch(acceptedScan());
    render(<NewScanPage />);
    fillPath();
    setTimeoutField("");
    submit();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const body = requestBody(fetchMock);
    expect(body.options).not.toHaveProperty("timeout_s");
    expect(body.options).toMatchObject({ sandbox: true, poisoned_well: true, no_cache: false });
  });

  it("sends the entered timeout", async () => {
    const fetchMock = stubFetch(acceptedScan());
    render(<NewScanPage />);
    fillPath();
    setTimeoutField("120");
    submit();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(requestBody(fetchMock).options).toMatchObject({ timeout_s: 120 });
  });

  it.each(["2", "9999"])("rejects %s client-side without calling the server", (value) => {
    const fetchMock = stubFetch(acceptedScan());
    render(<NewScanPage />);
    fillPath();
    setTimeoutField(value);
    submit();

    expect(screen.getByRole("alert").textContent).toContain("5 to 600");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the server's validation message unchanged", async () => {
    stubFetch(
      jsonResponse(422, {
        error: {
          code: "schema_violation",
          message: "options.timeout_s: Input should be less than or equal to 600",
          degraded: false,
        },
      }),
    );
    render(<NewScanPage />);
    fillPath();
    submit();

    expect((await screen.findByRole("alert")).textContent).toBe(
      "options.timeout_s: Input should be less than or equal to 600",
    );
  });
});

describe("NewScanPage cancel and completion", () => {
  async function startRunningScan() {
    stubFetch(acceptedScan());
    render(<NewScanPage />);
    fillPath();
    submit();
    await screen.findByRole("button", { name: "Cancel scan" });
  }

  it("sends cancel and shows a cancelled state when the server reports it", async () => {
    await startRunningScan();

    fireEvent.click(screen.getByRole("button", { name: "Cancel scan" }));
    expect(cancelMock).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Cancelling…" }).hasAttribute("disabled")).toBe(true);

    emit(message("error", { code: "cancelled", message: "cancelled by client", degraded: true }));

    expect(await screen.findByText(/scan cancelled before a verdict/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /cancel/i })).toBeNull();
  });

  it("treats a socket close after cancel as cancelled when no error event arrives", async () => {
    await startRunningScan();

    fireEvent.click(screen.getByRole("button", { name: "Cancel scan" }));
    end();

    expect(await screen.findByText(/scan cancelled before a verdict/i)).toBeTruthy();
  });

  it("links to the verdict page after completion", async () => {
    await startRunningScan();

    emit(message("completed", { verdict: { skill: "demo", skillId: SKILL_ID, verdict: "SAFE" } }));

    const link = await screen.findByRole("link", { name: "Open verdict" });
    expect(link.getAttribute("href")).toBe(`#/skill/${SKILL_ID}`);
    expect(screen.queryByRole("button", { name: /cancel/i })).toBeNull();
  });
});

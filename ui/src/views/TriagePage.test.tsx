import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api, ApiError, NetworkError, type ScanSummary } from "../api";
import { TriagePage } from "./TriagePage";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const row: ScanSummary = {
  scanId: "33333333-3333-4333-8333-333333333333",
  skill: "demo-skill",
  skillId: "22222222-2222-4222-8222-222222222222",
  startedAt: "2026-11-12T10:00:00Z",
  status: "completed",
  cached: false,
  durationMs: 1200,
  verdict: "SAFE",
  riskScore: 4,
  keyFinding: null,
};

describe("TriagePage empty states", () => {
  it("says no scans exist yet when the list is empty", async () => {
    vi.spyOn(api, "scans").mockResolvedValue({ scans: [] });
    render(<TriagePage />);
    expect(await screen.findByText(/no scans yet/i)).toBeTruthy();
    expect(screen.queryByText(/match the current filter/i)).toBeNull();
  });

  it("says no scans match when a filter hides every scan", async () => {
    vi.spyOn(api, "scans").mockResolvedValue({ scans: [row] });
    render(<TriagePage />);
    expect(await screen.findByText("demo-skill")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "MALICIOUS" }));

    expect(screen.getByText(/no scans match the current filter or search/i)).toBeTruthy();
    expect(screen.queryByText(/no scans yet/i)).toBeNull();
  });
});

describe("TriagePage loading and error states", () => {
  it("shows loading while the request is pending, without flashing the empty state", () => {
    vi.spyOn(api, "scans").mockReturnValue(new Promise(() => {}));
    render(<TriagePage />);
    expect(screen.getByRole("status").textContent).toContain("Loading scans");
    expect(screen.queryByText(/no scans yet/i)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a network failure with a way to retry, not a spinner or the empty state", async () => {
    const spy = vi.spyOn(api, "scans").mockRejectedValueOnce(new NetworkError("Failed to fetch"));
    spy.mockResolvedValue({ scans: [row] });
    render(<TriagePage />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/skill-sentry-cli serve/);
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.queryByText(/no scans yet/i)).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("demo-skill")).toBeTruthy();
  });

  it("explains a server error (non-2xx) in plain words", async () => {
    vi.spyOn(api, "scans").mockRejectedValue(new ApiError("500 Internal Server Error", 500));
    render(<TriagePage />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/server hit an error \(500\)/i);
  });

  it("points the empty state at the CLI as well as the form", async () => {
    vi.spyOn(api, "scans").mockResolvedValue({ scans: [] });
    render(<TriagePage />);
    expect(await screen.findByText(/skill-sentry-cli scan/)).toBeTruthy();
  });
});

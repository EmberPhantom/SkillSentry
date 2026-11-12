import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api, type ScanSummary } from "../api";
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

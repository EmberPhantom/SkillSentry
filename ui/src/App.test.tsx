import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { api } from "./api";
import { App } from "./App";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("compliance badge", () => {
  it("shows a neutral badge, not a local-analysis claim, when /meta fails", async () => {
    vi.spyOn(api, "meta").mockRejectedValue(new Error("offline"));
    vi.spyOn(api, "health").mockRejectedValue(new Error("offline"));
    vi.spyOn(api, "scans").mockResolvedValue({ scans: [] });
    render(<App />);
    expect(screen.getByText("Analysis backend unknown")).toBeTruthy();
    expect(screen.queryByText(/Fully local/)).toBeNull();
    await screen.findByText(/no scans yet/i);
  });

  it("prefers the server's badge text when /meta loads", async () => {
    vi.spyOn(api, "meta").mockResolvedValue({
      version: "2.1.1",
      backendActive: "ollama",
      gemmaBadge: "Server badge text",
      demoMode: false,
      contractVersion: "1",
    });
    vi.spyOn(api, "health").mockRejectedValue(new Error("offline"));
    vi.spyOn(api, "scans").mockResolvedValue({ scans: [] });
    render(<App />);
    expect(await screen.findByText("Server badge text")).toBeTruthy();
  });
});

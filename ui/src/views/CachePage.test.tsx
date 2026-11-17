import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api, NetworkError, type CacheStats } from "../api";
import { CachePage } from "./CachePage";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const stats: CacheStats = {
  entries: 3,
  dbSizeBytes: 2048,
  engineVersion: "2.1.1",
  modelVersion: "demo",
} as CacheStats;

describe("CachePage states", () => {
  it("shows loading first, with no empty or error state", () => {
    vi.spyOn(api, "cacheStats").mockReturnValue(new Promise(() => {}));
    render(<CachePage />);
    expect(screen.getByRole("status").textContent).toContain("Loading");
    expect(screen.queryByText(/cache is empty/i)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says the cache is empty and disables clearing when there are no entries", async () => {
    vi.spyOn(api, "cacheStats").mockResolvedValue({ ...stats, entries: 0 });
    render(<CachePage />);
    expect(await screen.findByText(/cache is empty/i)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Clear cache" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the stats, not the empty state, when entries exist", async () => {
    vi.spyOn(api, "cacheStats").mockResolvedValue(stats);
    render(<CachePage />);
    expect(await screen.findByText("2.0 KB")).toBeTruthy();
    expect(screen.queryByText(/cache is empty/i)).toBeNull();
  });

  it("shows an error with a retry that loads again", async () => {
    const spy = vi.spyOn(api, "cacheStats").mockRejectedValueOnce(new NetworkError("Failed to fetch"));
    spy.mockResolvedValue(stats);
    render(<CachePage />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/cannot reach the skillsentry server/i);

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("2.0 KB")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

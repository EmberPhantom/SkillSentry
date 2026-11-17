import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api, ApiError } from "../api";
import { SkillPage } from "./SkillPage";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("SkillPage error state", () => {
  it("offers a link back to triage", async () => {
    vi.spyOn(api, "skill").mockRejectedValue(new Error("unknown skill"));
    render(<SkillPage skillId="22222222-2222-4222-8222-222222222222" />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText("unknown skill")).toBeTruthy();
    const back = screen.getByRole("link", { name: /triage/i });
    expect(back.getAttribute("href")).toBe("#/");
  });
});

describe("SkillPage loading and error states", () => {
  it("shows loading with a way back while the skill loads", () => {
    vi.spyOn(api, "skill").mockReturnValue(new Promise(() => {}));
    render(<SkillPage skillId="22222222-2222-4222-8222-222222222222" />);
    expect(screen.getByRole("status").textContent).toContain("Loading skill");
    expect(screen.getByRole("link", { name: /triage/i }).getAttribute("href")).toBe("#/");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says a missing skill was not found and lets the user retry", async () => {
    const spy = vi.spyOn(api, "skill").mockRejectedValue(new ApiError("skill not found", 404));
    render(<SkillPage skillId="22222222-2222-4222-8222-222222222222" />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/skill not found\. It may have been removed/i);

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(spy).toHaveBeenCalledTimes(2);
  });
});

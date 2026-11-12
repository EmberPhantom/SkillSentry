import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { api } from "../api";
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

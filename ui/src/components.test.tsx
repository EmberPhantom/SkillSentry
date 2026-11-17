import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Empty, ErrorBox, Loading } from "./components";

afterEach(cleanup);

describe("shared view states", () => {
  it("announces loading politely and marks it busy", () => {
    render(<Loading label="Loading scans" />);
    const status = screen.getByRole("status");
    expect(status.textContent).toBe("Loading scans…");
    expect(status.getAttribute("aria-busy")).toBe("true");
  });

  it("shows an error as an alert whose text is the message", () => {
    render(<ErrorBox error="boom" />);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toBe("boom");
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("offers a retry that calls back", () => {
    const retry = vi.fn();
    render(<ErrorBox error="boom" onRetry={retry} />);
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(retry).toHaveBeenCalledTimes(1);
  });

  it("renders the empty message", () => {
    render(<Empty>Nothing here yet.</Empty>);
    expect(screen.getByText("Nothing here yet.")).toBeTruthy();
  });
});

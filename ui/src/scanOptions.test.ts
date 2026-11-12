import { describe, expect, it } from "vitest";
import { parseTimeout } from "./scanOptions";

describe("parseTimeout", () => {
  it("treats a blank field as the server default", () => {
    expect(parseTimeout("")).toEqual({ ok: true, value: undefined });
    expect(parseTimeout("   ")).toEqual({ ok: true, value: undefined });
  });

  it("accepts whole numbers from 5 to 600 inclusive", () => {
    expect(parseTimeout("5")).toEqual({ ok: true, value: 5 });
    expect(parseTimeout(" 60 ")).toEqual({ ok: true, value: 60 });
    expect(parseTimeout("600")).toEqual({ ok: true, value: 600 });
  });

  it.each(["4", "0", "601", "-1", "1.5", "abc", "1e3"])("rejects %s", (text) => {
    const result = parseTimeout(text);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("5 to 600");
  });
});

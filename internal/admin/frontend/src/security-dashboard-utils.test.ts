import { describe, expect, it } from "vitest";
import { banPage, remainingBanTime } from "./security-dashboard-utils";

describe("active ban pagination", () => {
  it("returns the requested slice and visible item range", () => {
    const result = banPage(["a", "b", "c", "d", "e", "f", "g", "h", "i"], 2, 5);
    expect(result).toEqual({ items: ["f", "g", "h", "i"], page: 2, totalPages: 2, start: 5, end: 9 });
  });

  it("clamps page numbers when filters reduce the result set", () => {
    expect(banPage(["a"], 4, 5)).toEqual({ items: ["a"], page: 1, totalPages: 1, start: 0, end: 1 });
  });
});

describe("live ban countdown formatting", () => {
  it("includes seconds so each tick is visible", () => {
    expect(remainingBanTime("2026-10-23T12:00:00.000Z", Date.parse("2026-10-23T11:59:59.000Z"))).toBe("1s");
    expect(remainingBanTime("2026-10-23T12:00:00.000Z", Date.parse("2026-10-23T11:00:01.000Z"))).toBe("59m 59s");
  });

  it("reports an elapsed ban", () => {
    expect(remainingBanTime("2026-10-23T11:00:00.000Z", Date.parse("2026-10-23T11:00:00.000Z"))).toBe("Expired");
  });

  it("handles missing expiration data without showing an invalid duration", () => {
    expect(remainingBanTime("not-a-date", Date.now())).toBe("Unknown");
  });
});

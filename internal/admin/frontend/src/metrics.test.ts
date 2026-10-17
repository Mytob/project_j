import { describe, expect, it } from "vitest";
import { chartPoints, formatBytes, formatNumber, formatPercent, formatRate, nearestChartPoint } from "./metrics";

describe("metric formatting", () => {
  it("keeps unavailable measurements distinct from zero", () => {
    expect(formatNumber(undefined)).toBe("—");
    expect(formatBytes(undefined)).toBe("—");
    expect(formatNumber(0)).toMatch(/^0/);
  });

  it("formats byte units and throughput", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatRate(1536)).toBe("1.5 KB/s");
    expect(formatBytes(-1)).toBe("—");
  });

  it("does not divide by missing or zero capacity", () => {
    expect(formatPercent(25, 100)).toBe("25.0%");
    expect(formatPercent(25, 0)).toBe("—");
    expect(formatPercent(undefined, 100)).toBe("—");
  });
});

describe("chart point mapping", () => {
  it("bounds finite samples and ignores unavailable values", () => {
    expect(chartPoints([undefined, 0, 5])).toEqual([
      { x: 0, y: 150, value: 0 },
      { x: 600, y: 18, value: 5 },
    ]);
  });

  it("returns no points for empty or non-finite samples", () => {
    expect(chartPoints([])).toEqual([]);
    expect(chartPoints([Number.NaN, Number.POSITIVE_INFINITY])).toEqual([]);
  });

  it("selects the nearest visible sample and handles empty charts", () => {
    const points = chartPoints([2, 4, 8]);
    expect(nearestChartPoint(points, 520)).toBe(2);
    expect(nearestChartPoint(points, 151)).toBe(1);
    expect(nearestChartPoint([], 100)).toBe(-1);
  });
});

export function formatNumber(value: number | undefined, suffix = "") {
  return value == null || !Number.isFinite(value) ? "—" : `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value)}${suffix}`;
}

export function formatBytes(value: number | undefined) {
  if (value == null || !Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(unit > 0 ? 1 : 0)} ${units[unit]}`;
}

export function formatRate(value: number | undefined) { return value == null ? "—" : `${formatBytes(value)}/s`; }

export function formatPercent(used?: number, total?: number) {
  return used == null || total == null || total <= 0 ? "—" : `${(100 * used / total).toFixed(1)}%`;
}

export function chartPoints(values: readonly (number | undefined)[]) {
  const finite = values.filter((value): value is number => value != null && Number.isFinite(value));
  if (finite.length === 0) return [];
  const max = Math.max(...finite) || 1;
  return finite.map((value, i) => ({ x: finite.length < 2 ? 300 : i * 600 / (finite.length - 1), y: 150 - value / max * 132, value }));
}

export function nearestChartPoint(points: readonly { x: number }[], x: number) {
  if (points.length === 0) return -1;
  let nearest = 0;
  for (let index = 1; index < points.length; index++) {
    if (Math.abs(points[index].x - x) < Math.abs(points[nearest].x - x)) nearest = index;
  }
  return nearest;
}

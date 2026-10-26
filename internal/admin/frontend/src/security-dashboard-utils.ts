export type BanPage<T> = {
  items: T[];
  page: number;
  totalPages: number;
  start: number;
  end: number;
};

export function banPage<T>(items: T[], requestedPage: number, pageSize: number): BanPage<T> {
  const safePageSize = Number.isFinite(pageSize) ? Math.max(1, Math.floor(pageSize)) : 1;
  const totalPages = Math.max(1, Math.ceil(items.length / safePageSize));
  const page = Math.min(totalPages, Math.max(1, Math.floor(requestedPage) || 1));
  const start = (page - 1) * safePageSize;
  const end = Math.min(items.length, start + safePageSize);
  return { items: items.slice(start, end), page, totalPages, start, end };
}

export function remainingBanTime(expiresAt: string, now: number): string {
  const deadline = new Date(expiresAt).getTime();
  if (!Number.isFinite(deadline)) return "Unknown";
  const seconds = Math.max(0, Math.floor((deadline - now) / 1000));
  if (!seconds) return "Expired";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remainder = seconds % 60;
  if (days) return `${days}d ${hours}h ${minutes}m ${remainder}s`;
  if (hours) return `${hours}h ${minutes}m ${remainder}s`;
  if (minutes) return `${minutes}m ${remainder}s`;
  return `${remainder}s`;
}

import React, { useEffect, useMemo, useState } from "react";
import "./security-dashboard.css";

export type SecurityService = "ssh" | "admin";
export type SecurityHistoryEvent = {
  id: string;
  at: string;
  service: SecurityService;
  ip: string;
  type: string;
  details?: string;
  failed_attempts?: number;
  escalation?: number;
  blocked_requests?: number;
};
export type SecurityProtectionConfig = {
  threshold: number;
  window: number;
  ban_durations: number[];
  escalation_reset: number;
};
export type SecurityConfig = { ssh: SecurityProtectionConfig; admin: SecurityProtectionConfig; history_retention: number };
export type SecuritySnapshot = {
  config: SecurityConfig;
  active_bans: { service: SecurityService; ip: string; started_at: string; expires_at: string; failed_attempts: number; escalation: number }[];
  recent_activity: SecurityHistoryEvent[];
  failed_24h: number;
  bans_24h: number;
  pending_failures: number;
  health: { fail2ban: string; ssh_journal: string; firewall: string; admin_events: string; caddy_sync: string; last_error?: string };
  captured_at: string;
};

const minute = 60 * 1_000_000_000;
const day = 24 * 60 * minute;
const ranges = [{ value: "1h", label: "Last hour", buckets: 12 }, { value: "24h", label: "Last 24 hours", buckets: 24 }, { value: "7d", label: "Last 7 days", buckets: 7 }, { value: "30d", label: "Last 30 days", buckets: 30 }] as const;

export function SecurityOverview({ snapshot, error, open }: { snapshot?: SecuritySnapshot; error?: string; open: () => void }) {
  const warning = !snapshot || Object.values(snapshot.health).some((value) => value !== "healthy");
  return <section className="panel security-overview"><div className="panel-title"><div><p className="eyebrow">SECURITY</p><h2>Protection status</h2></div><button className="button secondary" type="button" onClick={open}>Security details →</button></div>
    {error && <p className="security-warning" role="status">{error}</p>}
    <div className="security-overview-grid"><div><span>Active bans</span><strong>{snapshot?.active_bans.length ?? "—"}</strong></div><div><span>Failed attempts · 24h</span><strong>{snapshot?.failed_24h ?? "—"}</strong></div><div><span>Bans created · 24h</span><strong>{snapshot?.bans_24h ?? "—"}</strong></div><div><span>Fail2ban / firewall</span><strong className={warning ? "security-degraded" : "security-healthy"}>{snapshot ? `${labelStatus(snapshot.health.fail2ban)} / ${labelStatus(snapshot.health.firewall)}` : "Unknown"}</strong></div></div>
    {snapshot?.health.last_error && <p className="security-warning" role="status">{snapshot.health.last_error}</p>}
    {snapshot && <div className="security-recent"><b>Recent activity</b>{snapshot.recent_activity.length ? snapshot.recent_activity.slice(0, 3).map((event) => <span key={event.id}><time>{new Date(event.at).toLocaleTimeString()}</time>{event.ip} · {eventLabel(event.type)} · {event.service.toUpperCase()}</span>) : <span>No recent security events.</span>}</div>}
  </section>;
}

export function SecurityProtection({ csrf, snapshot: liveSnapshot, error: initialError, onSnapshot }: { csrf: string; snapshot?: SecuritySnapshot; error?: string; onSnapshot: (snapshot: SecuritySnapshot) => void }) {
  const [range, setRange] = useState<(typeof ranges)[number]["value"]>("24h");
  const [service, setService] = useState("all");
  const [search, setSearch] = useState("");
  const [eventType, setEventType] = useState("all");
  const [history, setHistory] = useState<SecurityHistoryEvent[]>([]);
  const [historyError, setHistoryError] = useState("");
  const [actionError, setActionError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const [banFilter, setBanFilter] = useState("all");
  const [form, setForm] = useState(() => liveSnapshot ? toFields(liveSnapshot.config) : undefined);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const query = new URLSearchParams({ range, service, q: search.trim() });
    fetch(`/security/history?${query}`, { credentials: "same-origin", cache: "no-store", signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(await response.text()); return response.json() as Promise<SecurityHistoryEvent[]>; })
      .then((rows) => { if (active) { setHistory(rows); setHistoryError(""); } })
      .catch((reason: unknown) => { if (active && !(reason instanceof DOMException && reason.name === "AbortError")) setHistoryError("Security history could not be loaded."); });
    return () => { active = false; controller.abort(); };
  }, [range, service, search, liveSnapshot?.recent_activity[0]?.id]);

  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 5000); return () => window.clearInterval(timer); }, []);
  useEffect(() => { if (!form && liveSnapshot) setForm(toFields(liveSnapshot.config)); }, [form, liveSnapshot]);

  const visibleHistory = useMemo(() => eventType === "all" ? history : history.filter((event) => event.type === eventType), [history, eventType]);
  const visibleBans = (liveSnapshot?.active_bans ?? []).filter((ban) => banFilter === "all" || ban.service === banFilter);
  const currentRange = ranges.find((item) => item.value === range) ?? ranges[1];
  const buckets = useMemo(() => makeBuckets(history, range, service, currentRange.buckets), [history, range, service, currentRange.buckets]);

  async function mutate(path: string, body: unknown, name: string) {
    setBusy(name); setActionError(""); setNotice("");
    try {
      const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error((await response.text()).trim() || "Security changes could not be saved.");
      const updated = await response.json() as SecuritySnapshot;
      onSnapshot(updated);
      if (path.endsWith("/config")) { setForm(toFields(updated.config)); setNotice("Security settings saved."); }
      else setNotice("Address unbanned.");
    } catch (reason: unknown) { setActionError(reason instanceof Error ? reason.message : "Security changes could not be saved."); }
    finally { setBusy(""); }
  }

  function saveConfig(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!form) return;
    void mutate("/security/config", toConfig(form), "config");
  }

  if (!liveSnapshot) return <section className="panel"><div className="panel-title"><div><p className="eyebrow">SECURITY PROTECTION</p><h2>Status unavailable</h2></div></div><p className="security-warning" role="alert">{initialError ?? "The private security service has not supplied a status snapshot."}</p></section>;

  return <>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">LIVE PROTECTION</p><h2>Fail2ban and firewall</h2></div><span className={`state-pill ${liveSnapshot.health.fail2ban === "healthy" ? "healthy" : "degraded"}`}><i/>{labelStatus(liveSnapshot.health.fail2ban)}</span></div>
      <div className="security-health-grid">{[["Fail2ban", liveSnapshot.health.fail2ban], ["SSH journal", liveSnapshot.health.ssh_journal], ["SSH firewall", liveSnapshot.health.firewall], ["Admin auth events", liveSnapshot.health.admin_events], ["Caddy admin bans", liveSnapshot.health.caddy_sync]].map(([name, state]) => <div className="security-health-item" key={name}><span>{name}</span><b className={state === "healthy" ? "security-healthy" : "security-degraded"}>{labelStatus(state)}</b></div>)}</div>
      {liveSnapshot.health.last_error && <p className="security-warning" role="alert">{liveSnapshot.health.last_error}</p>}
    </section>

    <section className="panel"><div className="panel-title"><div><p className="eyebrow">AUTHENTICATION ACTIVITY</p><h2>Failures and bans over time</h2></div><span className="live-indicator"><i/>Live via SSE</span></div>
      <div className="security-filters"><label>Time range<select value={range} onChange={(event) => setRange(event.target.value as typeof range)}>{ranges.map((item) => <option value={item.value} key={item.value}>{item.label}</option>)}</select></label><label>Service<select value={service} onChange={(event) => setService(event.target.value)}><option value="all">All services</option><option value="ssh">SSH</option><option value="admin">Admin</option></select></label></div>
      <SecurityChart buckets={buckets} range={range}/>
    </section>

    <section className="panel"><div className="panel-title"><div><p className="eyebrow">ACTIVE BANS</p><h2>Blocked addresses</h2></div><span className="muted">{visibleBans.length} active</span></div>
      <div className="security-filters"><label>Service<select value={banFilter} onChange={(event) => setBanFilter(event.target.value)}><option value="all">All services</option><option value="ssh">SSH</option><option value="admin">Admin</option></select></label></div>
      {visibleBans.length ? <div className="security-ban-list">{visibleBans.map((ban) => <article className="security-ban" key={`${ban.service}:${ban.ip}`}><div className="security-ban-address"><code>{ban.ip}</code><span className={`service-tag ${ban.service}`}>{ban.service.toUpperCase()}</span></div><dl><div><dt>Started</dt><dd>{new Date(ban.started_at).toLocaleString()}</dd></div><div><dt>Remaining</dt><dd>{remaining(ban.expires_at, now)}</dd></div><div><dt>Failed attempts</dt><dd>{ban.failed_attempts}</dd></div><div><dt>Escalation</dt><dd>Level {ban.escalation}</dd></div></dl><button type="button" className="button danger" disabled={busy === `unban:${ban.ip}`} onClick={() => void mutate("/security/unban", { service: ban.service, ip: ban.ip }, `unban:${ban.ip}`)}>Unban</button></article>)}</div> : <p className="empty-chart">No active bans for this filter.</p>}
    </section>

    <section className="panel"><div className="panel-title"><div><p className="eyebrow">SECURITY HISTORY</p><h2>Authentication and ban events</h2></div><span className="muted">Successes are not retained</span></div>
      <div className="security-filters"><label>Search<input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="IP address or event" maxLength={100}/></label><label>Event type<select value={eventType} onChange={(event) => setEventType(event.target.value)}><option value="all">All events</option><option value="failure">Failed login</option><option value="ban">Ban created</option><option value="expired">Ban expired</option><option value="manual_unban">Manual unban</option><option value="blocked_requests">Blocked requests</option></select></label></div>
      {historyError && <p className="security-warning" role="alert">{historyError}</p>}
      {visibleHistory.length ? <div className="security-history-list">{visibleHistory.map((event) => <article className="security-history-row" key={event.id}><time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time><code>{event.ip}</code><span className={`service-tag ${event.service}`}>{event.service.toUpperCase()}</span><b>{eventLabel(event.type)}</b><span>{event.details}{event.failed_attempts ? ` · ${event.failed_attempts} failures` : ""}{event.escalation ? ` · level ${event.escalation}` : ""}{event.blocked_requests ? ` · ${event.blocked_requests} requests` : ""}</span></article>)}</div> : <p className="empty-chart">No security events match the selected range and filters.</p>}
    </section>

    <section className="panel"><div className="panel-title"><div><p className="eyebrow">PROTECTION POLICY</p><h2>SSH and admin settings</h2></div></div>
      {form && <form className="security-config" onSubmit={saveConfig}>
        <ProtectionFields title="SSH protection" name="ssh" value={form.ssh} setForm={setForm}/>
        <ProtectionFields title="Admin protection" name="admin" value={form.admin} setForm={setForm}/>
        <div className="security-retention"><label>Security history retention (days)<input type="number" min="1" max="365" required value={form.retentionDays} onChange={(event) => setForm({ ...form, retentionDays: Number(event.target.value) })}/></label></div>
        <button className="button" type="submit" disabled={busy === "config"}>{busy === "config" ? "Saving…" : "Save protection settings"}</button>
      </form>}
      {actionError && <p className="security-warning" role="alert">{actionError}</p>}{notice && <p className="security-saved" role="status">{notice}</p>}
    </section>
  </>;
}

type Fields = { threshold: number; windowMinutes: number; banMinutes: number[]; resetDays: number };
type ConfigFields = { ssh: Fields; admin: Fields; retentionDays: number };
function toFields(config: SecurityConfig): ConfigFields {
  const convert = (value: SecurityProtectionConfig): Fields => ({ threshold: value.threshold, windowMinutes: value.window / minute, banMinutes: value.ban_durations.map((duration) => duration / minute), resetDays: value.escalation_reset / day });
  return { ssh: convert(config.ssh), admin: convert(config.admin), retentionDays: config.history_retention / day };
}
function toConfig(form: ConfigFields): SecurityConfig {
  const convert = (value: Fields): SecurityProtectionConfig => ({ threshold: value.threshold, window: Math.round(value.windowMinutes * minute), ban_durations: value.banMinutes.map((duration) => Math.round(duration * minute)), escalation_reset: Math.round(value.resetDays * day) });
  return { ssh: convert(form.ssh), admin: convert(form.admin), history_retention: Math.round(form.retentionDays * day) };
}

function ProtectionFields({ title, name, value, setForm }: { title: string; name: "ssh" | "admin"; value: Fields; setForm: React.Dispatch<React.SetStateAction<ConfigFields | undefined>> }) {
  const update = (field: keyof Fields, next: number | number[]) => setForm((current) => current ? { ...current, [name]: { ...current[name], [field]: next } } : current);
  return <fieldset className="security-protection"><legend>{title}</legend><div className="security-config-grid"><label>Failed attempts<input type="number" min="1" max="100" required value={value.threshold} onChange={(event) => update("threshold", Number(event.target.value))}/></label><label>Detection window (minutes)<input type="number" min="1" max="10080" required value={value.windowMinutes} onChange={(event) => update("windowMinutes", Number(event.target.value))}/></label>{value.banMinutes.map((duration, index) => <label key={index}>Ban {index + 1} (minutes)<input type="number" min="1" max="525600" required value={duration} onChange={(event) => { const next = [...value.banMinutes]; next[index] = Number(event.target.value); update("banMinutes", next); }}/></label>)}<label>Escalation reset (days)<input type="number" min="1" max="365" required value={value.resetDays} onChange={(event) => update("resetDays", Number(event.target.value))}/></label></div></fieldset>;
}

type Bucket = { failures: number; bans: number };
function makeBuckets(events: SecurityHistoryEvent[], range: string, service: string, count: number): Bucket[] {
  const output = Array.from({ length: count }, () => ({ failures: 0, bans: 0 }));
  const duration = range === "1h" ? 60 * 60_000 : range === "24h" ? 24 * 60 * 60_000 : range === "7d" ? 7 * 24 * 60 * 60_000 : 30 * 24 * 60 * 60_000;
  const now = Date.now();
  for (const event of events) {
    if (service !== "all" && event.service !== service) continue;
    const age = now - new Date(event.at).getTime();
    if (age < 0 || age > duration) continue;
    const index = Math.min(count - 1, Math.floor((duration - age) / duration * count));
    if (event.type === "failure") output[index].failures++;
    if (event.type === "ban") output[index].bans++;
  }
  return output;
}
function SecurityChart({ buckets, range }: { buckets: Bucket[]; range: string }) {
  const maxValue = Math.max(1, ...buckets.flatMap((bucket) => [bucket.failures, bucket.bans]));
  const coords = (key: keyof Bucket) => buckets.map((bucket, index) => `${(index * 600 / Math.max(1, buckets.length - 1)).toFixed(1)},${(140 - bucket[key] * 125 / maxValue).toFixed(1)}`).join(" ");
  return <div className="security-chart-wrap"><svg className="security-chart" viewBox="0 0 600 160" preserveAspectRatio="none" role="img" aria-label={`Failed authentication and bans over ${range}`}><path d="M0 15H600M0 55H600M0 95H600M0 140H600" className="security-chart-grid"/><polyline points={coords("failures")} className="security-failures-line"/><polyline points={coords("bans")} className="security-bans-line"/></svg><div className="security-chart-legend"><span><i className="failure-dot"/>Failed logins</span><span><i className="ban-dot"/>Bans</span></div><div className="security-chart-total"><span>{buckets.reduce((sum, bucket) => sum + bucket.failures, 0)} failures</span><span>{buckets.reduce((sum, bucket) => sum + bucket.bans, 0)} bans</span></div></div>;
}
function eventLabel(type: string) { return ({ failure: "Failed login", ban: "Ban created", expired: "Ban expired", manual_unban: "Manual unban", blocked_requests: "Blocked requests" } as Record<string, string>)[type] ?? type; }
function labelStatus(state: string) { return state ? state[0].toUpperCase() + state.slice(1) : "Unknown"; }
function remaining(expiresAt: string, now: number) { const seconds = Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000)); if (!seconds) return "Expired"; const days = Math.floor(seconds / 86400); const hours = Math.floor(seconds % 86400 / 3600); const minutes = Math.floor(seconds % 3600 / 60); return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m ${seconds % 60}s`; }

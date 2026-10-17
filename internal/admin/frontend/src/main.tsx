import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { chartPoints, formatBytes as bytes, formatNumber as number, formatPercent as pct, formatRate as rate, nearestChartPoint } from "./metrics";

type Component = { name: string; state: string; class: string; detail: string; checked_at?: string; last_success_at?: string; last_failure_at?: string };
type HealthEvent = { at: string; name: string; from?: string; to: string; detail: string };
type Metrics = { status: string; captured_at?: string; host?: HostMetrics; proxy?: ProxyMetrics };
type WireGuardStatus = { peer_public_key: string; server_address: string; client_address: string; listen_port: number; config_available: boolean; peer_state: string; peer_detail: string; peer_last_handshake?: string; peer_rx_bytes: number; peer_tx_bytes: number };
type WhitelistEntry = { address: string; name?: string };
type HostMetrics = { cpu_percent?: number; memory_used_bytes?: number; memory_total_bytes?: number; disk_used_bytes?: number; disk_total_bytes?: number; network_in_bytes_per_second?: number; network_out_bytes_per_second?: number; load_1?: number; load_5?: number; load_15?: number; uptime_seconds?: number };
type ProxyMetrics = { active_requests?: number; requests_per_second?: number; allowed_requests?: number; blocked_requests?: number; http_error_count?: number; error_rate_percent?: number; incoming_bytes_per_second?: number; outgoing_bytes_per_second?: number; total_transferred_bytes?: number };
type Initial = { csrf: string; version: string; build_number: string; whitelist_enabled: boolean; whitelist: string[]; whitelist_entries?: WhitelistEntry[]; wireguard_enabled: boolean; wireguard_config_available: boolean; wireguard_status?: WireGuardStatus; totp_status: string; totp_setup_visible: boolean; totp_secret?: string; totp_qr_code?: string; components: Component[]; health_events: HealthEvent[]; current: Metrics };
type HistoryPoint = { captured_at: string; host?: HostMetrics; proxy?: ProxyMetrics };

const pages = [
  ["/dashboard", "Overview", "⌂"],
  ["/statistics", "Statistics", "▥"],
  ["/health", "Health", "⌁"],
  ["/access-control", "Access control", "◉"],
  ["/wireguard", "WireGuard", "◇"],
  ["/security", "Security", "⛨"],
] as const;
const labels: Record<string, [string, string]> = {
  "/dashboard": ["OVERVIEW", "Infrastructure status and live traffic"],
  "/statistics": ["MONITORING", "Live and historical host and proxy measurements"],
  "/health": ["DIAGNOSTICS", "Evidence from the Caddy to Jellyfin connection path"],
  "/access-control": ["ACCESS", "Manage addresses allowed to reach Jellyfin"],
  "/wireguard": ["TUNNEL", "Windows peer configuration and connection status"],
  "/security": ["ACCOUNT SECURITY", "Administrator password and authenticator"],
};

async function getInitial(): Promise<Initial> {
  const response = await fetch("/api/initial", { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(response.status === 401 ? "Your administrator session has ended. Sign in again." : "The admin service could not load its current status.");
  return response.json() as Promise<Initial>;
}

function useLiveMetrics(onData: (data: Metrics) => void, onHealth: (data: { components: Component[]; health_events: HealthEvent[] }) => void, onAuthRequired: () => void) {
  useEffect(() => {
    const source = new EventSource("/statistics/events", { withCredentials: true });
    source.addEventListener("metrics", (event) => {
      try { onData(JSON.parse((event as MessageEvent<string>).data) as Metrics); } catch { /* reconnect will deliver the next full sample */ }
    });
    source.addEventListener("health", (event) => {
      try { onHealth(JSON.parse((event as MessageEvent<string>).data) as { components: Component[]; health_events: HealthEvent[] }); } catch { /* reconnect will deliver the next health snapshot */ }
    });
    source.addEventListener("auth-required", () => { source.close(); onAuthRequired(); });
    return () => source.close();
  }, [onData, onHealth, onAuthRequired]);
}

function App() {
  const [initial, setInitial] = useState<Initial>();
  const [metrics, setMetrics] = useState<Metrics>();
  const [path, setPath] = useState(window.location.pathname === "/" ? "/dashboard" : window.location.pathname);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(async () => {
    try {
      const value = await getInitial();
      setInitial(value);
      setMetrics(value.current);
      setError("");
      return value;
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Unable to load admin status.");
      return undefined;
    } finally {
      setLoading(false);
    }
  }, []);
  const onLive = useCallback((value: Metrics) => setMetrics(value), []);
  const onHealth = useCallback((value: { components: Component[]; health_events: HealthEvent[] }) => setInitial((prior) => prior ? { ...prior, ...value } : prior), []);
  const onAuthRequired = useCallback(() => setError("Your administrator session has ended. Sign in again."), []);
  useLiveMetrics(onLive, onHealth, onAuthRequired);
  useEffect(() => { refresh(); const timer = window.setInterval(refresh, 30_000); const pop = () => setPath(window.location.pathname); window.addEventListener("popstate", pop); return () => { window.clearInterval(timer); window.removeEventListener("popstate", pop); }; }, [refresh]);
  const navigate = (to: string) => { window.history.pushState({}, "", to); setPath(to); document.body.classList.remove("nav-open"); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const available = useMemo(() => pages.filter(([href]) => href !== "/access-control" || initial?.whitelist_enabled).filter(([href]) => href !== "/wireguard" || initial?.wireguard_enabled), [initial]);

  if (loading) return <main className="loading" aria-live="polite">Connecting to Jellyfin Proxy…</main>;
  if (error || !initial) return <main className="loading"><section className="error-card"><Brand/><h1>Admin connection unavailable</h1><p role="alert">{error || "Current administrator status is unavailable."}</p><button className="button" onClick={refresh}>Try again</button><a href="/">Return to sign in</a></section></main>;
  const page = labels[path] ? path : "/dashboard";
  const [eyebrow, description] = labels[page];
  const title = pages.find(([href]) => href === page)?.[1] ?? "Overview";
  return <div className="shell"><a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="rail"><a className="brand" href="/dashboard" onClick={(e) => { e.preventDefault(); navigate("/dashboard"); }}><Brand/><span><b>Jellyfin Proxy</b><small>Administration</small></span></a>
      <nav aria-label="Main navigation">{available.map(([href, label, icon]) => <a key={href} href={href} className={`nav-link ${page === href ? "active" : ""}`} aria-current={page === href ? "page" : undefined} onClick={(e) => { e.preventDefault(); navigate(href); }}><span className="nav-icon" aria-hidden="true">{icon}</span><span>{label}</span></a>)}</nav>
      <div className="rail-bottom"><form action="/logout" method="post"><input type="hidden" name="csrf" value={initial.csrf}/><button className="nav-link" type="submit"><span className="nav-icon" aria-hidden="true">↪</span>Sign out</button></form></div>
    </aside>
    <main id="main-content" className="main" tabIndex={-1}><header className="topbar"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></div><button className="mobile-menu" aria-label="Toggle navigation" onClick={() => document.body.classList.toggle("nav-open")}>☰</button></header>
      {error && <div className="banner" role="alert">{error}</div>}
      {page === "/dashboard" && <Dashboard data={initial} go={navigate}/>}
      {page === "/statistics" && <Statistics metrics={metrics ?? initial.current}/>}
      {page === "/health" && <Health data={initial} refresh={refresh}/>}
      {page === "/access-control" && <Access data={initial}/>}
      {page === "/wireguard" && <WireGuard data={initial} refresh={refresh}/>}
      {page === "/security" && <Security data={initial}/>}
      <footer className="page-footer"><span>Version {initial.version} · Build {initial.build_number}</span></footer>
    </main>
  </div>;
}

function Brand() { return <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 36 36"><path d="M18 3 32 29H4L18 3Z"/><circle cx="18" cy="20" r="4"/></svg></span>; }
function Stat({ title, value, detail, color = "cyan" }: { title: string; value: string; detail: string; color?: string }) { return <article className={`stat-card ${color}`}><div className="stat-head"><span className="stat-glyph" aria-hidden="true">✦</span><span>{title}</span></div><strong>{value}</strong><small>{detail}</small><span className="stat-glow"/></article>; }
function Dashboard({ data, go }: { data: Initial; go: (path: string) => void }) {
  const healthyCount = data.components.filter((component) => component.state === "Healthy").length;
  return <>
    <section className="panel overview-status"><div className="overview-summary"><div><p className="eyebrow">SYSTEM HEALTH</p><h2>{worst(data.components)}</h2><p>{healthyCount} of {data.components.length} components healthy</p></div><button className="button secondary" onClick={() => go("/health")}>Health details →</button></div><ul className="overview-components" aria-label="Component status">{data.components.map((component) => <li key={component.name}><span>{component.name}</span><span className={`state-pill ${component.class}`}><i/>{component.state}</span></li>)}</ul></section>
  </>;
}
function worst(items: Component[]) { const states = items.map((item) => item.state); return states.includes("Down") ? "Down" : states.includes("Degraded") ? "Degraded" : states.includes("Unknown") ? "Unknown" : "Healthy"; }
function displayTime(value?: string) { return value ? new Date(value).toLocaleString() : "Not recorded"; }
function ComponentCards({ components }: { components: Component[] }) { return <div className="component-grid">{components.map((item) => <article className="component-card" key={item.name}><span className={`state-pill ${item.class}`}><i/>{item.state}</span><h3>{item.name}</h3><p>{item.detail}</p><small>Checked {displayTime(item.checked_at)} · Last success {displayTime(item.last_success_at)} · Last failure {displayTime(item.last_failure_at)}</small></article>)}</div>; }
function PathDiagram() { return <div className="path-diagram" aria-label="Jellyfin connection path"><span>Caddy / Proxy</span><b>→</b><span>WireGuard</span><b>→</b><span>Windows PC</span><b>→</b><span>Jellyfin</span></div>; }
function Statistics({ metrics }: { metrics: Metrics }) {
  const [range, setRange] = useState("24h"); const [history, setHistory] = useState<HistoryPoint[]>([]); const [failed, setFailed] = useState(false);
  useEffect(() => { let alive = true; fetch(`/statistics/history?range=${range}`, { credentials: "same-origin" }).then((response) => { if (!response.ok) throw new Error(); return response.json() as Promise<HistoryPoint[]>; }).then((rows) => { if (alive) { setHistory(rows); setFailed(false); } }).catch(() => { if (alive) setFailed(true); }); return () => { alive = false; }; }, [range]);
  const host = metrics.host; const proxy = metrics.proxy;
  return <><div className="toolbar"><span className="live-indicator"><i/>{metrics.status === "live" ? "Live via SSE" : "Waiting for metrics"}</span><label>History range <select value={range} onChange={(event) => setRange(event.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="90d">Last 90 days</option></select></label></div>
    <section className="stat-grid"><Stat title="Active requests" value={number(proxy?.active_requests)} detail="HTTP requests in flight"/><Stat title="Requests / sec" value={number(proxy?.requests_per_second)} detail="Current request rate" color="purple"/><Stat title="Allowed / blocked" value={`${number(proxy?.allowed_requests)} / ${number(proxy?.blocked_requests)}`} detail="Since Caddy started" color="blue"/><Stat title="Error rate" value={number(proxy?.error_rate_percent, "%")} detail={`${number(proxy?.http_error_count)} HTTP errors`} color="amber"/></section>
    <section className="stat-grid compact"><Stat title="CPU" value={number(host?.cpu_percent, "%")} detail="VPS host"/><Stat title="Memory" value={pct(host?.memory_used_bytes, host?.memory_total_bytes)} detail={`${bytes(host?.memory_used_bytes)} of ${bytes(host?.memory_total_bytes)}`} color="purple"/><Stat title="Incoming" value={rate(proxy?.incoming_bytes_per_second)} detail="Client → proxy" color="blue"/><Stat title="Outgoing" value={rate(proxy?.outgoing_bytes_per_second)} detail="Proxy → client" color="amber"/></section>
    {failed && <p className="notice" role="status">Historical statistics could not be loaded. Live values remain available.</p>}
    <section className="chart-grid"><Chart title="Proxy traffic" rows={history} read={(row) => row.proxy?.outgoing_bytes_per_second}/><Chart title="Request rate" rows={history} read={(row) => row.proxy?.requests_per_second}/><Chart title="CPU usage" rows={history} read={(row) => row.host?.cpu_percent}/><Chart title="Memory usage" rows={history} read={(row) => row.host?.memory_used_bytes}/></section>
  </>;
}
function Chart({ title, rows, read }: { title: string; rows: HistoryPoint[]; read: (row: HistoryPoint) => number | undefined }) {
  const validRows = rows.map((row) => ({ row, value: read(row) })).filter((sample): sample is { row: HistoryPoint; value: number } => sample.value != null && Number.isFinite(sample.value));
  const values = validRows.map((sample) => sample.value);
  const samples = chartPoints(values);
  const points = samples.map(({x,y}) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const [requestedIndex, setRequestedIndex] = useState(-1);
  const activeIndex = samples.length ? Math.min(requestedIndex < 0 ? samples.length - 1 : requestedIndex, samples.length - 1) : -1;
  const selected = activeIndex >= 0 ? samples[activeIndex] : undefined;
  const selectedRow = activeIndex >= 0 ? validRows[activeIndex]?.row : undefined;
  const displayedValue = selected ? title === "Proxy traffic" ? rate(selected.value) : title === "Memory usage" ? bytes(selected.value) : title === "CPU usage" ? number(selected.value, "%") : number(selected.value) : "No samples";
  const chooseNearest = (event: React.PointerEvent<SVGSVGElement>) => {
    if (samples.length < 2) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    if (bounds.width <= 0) return;
    const chartX = Math.max(0, Math.min(600, (event.clientX - bounds.left) * 600 / bounds.width));
    setRequestedIndex(nearestChartPoint(samples, chartX));
  };
  const crosshair = selected ? `M${selected.x.toFixed(1)} 10V150` : "";
  return <article className="panel chart-panel"><div className="panel-title"><div><p className="eyebrow">HISTORY</p><h2>{title}</h2></div><span className="muted">{values.length} samples</span></div>
    <svg className="chart" viewBox="0 0 600 160" role="group" aria-label={`${title} historical chart`} preserveAspectRatio="none" onPointerMove={chooseNearest} onPointerDown={chooseNearest} onPointerLeave={() => setRequestedIndex(-1)}>
      <path className="chart-gridline" d="M0 20H600M0 60H600M0 100H600M0 150H600"/><polyline points={points}/>
      {selected && <><path className="chart-crosshair" d={crosshair}/><circle className="chart-selected" cx={selected.x} cy={selected.y} r="5"/></>}
    </svg>
    <label className="chart-scrubber">Explore samples<input aria-label={`${title} chart sample`} className="chart-range" type="range" min="0" max={Math.max(values.length - 1, 0)} value={Math.max(activeIndex, 0)} disabled={values.length < 2} onChange={(event) => setRequestedIndex(Number(event.target.value))}/><output className="chart-output">{selectedRow?.captured_at ? new Date(selectedRow.captured_at).toLocaleString() : "No measurements recorded for this range"} · {displayedValue}</output></label>
  </article>;
}

function Health({ data, refresh }: { data: Initial; refresh: () => void }) { return <><div className="health-summary"><span className="health-dot"/><div><b>{worst(data.components)}</b><p>Each state is based on its latest check. Unknown means the service cannot be observed through the private admin boundary.</p></div><button className="button secondary" onClick={refresh}>Run diagnostics</button></div><article className="panel"><div className="panel-title"><div><p className="eyebrow">SERVICE PATH</p><h2>Caddy → WireGuard → Windows PC → Jellyfin</h2></div></div><PathDiagram/><p className="muted">Peer handshakes and Jellyfin reachability are checked from the WireGuard network namespace. Container liveness and restart counts come from a private, GET-only Docker observer.</p></article><section className="panel"><div className="panel-title"><div><p className="eyebrow">COMPONENTS</p><h2>Detailed status</h2></div></div><ComponentCards components={data.components}/></section><section className="panel"><div className="panel-title"><div><p className="eyebrow">RECENT CHANGES</p><h2>Health history</h2></div><span className="muted">Last 90 days · up to 500 changes</span></div>{data.health_events.length ? <ol className="health-events">{[...data.health_events].reverse().map((event, index) => <li key={`${event.at}-${event.name}-${index}`}><time dateTime={event.at}>{displayTime(event.at)}</time><b>{event.name}</b><span>{event.from ?? "First check"} → {event.to}</span><p>{event.detail}</p></li>)}</ol> : <p className="empty-chart">No health status changes have been recorded.</p>}</section></>; }
function Access({ data }: { data: Initial }) {
  const entries = data.whitelist_entries ?? (data.whitelist ?? []).map((address) => ({ address, name: "" }));
  return <section className="panel"><div className="panel-title"><div><p className="eyebrow">DEFAULT DENY</p><h2>Allowed addresses</h2><p className="muted">IPv4, IPv6, and CIDR ranges with the trusted socket peer address.</p></div></div>
    <form className="inline-form" action="/whitelist/add" method="post"><input type="hidden" name="csrf" value={data.csrf}/><div className="form-field"><label htmlFor="allow-entry">IP address or CIDR</label><input id="allow-entry" name="entry" placeholder="203.0.113.10 or 2001:db8::/64" required maxLength={64}/></div><div className="form-field"><label htmlFor="allow-name">Friendly name (optional)</label><input id="allow-name" name="name" placeholder="e.g. Home phone" maxLength={80}/></div><button className="button" type="submit">Add address</button></form>
    <div className="address-list">{entries.length ? entries.map((entry, index) => <div className="address-row" key={entry.address}><div className="address-label"><code>{entry.address}</code>{entry.name && <span>{entry.name}</span>}</div><div className="address-actions"><details className="address-name-details"><summary>{entry.name ? "Edit name" : "Add name"}</summary><form className="address-name-form" action="/whitelist/name" method="post"><input type="hidden" name="csrf" value={data.csrf}/><input type="hidden" name="entry" value={entry.address}/><label className="sr-only" htmlFor={`allow-name-${index}`}>Friendly name for {entry.address}</label><input id={`allow-name-${index}`} name="name" defaultValue={entry.name} placeholder="e.g. Home phone" maxLength={80}/><button className="button secondary" type="submit">Save name</button></form></details><form action="/whitelist/remove" method="post"><input type="hidden" name="csrf" value={data.csrf}/><input type="hidden" name="entry" value={entry.address}/><button className="button danger" type="submit" aria-label={`Remove ${entry.address}`}>Remove</button></form></div></div>) : <p className="empty-chart">No addresses are configured. Access remains blocked by default.</p>}</div>
  </section>;
}
function WireGuard({ data, refresh }: { data: Initial; refresh: () => Promise<Initial | undefined> }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadConsumed, setDownloadConsumed] = useState(false);
  const status = data.wireguard_status;
  const configurationAvailable = data.wireguard_config_available && !downloadConsumed;
  async function downloadConfiguration() {
    if (downloading) return;
    setDownloading(true);
    try {
      const response = await fetch("/wireguard/config", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) return;
      const configuration = await response.blob();
      const objectURL = URL.createObjectURL(configuration);
      const link = document.createElement("a");
      link.href = objectURL;
      link.download = "jellyfin-proxy.conf";
      link.hidden = true;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
      setDownloadConsumed(true);
      await refresh();
    } catch {
      // Keep the download action available when the transfer did not complete.
    } finally {
      setDownloading(false);
    }
  }
  return <><section className="panel"><div className="panel-title"><div><p className="eyebrow">WINDOWS PEER</p><h2>WireGuard configuration</h2></div></div>
    {configurationAvailable ? <button className="button download-button" type="button" onClick={downloadConfiguration} disabled={downloading}>Download configuration</button> : <form action="/wireguard/rotate" method="post"><input type="hidden" name="csrf" value={data.csrf}/><button className="button danger" type="submit">Regenerate and revoke current peer</button></form>}
  </section>{status && <section className="panel"><div className="panel-title"><div><p className="eyebrow">LIVE DIAGNOSTICS</p><h2>Current tunnel status</h2></div></div><div className="stat-grid"><Stat title="Windows peer" value={status.peer_state} detail={status.peer_last_handshake ? `Handshake ${displayTime(status.peer_last_handshake)}` : "No handshake recorded"} color="blue"/><Stat title="Received" value={bytes(status.peer_rx_bytes)} detail="Peer traffic received by VPS" color="cyan"/><Stat title="Sent" value={bytes(status.peer_tx_bytes)} detail="Peer traffic sent by VPS" color="purple"/></div><p className="muted">{status.peer_detail}</p></section>}</>;
}
function Security({ data }: { data: Initial }) { return <><section className="panel"><div className="panel-title"><div><p className="eyebrow">ADMINISTRATOR ACCOUNT</p><h2>Change password</h2></div></div><p className="muted">Use at least 12 characters. Changing the password signs out all administrator sessions. Authenticator protection remains enabled.</p><form className="form-grid" action="/password/change" method="post"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Current password" name="current_password" autocomplete="current-password"/><Field label="New password" name="new_password" autocomplete="new-password"/><Field label="Confirm new password" name="confirm_password" autocomplete="new-password"/>{data.totp_status === "enabled" && <div className="form-field"><label htmlFor="password-change-code">Current six-digit authenticator code for password change</label><input id="password-change-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" maxLength={6} required/></div>}<button className="button" type="submit">Change password</button></form><p className="muted">Root recovery remains available with <code>proxyctl reset-password</code>.</p></section><TOTP data={data}/></>; }
function Field({ label, name, autocomplete }: { label: string; name: string; autocomplete: string }) { return <div className="form-field"><label htmlFor={name}>{label}</label><input id={name} name={name} type="password" autoComplete={autocomplete} minLength={12} maxLength={1024} required/></div>; }
function TOTP({ data }: { data: Initial }) { return <section className="panel"><div className="panel-title"><div><p className="eyebrow">TWO-FACTOR AUTHENTICATION</p><h2>Administrator authenticator</h2></div><span className={`state-pill ${data.totp_status === "enabled" ? "healthy" : "unknown"}`}><i/>{data.totp_status === "enabled" ? "Enabled" : data.totp_status}</span></div>{data.totp_status === "enabled" ? <><p>Two-factor authentication is enabled for administrator sign-in.</p><details className="details"><summary>Disable two-factor authentication</summary><p className="muted">Both your administrator password and a current authenticator code are required. All administrator sessions will be signed out.</p><form action="/totp/disable" method="post" className="form-grid"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Administrator password" name="password" autocomplete="current-password"/><div className="form-field"><label htmlFor="disable-code">Current six-digit authenticator code</label><input id="disable-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" maxLength={6} required/></div><button className="button danger" type="submit">Disable authenticator</button></form></details></> : <><p className="muted">Add a second factor to protect administrator sign-in.</p><form action="/totp/enroll/start" method="post" className="inline-form"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Administrator password" name="password" autocomplete="current-password"/><button className="button" type="submit">Set up authenticator</button></form>{data.totp_setup_visible && <div className="setup-card"><p>Scan the QR code or enter the secret in your authenticator app.</p>{data.totp_qr_code && <img src={data.totp_qr_code} alt="Authenticator setup QR code" width="256" height="256"/>}<code>{data.totp_secret}</code><form action="/totp/enroll/confirm" method="post" className="inline-form"><input type="hidden" name="csrf" value={data.csrf}/><label htmlFor="confirm-code">Six-digit code</label><input id="confirm-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required/><button className="button" type="submit">Confirm authenticator</button></form><form action="/totp/enroll/cancel" method="post"><input type="hidden" name="csrf" value={data.csrf}/><button className="button secondary" type="submit">Cancel setup</button></form></div>}</>}</section>; }

function main() { const root = document.getElementById("root"); if (root) createRoot(root).render(<React.StrictMode><App/></React.StrictMode>); }
main();

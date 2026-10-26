import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import "./statistics-settings.css";
import { chartPoints, chartSegments, formatBytes as bytes, formatNumber as number, formatPercent as pct, formatRate as rate } from "./metrics";
import { SecurityProtection, type SecuritySnapshot } from "./security-dashboard";
import "./redesign.css";

type Component = { name: string; state: string; class: string; detail: string; checked_at?: string; last_success_at?: string; last_failure_at?: string };
type HealthEvent = { at: string; name: string; from?: string; to: string; detail: string };
type Metrics = { captured_at?: string; host?: HostMetrics; proxy?: ProxyMetrics };
type WireGuardStatus = { peer_public_key: string; server_address: string; client_address: string; listen_port: number; config_available: boolean; peer_state: string; peer_detail: string; peer_last_handshake?: string; peer_rx_bytes: number; peer_tx_bytes: number };
type WhitelistEntry = { address: string; name?: string };
type HostMetrics = { cpu_percent?: number; memory_used_bytes?: number; memory_total_bytes?: number; disk_used_bytes?: number; disk_total_bytes?: number; network_in_bytes_per_second?: number; network_out_bytes_per_second?: number; load_1?: number; load_5?: number; load_15?: number; uptime_seconds?: number };
type ProxyMetrics = { active_requests?: number; requests_per_second?: number; allowed_requests?: number; blocked_requests?: number; http_error_count?: number; error_rate_percent?: number; incoming_bytes_per_second?: number; outgoing_bytes_per_second?: number; total_transferred_bytes?: number };
type Initial = { csrf: string; version: string; build_number: string; whitelist_enabled: boolean; whitelist: string[]; whitelist_entries?: WhitelistEntry[]; wireguard_enabled: boolean; wireguard_config_available: boolean; wireguard_status?: WireGuardStatus; totp_status: string; totp_setup_visible: boolean; totp_secret?: string; totp_qr_code?: string; components: Component[]; health_events: HealthEvent[] | null; current: Metrics; security?: SecuritySnapshot; security_error?: string };
type HistoryPoint = { captured_at: string; host?: HostMetrics; proxy?: ProxyMetrics };
type StatisticsSettings = { proxy_retention_days: number; security_retention_days: number; database_bytes: number; retained_samples: number; disk_available_bytes?: number };
type WebContentStatus = { current_revision?: string; previous_revision?: string };
type SystemBackup = { name: string; size_bytes: number; modified_at: string };
type MaintenanceJob = { id: string; action: string; state: string; step: number; total: number; message: string; result?: string; error?: string; started_at: string; updated_at: string; completed_at?: string };
type PackageUpload = { id: string; filename: string; size_bytes: number; chunk_bytes: number; total_chunks: number; received_chunks: number[]; complete: boolean; sha256?: string; updated_at: string };
type SavedPackageUpload = { id: string; filename: string; sizeBytes: number; lastModified: number };
type UpdateReview = { current_version: string; current_build_id: string; candidate_version: string; candidate_build_id: string; target_os: string; architecture: string; database_schema_minimum: number; database_schema_maximum: number };
type ReleaseVersion = { version?: string; build_id?: string };
type ReleaseState = { current: ReleaseVersion; previous: ReleaseVersion };
type RecoveryService = { service: string; state: string; health: string; attempts: number; next_attempt_at?: string; last_action?: string; stopped: boolean; detail?: string };
type RecoveryEvent = { at: string; service: string; action: string; attempt: number; detail: string };
type RecoveryStatus = { checked_at?: string; operation_active: boolean; services: RecoveryService[] | null; events: RecoveryEvent[] | null };
type AboutInfo = { version: string; build_id: string; installed_at?: string; go_version: string; inventory_available: boolean; ubuntu_version?: string; proxyctl_version?: string; docker_engine_version?: string; compose_version?: string; services: { service: string; image: string; component_version?: string }[] };

type NavPage = readonly [href: string, label: string, icon: string];
type SectionTab = readonly [href: string, label: string];
type AdminSection = { label: string; href: string; pages: SectionTab[] };
const sections: AdminSection[] = [
  { label: "Monitor", href: "/statistics", pages: [["/statistics", "Traffic"], ["/health", "Health"]] },
  { label: "Network", href: "/access-control", pages: [["/access-control", "Access"], ["/wireguard", "Tunnel"]] },
  { label: "Security", href: "/security", pages: [["/security", "Account"], ["/security/protection", "Protection"]] },
  { label: "System", href: "/system", pages: [["/system", "Updates"], ["/backups", "Backups"], ["/settings", "Storage"], ["/web-content", "Website"], ["/about", "About"]] },
];
const labels: Record<string, { section: string; title: string; description: string }> = {
  "/dashboard": { section: "OVERVIEW", title: "Overview", description: "System status at a glance" },
  "/statistics": { section: "MONITOR", title: "Traffic", description: "Current and historical traffic" },
  "/health": { section: "MONITOR", title: "Health", description: "Component health and system resources" },
  "/access-control": { section: "NETWORK", title: "Access", description: "Allowed addresses" },
  "/wireguard": { section: "NETWORK", title: "Tunnel", description: "Configuration and connection status" },
  "/security": { section: "SECURITY", title: "Account", description: "Administrator sign-in and authenticator" },
  "/security/protection": { section: "SECURITY", title: "Protection", description: "Protection status, blocked addresses, and activity" },
  "/system": { section: "SYSTEM", title: "Updates", description: "Application updates and recovery" },
  "/backups": { section: "SYSTEM", title: "Backups", description: "Create, restore, and manage backups" },
  "/settings": { section: "SYSTEM", title: "Storage", description: "History retention and storage use" },
  "/web-content": { section: "SYSTEM", title: "Website", description: "Homepage and error pages" },
  "/about": { section: "SYSTEM", title: "About", description: "Build and component versions" },
};
const sessionEndedMessage = "Your administrator session has ended. Sign in again.";

async function getInitial(): Promise<Initial> {
  const response = await fetch("/api/initial", { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(response.status === 401 ? sessionEndedMessage : "The admin service could not load its current status.");
  return response.json() as Promise<Initial>;
}

function useLiveMetrics(onData: (data: Metrics) => void, onHealth: (data: { components: Component[]; health_events: HealthEvent[] | null }) => void, onSecurity: (data: SecuritySnapshot) => void, onAuthRequired: () => void) {
  useEffect(() => {
    const source = new EventSource("/statistics/events", { withCredentials: true });
    source.addEventListener("metrics", (event) => {
      try { onData(JSON.parse((event as MessageEvent<string>).data) as Metrics); } catch { /* reconnect will deliver the next full sample */ }
    });
    source.addEventListener("health", (event) => {
      try { onHealth(JSON.parse((event as MessageEvent<string>).data) as { components: Component[]; health_events: HealthEvent[] | null; wireguard_status?: WireGuardStatus }); } catch { /* reconnect will deliver the next health snapshot */ }
    });
    source.addEventListener("security", (event) => {
      try { onSecurity(JSON.parse((event as MessageEvent<string>).data) as SecuritySnapshot); } catch { /* reconnect will deliver the next security snapshot */ }
    });
    source.addEventListener("auth-required", () => { source.close(); onAuthRequired(); });
    return () => source.close();
  }, [onData, onHealth, onSecurity, onAuthRequired]);
}

function App() {
  const [initial, setInitial] = useState<Initial>();
  const [metrics, setMetrics] = useState<Metrics>();
  const [path, setPath] = useState(window.location.pathname === "/" ? "/dashboard" : window.location.pathname);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const refresh = useCallback(async () => {
    setRefreshing(true);
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
      setRefreshing(false);
    }
  }, []);
  const onLive = useCallback((value: Metrics) => setMetrics(value), []);
  const onHealth = useCallback((value: { components: Component[]; health_events: HealthEvent[] | null; wireguard_status?: WireGuardStatus }) => setInitial((prior) => prior ? { ...prior, ...value } : prior), []);
  const onSecurity = useCallback((value: SecuritySnapshot) => setInitial((prior) => prior ? { ...prior, security: value, security_error: undefined } : prior), []);
  const onAuthRequired = useCallback(() => setError(sessionEndedMessage), []);
  const onWireGuardConfigConsumed = useCallback(() => setInitial((prior) => prior ? {
    ...prior,
    wireguard_config_available: false,
    wireguard_status: prior.wireguard_status ? { ...prior.wireguard_status, config_available: false } : undefined,
  } : prior), []);
  const onSessionEnded = useCallback(() => setError(sessionEndedMessage), []);
  useLiveMetrics(onLive, onHealth, onSecurity, onAuthRequired);
  useEffect(() => { void refresh(); const pop = () => setPath(window.location.pathname); window.addEventListener("popstate", pop); return () => window.removeEventListener("popstate", pop); }, [refresh]);
  const navigate = (to: string) => { window.history.pushState({}, "", to); setPath(to); setNavOpen(false); document.body.classList.remove("nav-open"); window.scrollTo({ top: 0, behavior: "smooth" }); };

  if (loading) return <main className="loading" aria-live="polite">Connecting to administration…</main>;
  if (!initial || error === sessionEndedMessage) return <main className="loading"><section className="error-card"><Brand/><h1>Admin connection unavailable</h1><p role="alert">{error || "Current administrator status is unavailable."}</p><button className="button" onClick={() => void refresh()} disabled={refreshing}>{refreshing ? "Retrying…" : "Try again"}</button><a href="/">Return to sign in</a></section></main>;
  const page = labels[path] ? path : "/dashboard";
  const { section: eyebrow, description, title } = labels[page];
  const sectionPagesAvailable = (href: string) => href !== "/access-control" || initial.whitelist_enabled;
  const availableSections = sections.map((item) => ({ ...item, pages: item.pages.filter(([href]) => sectionPagesAvailable(href) && (href !== "/wireguard" || initial.wireguard_enabled)) })).filter((item) => item.pages.length > 0).map((item) => ({ ...item, href: item.pages[0][0] }));
  const section = availableSections.find((item) => item.pages.some(([href]) => href === page));
  const selectedMainPage = section?.href ?? page;
  const mainNav: NavPage[] = [["/dashboard", "Overview", "⌂"], ...availableSections.map((item) => [item.href, item.label, item.label === "Monitor" ? "▥" : item.label === "Network" ? "◇" : item.label === "Security" ? "⛨" : "▣"] as NavPage)];
  return <div className="shell"><a className="skip-link" href="#main-content">Skip to content</a>
    <button className="nav-scrim" type="button" aria-label="Close navigation" onClick={() => { setNavOpen(false); document.body.classList.remove("nav-open"); }}/>
    <aside className="rail"><a className="brand" href="/dashboard" onClick={(e) => { e.preventDefault(); navigate("/dashboard"); }}><Brand/><span><b>Admin</b><small>Control panel</small></span></a>
      <nav id="main-navigation" aria-label="Main navigation">{mainNav.map(([href, label, icon]) => <a key={href} href={href} className={`nav-link ${selectedMainPage === href ? "active" : ""}`} aria-current={selectedMainPage === href ? "page" : undefined} onClick={(e) => { e.preventDefault(); navigate(href); }}><span className="nav-icon" aria-hidden="true">{icon}</span><span>{label}</span></a>)}</nav>
      <div className="rail-bottom"><form action="/logout" method="post"><input type="hidden" name="csrf" value={initial.csrf}/><button className="nav-link" type="submit"><span className="nav-icon" aria-hidden="true">↪</span>Sign out</button></form></div>
    </aside>
    <main id="main-content" className="main" tabIndex={-1}><header className="topbar"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></div><button className="mobile-menu" aria-label="Toggle navigation" aria-expanded={navOpen} aria-controls="main-navigation" onClick={() => { setNavOpen((open) => !open); document.body.classList.toggle("nav-open"); }}>☰</button></header>
      {section && <nav className="section-tabs" aria-label={`${section.label} pages`}>{section.pages.map(([href, label]) => <a key={href} href={href} className={page === href ? "active" : ""} aria-current={page === href ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate(href); }}>{label}</a>)}</nav>}
      {error && <div className="banner" role="alert"><span>{error}</span><button className="text-button" type="button" onClick={() => void refresh()} disabled={refreshing}>{refreshing ? "Retrying…" : "Try again"}</button></div>}
      {page === "/dashboard" && <Dashboard data={initial} go={navigate}/>}
      {page === "/statistics" && <Statistics metrics={metrics ?? initial.current}/>}
      {(page === "/system" || page === "/backups") && <System csrf={initial.csrf} view={page === "/system" ? "updates" : "backups"}/>}
      {page === "/health" && <Health data={initial} metrics={metrics ?? initial.current} refresh={refresh}/>}
      {page === "/access-control" && <Access data={initial}/>}
      {page === "/wireguard" && <WireGuard data={initial} onConfigConsumed={onWireGuardConfigConsumed} onSessionEnded={onSessionEnded}/>}
      {page === "/security" && <Security data={initial}/>}
      {page === "/security/protection" && <SecurityProtection csrf={initial.csrf} snapshot={initial.security} error={initial.security_error} onSnapshot={onSecurity}/>}
      {page === "/settings" && <StatisticsStorageSettings csrf={initial.csrf} onSecurity={onSecurity}/>}
      {page === "/web-content" && <WebContent csrf={initial.csrf}/>}
      {page === "/about" && <About/>}
    </main>
  </div>;
}

function System({ csrf, view }: { csrf: string; view: "updates" | "backups" }) {
  const [backups, setBackups] = useState<SystemBackup[]>([]);
  const [release, setRelease] = useState<ReleaseState>();
  const [job, setJob] = useState<MaintenanceJob>();
  const [packageFile, setPackageFile] = useState<File>();
  const [savedUpload, setSavedUpload] = useState<SavedPackageUpload>();
  const [upload, setUpload] = useState<PackageUpload>();
  const [checksum, setChecksum] = useState("");
  const [review, setReview] = useState<UpdateReview>();
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [progressConnection, setProgressConnection] = useState<"reconnecting" | "sign-in" | "">("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const activeJob = job?.state === "queued" || job?.state === "running";
  const uploadMatchesFile = !!packageFile && !!savedUpload && packageFile.name === savedUpload.filename && packageFile.size === savedUpload.sizeBytes && packageFile.lastModified === savedUpload.lastModified;
  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const [backupResponse, jobsResponse, releaseResponse] = await Promise.all([
        fetch("/system/backups", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } }),
        fetch("/system/jobs", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } }),
        fetch("/system/releases", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } }),
      ]);
      if (!backupResponse.ok || !jobsResponse.ok || !releaseResponse.ok) throw new Error("System status is unavailable.");
      setBackups(await backupResponse.json() as SystemBackup[]);
      const jobs = await jobsResponse.json() as MaintenanceJob[];
      setJob(jobs[0]);
      setRelease(await releaseResponse.json() as ReleaseState);
      setError("");
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "System status is unavailable.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    let alive = true;
    let raw: string | null;
    try { raw = window.localStorage.getItem("jellyfin-proxy-system-upload"); } catch { return () => { alive = false; }; }
    if (!raw) return () => { alive = false; };
    try {
      const saved = JSON.parse(raw) as SavedPackageUpload;
      if (!/^[a-f0-9]{32}$/.test(saved.id) || typeof saved.filename !== "string" || !Number.isSafeInteger(saved.sizeBytes) || !Number.isSafeInteger(saved.lastModified)) throw new Error("invalid upload record");
      fetch(`/system/uploads/${saved.id}`, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } }).then(async (response) => {
        if (!response.ok) throw new Error("Stored upload is no longer available.");
        return await response.json() as PackageUpload;
      }).then((value) => { if (alive) { setSavedUpload(saved); setUpload(value); } }).catch(() => {
        if (alive) { try { window.localStorage.removeItem("jellyfin-proxy-system-upload"); } catch { /* Storage may be disabled in private browsing. */ } }
      });
    } catch {
      try { window.localStorage.removeItem("jellyfin-proxy-system-upload"); } catch { /* Storage may be disabled in private browsing. */ }
    }
    return () => { alive = false; };
  }, []);
  useEffect(() => {
    if (!activeJob) return;
    let alive = true;
    let stoppedForSession = false;
    let timer = 0;
    const poll = async () => {
      try {
        const response = await fetch(`/system/jobs/${encodeURIComponent(job!.id)}`, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
        if (response.status === 401 || response.redirected) {
          if (alive) setProgressConnection("sign-in");
          stoppedForSession = true;
          return;
        }
        if (!response.ok) throw new Error("Maintenance progress is unavailable.");
        const current = await response.json() as MaintenanceJob;
        if (alive) {
          setProgressConnection("");
          setJob(current);
          if (current.state === "completed" || current.state === "failed") void load();
        }
      } catch {
        if (alive) setProgressConnection("reconnecting");
      }
      if (alive && !stoppedForSession) timer = window.setTimeout(() => void poll(), 1000);
    };
    timer = window.setTimeout(() => void poll(), 1000);
    return () => { alive = false; window.clearTimeout(timer); };
  }, [activeJob, job?.id, load]);
  async function uploadAndReview() {
    if (!packageFile) { setError("Choose a .pkg release file first."); return; }
    const expected = checksum.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(expected)) { setError("Enter the 64-character SHA-256 value from the package checksum file."); return; }
    setError(""); setReview(undefined); setUploading(true);
    try {
      let current: PackageUpload;
      let saved: SavedPackageUpload;
      if (uploadMatchesFile && savedUpload) {
        saved = savedUpload;
        const existing = await fetch(`/system/uploads/${saved.id}`, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
        if (!existing.ok) throw new Error("The saved upload expired. Start a new upload.");
        current = await existing.json() as PackageUpload;
        if (current.filename !== packageFile.name || current.size_bytes !== packageFile.size) throw new Error("The selected file does not match the saved upload.");
      } else {
        const created = await fetch("/system/uploads", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ filename: packageFile.name, size_bytes: packageFile.size }) });
        if (!created.ok) throw new Error((await created.text()).trim() || "Package upload could not be started.");
        current = await created.json() as PackageUpload;
        saved = { id: current.id, filename: packageFile.name, sizeBytes: packageFile.size, lastModified: packageFile.lastModified };
        try { window.localStorage.setItem("jellyfin-proxy-system-upload", JSON.stringify(saved)); } catch { /* The current upload still works without reload recovery. */ }
        setSavedUpload(saved);
      }
      const received = new Set(current.received_chunks);
      setUpload(current);
      setUploadProgress(received.size / current.total_chunks);
      for (let index = 0; index < current.total_chunks; index++) {
        if (received.has(index)) continue;
        const start = index * current.chunk_bytes;
        const chunk = packageFile.slice(start, Math.min(start + current.chunk_bytes, packageFile.size));
        const response = await fetch(`/system/uploads/${current.id}/${index}`, { method: "PUT", credentials: "same-origin", headers: { "X-CSRF-Token": csrf, "Content-Type": "application/octet-stream" }, body: chunk });
        if (!response.ok) throw new Error((await response.text()).trim() || `Package upload paused at part ${index + 1}; select the same file to resume.`);
        current = await response.json() as PackageUpload;
        setUpload(current);
        setUploadProgress(current.received_chunks.length / current.total_chunks);
      }
      const completed = await fetch(`/system/uploads/${current.id}/complete`, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ sha256: expected }) });
      if (!completed.ok) throw new Error((await completed.text()).trim() || "Package checksum verification failed.");
      current = await completed.json() as PackageUpload;
      setUpload(current); setUploadProgress(1);
      const validated = await fetch("/system/packages/validate", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ upload_id: current.id, sha256: expected }) });
      if (!validated.ok) throw new Error((await validated.text()).trim() || "Package is incompatible with this installation.");
      setReview(await validated.json() as UpdateReview);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Package could not be verified.");
    } finally { setUploading(false); }
  }
  async function runJob(action: string, extra: { upload_id?: string; sha256?: string; backup_name?: string } = {}) {
    if (action === "restore" && !window.confirm("Restore this backup? The current application data will be replaced. A safety backup will be created first.")) return;
    if (action === "rollback" && !window.confirm("Roll back to the previous application release? Current data will be preserved and backed up first.")) return;
    if (action === "update" && !window.confirm(`Install ${review?.candidate_version} now? The current installation will be backed up first.`)) return;
    if (action === "delete-backup" && !window.confirm("Permanently delete this backup? This cannot be undone.")) return;
    if (action === "cleanup" && !window.confirm("Remove unused application images? The active release, rollback release, images used by any container, and unrelated Docker images will be kept.")) return;
    setError(""); setProgressConnection(""); setBusy(true);
    try {
      const response = await fetch("/system/jobs", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ action, ...extra }) });
      if (!response.ok) throw new Error((await response.text()).trim() || (response.status === 409 ? "Another maintenance operation is already running." : "Maintenance operation could not be started."));
      setJob(await response.json() as MaintenanceJob);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Maintenance operation could not be started.");
    } finally { setBusy(false); }
  }
  async function createBackup() {
    await runJob("backup");
  }
  const busyOperation = activeJob || busy || uploading;
  return <>
  {view === "updates" && <section className="panel system-panel">
    <div className="panel-title"><div><p className="eyebrow">APPLICATION RELEASE</p><h2>Update or recover</h2><p className="muted">Updates are manual. Upload a verified package and review compatibility before applying it.</p></div><button className="button secondary" type="button" onClick={() => void load()} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh"}</button></div>
    {error && <p className="notice error" role="alert">{error}</p>}
    {job && <div className={`system-job ${job.state}`} role="status" aria-live="polite"><strong>{job.message}</strong>{(job.state === "queued" || job.state === "running") && <progress max={job.total} value={job.step} />}{progressConnection === "reconnecting" && <small>Reconnecting to the maintenance service…</small>}{progressConnection === "sign-in" && <small>Your sign-in ended during the restart. <a href="/">Sign in again</a>, then check System for the result.</small>}{job.result && <small>{job.action === "backup" ? "Backup created" : job.action === "delete-backup" ? "Backup deleted" : `Result: ${job.result}`}</small>}{job.error && <small>{job.error}</small>}</div>}
    <dl className="release-summary"><div><dt>Running</dt><dd>{release?.current.version || "Loading…"}{release?.current.build_id ? ` · ${release.current.build_id}` : ""}</dd></div><div><dt>Previous release</dt><dd>{release?.previous.version ? `${release.previous.version} · ${release.previous.build_id}` : "Not available"}</dd></div></dl>
    <div className="form-grid package-upload-form">
      <div className="form-field"><label htmlFor="release-package">Release package (.pkg)</label><input id="release-package" type="file" accept=".pkg,application/octet-stream" onChange={(event) => { const selected = event.currentTarget.files?.[0]; setPackageFile(selected); setReview(undefined); setError(""); if (selected && savedUpload && selected.name === savedUpload.filename && selected.size === savedUpload.sizeBytes && selected.lastModified === savedUpload.lastModified) { void fetch(`/system/uploads/${savedUpload.id}`, { credentials: "same-origin", cache: "no-store" }).then(async (response) => { if (response.ok) setUpload(await response.json() as PackageUpload); else setUpload(undefined); }); } else setUpload(undefined); }}/></div>
      <div className="form-field"><label htmlFor="package-sha256">Independent SHA-256 checksum</label><input id="package-sha256" type="text" autoComplete="off" spellCheck={false} inputMode="text" maxLength={64} pattern="[A-Fa-f0-9]{64}" placeholder="64 characters from the .sha256 file" value={checksum} onChange={(event) => setChecksum(event.currentTarget.value)}/></div>
      <button className="button" type="button" onClick={() => void uploadAndReview()} disabled={busyOperation || !packageFile}>{uploading ? "Uploading and verifying…" : uploadMatchesFile && upload && !upload.complete ? "Resume upload and verify" : "Upload and verify package"}</button>
    </div>
    {upload && packageFile && uploadMatchesFile && <div className="upload-progress" role="status"><span>{upload.complete ? "Package uploaded" : `Upload ${Math.round(uploadProgress * 100)}% · ${upload.received_chunks.length} of ${upload.total_chunks} parts`}</span><progress max={upload.total_chunks} value={upload.complete ? upload.total_chunks : upload.received_chunks.length}/></div>}
    {!packageFile && upload && <p className="muted">Select the same package file to resume its saved upload.</p>}
    {review && <div className="package-review"><h3>Compatibility review</h3><dl className="release-summary"><div><dt>Current release</dt><dd>{review.current_version} · {review.current_build_id}</dd></div><div><dt>Candidate release</dt><dd>{review.candidate_version} · {review.candidate_build_id}</dd></div><div><dt>Target</dt><dd>{review.target_os} · {review.architecture}</dd></div><div><dt>Statistics schema</dt><dd>{review.database_schema_minimum}–{review.database_schema_maximum}</dd></div></dl><button className="button" type="button" onClick={() => void runJob("update", { upload_id: upload?.id, sha256: checksum.trim().toLowerCase() })} disabled={busyOperation}>Install reviewed update</button></div>}
    {release?.previous.version && <div className="system-recovery-action"><p className="muted">Rollback activates {release.previous.version} and keeps current data.</p><button className="button danger" type="button" onClick={() => void runJob("rollback")} disabled={busyOperation}>Roll back to previous release</button></div>}
    <div className="system-recovery-action"><p className="muted">Remove unused application images while keeping active releases and images used by containers.</p><button className="button secondary" type="button" onClick={() => void runJob("cleanup")} disabled={busyOperation}>Clean unused images</button></div>
  </section>}
  {view === "backups" && <section className="panel system-panel">
     <div className="panel-title"><div><p className="eyebrow">BACKUPS</p><h2>Stored backups</h2><p className="muted">Up to 10 managed backups are kept. Older ones are removed automatically.</p></div><div className="system-actions"><button className="button" type="button" onClick={() => void createBackup()} disabled={busyOperation}>Create backup</button><button className="button secondary" type="button" onClick={() => void load()} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh"}</button></div></div>
    {error && <p className="notice error" role="alert">{error}</p>}
    {job && <div className={`system-job ${job.state}`} role="status" aria-live="polite"><strong>{job.message}</strong>{(job.state === "queued" || job.state === "running") && <progress max={job.total} value={job.step} />}{progressConnection === "reconnecting" && <small>Reconnecting to the maintenance service…</small>}{progressConnection === "sign-in" && <small>Your sign-in ended during the restart. <a href="/">Sign in again</a>, then check System for the result.</small>}{job.result && <small>{job.action === "backup" ? "Backup created" : job.action === "delete-backup" ? "Backup deleted" : `Result: ${job.result}`}</small>}{job.error && <small>{job.error}</small>}</div>}
    {loading ? <p className="muted" role="status">Loading backups…</p> : backups.length === 0 ? <p className="muted">No backups are stored on this server.</p> : <div className="system-backup-list" role="list">{backups.map((backup) => <article className="system-backup-row" role="listitem" key={backup.name}><div><strong>{backupLabel(backup.name)}</strong><small>{bytes(backup.size_bytes)} · {displayTime(backup.modified_at)}</small></div><div className="system-actions"><a className="button secondary" href={`/system/backups/${encodeURIComponent(backup.name)}`} download>Download</a><button className="button secondary" type="button" onClick={() => void runJob("delete-backup", { backup_name: backup.name })} disabled={busyOperation}>Delete</button><button className="button danger" type="button" onClick={() => void runJob("restore", { backup_name: backup.name })} disabled={busyOperation}>Restore</button></div></article>)}</div>}
  </section>}
  </>;
}

function About() {
  const [info, setInfo] = useState<AboutInfo>();
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    fetch("/api/about", { credentials: "same-origin", cache: "no-store" }).then((response) => {
      if (!response.ok) throw new Error("Running component information is unavailable.");
      return response.json() as Promise<AboutInfo>;
    }).then((value) => { if (alive) setInfo(value); }).catch((reason: unknown) => {
      if (alive) setError(reason instanceof Error ? reason.message : "Running component information is unavailable.");
    });
    return () => { alive = false; };
  }, []);
  const services = info?.services ?? [];
  const versionFor = (name: string) => services.find((service) => service.service === name);
  const values: { name: string; version: string; source: string }[] = [
    { name: "Application", version: info ? `${info.version} · ${info.build_id}` : "Loading…", source: "Running admin service" },
    { name: "Installation date", version: info?.installed_at ? displayTime(info.installed_at) : "Not recorded", source: "Persistent installation metadata" },
    { name: "Host utility", version: info?.proxyctl_version || "Unavailable", source: "Installed host utility" },
    { name: "Caddy", version: versionFor("caddy")?.component_version || "Unavailable", source: "Running container image" },
    { name: "WireGuard tools", version: versionFor("wireguard")?.component_version || "Unavailable", source: "Running container image" },
    { name: "Fail2ban", version: versionFor("securityd")?.component_version || "Unavailable", source: "Running container image" },
    { name: "Go", version: info?.go_version || "Unavailable", source: "Admin application build runtime" },
    { name: "Docker Engine", version: info?.docker_engine_version || "Unavailable", source: "Running host engine" },
    { name: "Docker Compose", version: info?.compose_version || "Unavailable", source: "Running host plugin" },
    { name: "Ubuntu", version: info?.ubuntu_version || "Unavailable", source: "Running host OS" },
  ];
  return <section className="panel about-panel">
    <div className="panel-title"><div><p className="eyebrow">VERSION INFORMATION</p><h2>Application and components</h2><p className="muted">Host versions come from the restricted maintenance observer; container versions come from the running images.</p></div></div>
    {!info?.inventory_available && <p className="notice" role="status">Host component inventory is unavailable. Application build details are shown where available.</p>}
    {error && <p className="notice error" role="alert">{error}</p>}
    <dl className="about-version-list">{values.map((item) => <div key={item.name}><dt>{item.name}</dt><dd>{item.version}</dd><small>{item.source}</small></div>)}</dl>
  </section>;
}

function WebContent({ csrf }: { csrf: string }) {
  const [status, setStatus] = useState<WebContentStatus>();
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    const response = await fetch("/web-content/status", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) throw new Error("Public website status is unavailable.");
    setStatus(await response.json() as WebContentStatus);
  }, []);
  useEffect(() => { void load().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Public website status is unavailable.")); }, [load]);
  async function publish(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip") || file.size > 25 * 1024 * 1024) { setError("Choose a ZIP file no larger than 25 MiB."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      const body = new FormData(); body.set("archive", file);
      const response = await fetch("/web-content/upload", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf }, body });
      if (!response.ok) throw new Error((await response.text()).trim() || "Website could not be published.");
      setStatus(await response.json() as WebContentStatus); setFile(undefined);
      const input = document.getElementById("web-content-archive") as HTMLInputElement | null; if (input) input.value = "";
      setNotice("Website published. The previous version is available to restore.");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "Website could not be published."); }
    finally { setBusy(false); }
  }
  async function rollback() {
    if (!status?.previous_revision || !window.confirm("Restore the previous public website version?")) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/web-content/rollback", { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf } });
      if (!response.ok) throw new Error((await response.text()).trim() || "Previous website version could not be restored.");
      setStatus(await response.json() as WebContentStatus); setNotice("Previous website version restored.");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "Previous website version could not be restored."); }
    finally { setBusy(false); }
  }
  return <>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">STATIC WEBSITE</p><h2>Homepage and error pages</h2><p className="muted">Upload a static ZIP. Publishing keeps one previous version for rollback.</p></div></div>
      <form className="web-content-form" onSubmit={publish}>
        <label className="form-field" htmlFor="web-content-archive">Website ZIP<input id="web-content-archive" type="file" accept=".zip,application/zip" onChange={(event) => setFile(event.target.files?.[0])}/></label>
        <button className="button" type="submit" disabled={busy || !file}>{busy ? "Publishing…" : "Publish website"}</button>
      </form>
      <p className="muted web-content-help">ZIP must contain root index.html. Optional custom pages: errors/403.html, errors/404.html, errors/502.html and errors/503.html. Only HTML, CSS, JavaScript and approved image files are accepted.</p>
      {status && <div className="web-content-status" role="status"><span>Published website active</span>{status.previous_revision && <button className="button secondary" type="button" onClick={() => void rollback()} disabled={busy}>Restore previous version</button>}</div>}
      {error && <p className="notice error" role="alert">{error}</p>}{notice && <p className="notice" role="status">{notice}</p>}
    </section>
  </>;
}

function Brand() { return <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 36 36"><path d="M18 3 32 29H4L18 3Z"/><circle cx="18" cy="20" r="4"/></svg></span>; }
function Stat({ title, value, detail, color = "cyan" }: { title: string; value: string; detail: string; color?: string }) { return <article className={`stat-card ${color}`}><div className="stat-head"><span className="stat-glyph" aria-hidden="true">✦</span><span>{title}</span></div><strong>{value}</strong><small>{detail}</small><span className="stat-glow"/></article>; }
function Dashboard({ data, go }: { data: Initial; go: (path: string) => void }) {
  const systemState = worst(data.components);
  const securityState = securityHealthState(data.security);
  const issues: string[] = [];
  if (!data.security) issues.push(data.security_error || "Security protection status is unavailable.");
  else {
    for (const [name, state] of Object.entries(data.security.health)) {
      if (name !== "last_error" && state !== "healthy") issues.push(`${securityLabel(name)}: ${state}`);
    }
    if (data.security.health.last_error) issues.push(data.security.health.last_error);
  }
  return <>
    <section className="panel overview-status" aria-label="Operational summary">
      <div className="overview-summary">
        <div className="overview-check"><p className="eyebrow">SYSTEM</p><strong className={`state-pill ${systemState.toLowerCase()}`}><i/>{systemState}</strong><button className="text-button" onClick={() => go("/health")}>Health details →</button></div>
        <div className="overview-check"><p className="eyebrow">SECURITY PROTECTION</p><strong className={`state-pill ${securityState.toLowerCase()}`}><i/>{securityState}</strong><button className="text-button" onClick={() => go("/security/protection")}>Security details →</button></div>
      </div>
      <ul className="overview-components" aria-label="Component health">{data.components.map((component) => <li key={component.name}><span>{componentLabel(component.name)}</span><span className={`state-pill ${component.class}`}><i/>{component.state}</span></li>)}</ul>
      {issues.length ? <ul className="overview-issues" aria-label="Action needed">{issues.slice(0, 4).map((issue, index) => <li key={`${index}:${issue}`}>{issue}</li>)}{issues.length > 4 && <li>{issues.length - 4} more issues. Open Health or Security for details.</li>}</ul> : <p className="overview-quiet">No action needed.</p>}
    </section>
  </>;
}
function worst(items: Component[]) { const states = items.map((item) => item.state); return states.includes("Down") ? "Down" : states.includes("Degraded") ? "Degraded" : states.includes("Unknown") || states.length === 0 ? "Unknown" : "Healthy"; }
function securityHealthState(snapshot?: SecuritySnapshot) { if (!snapshot) return "Unknown"; const states = Object.entries(snapshot.health).filter(([name]) => name !== "last_error").map(([, state]) => state); return snapshot.health.last_error || states.some((state) => state === "degraded" || state === "down") ? "Degraded" : states.length > 0 && states.every((state) => state === "healthy") ? "Healthy" : "Unknown"; }
function securityLabel(name: string) { return ({ fail2ban: "Fail2ban", ssh_journal: "SSH journal", firewall: "Firewall", admin_events: "Admin authentication events", caddy_sync: "Caddy ban sync" } as Record<string, string>)[name] ?? name; }
function displayTime(value?: string) { return value && !value.startsWith("0001-") ? new Date(value).toLocaleString() : "Not recorded"; }
function componentLabel(name: string) { return ({ "Jellyfin endpoint": "Service endpoint", "Caddy / proxy": "Gateway", "Proxy metrics": "Traffic metrics" } as Record<string, string>)[name] ?? name; }
function publicHealthText(value: string) { return value.replaceAll("Jellyfin", "service").replaceAll("jellyfin", "service").replaceAll("proxy", "gateway").replaceAll("Proxy", "Gateway"); }
function backupLabel(name: string) { return /^jellyfin-proxy-/i.test(name) ? "Managed backup" : name; }
function ComponentCards({ components }: { components: Component[] }) { return <div className="health-component-list">{components.map((item) => <details className="health-component" key={item.name}><summary><span>{componentLabel(item.name)}</span><span className={`state-pill ${item.class}`}><i/>{item.state}</span></summary><p>{publicHealthText(item.detail)}</p><small>Checked {displayTime(item.checked_at)} · Last success {displayTime(item.last_success_at)} · Last failure {displayTime(item.last_failure_at)}</small></details>)}</div>; }
function PathDiagram() { return <div className="path-diagram" aria-label="Service connection path"><span>Gateway</span><b>→</b><span>Tunnel</span><b>→</b><span>Windows PC</span><b>→</b><span>Service</span></div>; }
type ChartDefinition = { title: string; read: (row: HistoryPoint) => number | undefined; unit: "rate" | "percent" | "bytes" | "number" };

function Statistics({ metrics }: { metrics: Metrics }) {
  const [range, setRange] = useState("24h"); const [history, setHistory] = useState<HistoryPoint[]>([]); const [failed, setFailed] = useState(false);
  useEffect(() => { let alive = true; fetch(`/statistics/history?range=${range}`, { credentials: "same-origin" }).then((response) => { if (!response.ok) throw new Error(); return response.json() as Promise<HistoryPoint[]>; }).then((rows) => { if (alive) { setHistory(rows); setFailed(false); } }).catch(() => { if (alive) setFailed(true); }); return () => { alive = false; }; }, [range]);
  const proxy = metrics.proxy;
  const charts: ChartDefinition[] = [
    { title: "Incoming traffic", read: (row) => row.proxy?.incoming_bytes_per_second, unit: "rate" },
    { title: "Outgoing traffic", read: (row) => row.proxy?.outgoing_bytes_per_second, unit: "rate" },
    { title: "Request rate", read: (row) => row.proxy?.requests_per_second, unit: "number" },
  ];
  return <><div className="toolbar"><label>History range <select value={range} onChange={(event) => setRange(event.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="90d">Last 90 days</option></select></label></div>
    <section className="stat-grid proxy-stat-grid"><Stat title="Request rate" value={`${number(proxy?.requests_per_second)}/s`} detail={`${number(proxy?.active_requests)} active requests`} color="purple"/><Stat title="Allowed requests" value={number(proxy?.allowed_requests)} detail="Since service start" color="blue"/><Stat title="Blocked requests" value={number(proxy?.blocked_requests)} detail="Since service start" color="amber"/><Stat title="Error rate" value={number(proxy?.error_rate_percent, "%")} detail={`Latest interval · ${number(proxy?.http_error_count)} total HTTP errors since start`} color="cyan"/></section>
    <section className="stat-grid compact proxy-traffic-summary"><Stat title="Incoming" value={rate(proxy?.incoming_bytes_per_second)} detail="Inbound" color="blue"/><Stat title="Outgoing" value={rate(proxy?.outgoing_bytes_per_second)} detail="Outbound" color="purple"/><Stat title="Total transferred" value={bytes(proxy?.total_transferred_bytes)} detail="Since service start" color="amber"/></section>
    {failed && <p className="notice" role="status">Historical statistics could not be loaded. Live values remain available.</p>}
    <HistoryCharts rows={history} definitions={charts}/>
  </>;
}

function StatisticsStorageSettings({ csrf, onSecurity }: { csrf: string; onSecurity: (snapshot: SecuritySnapshot) => void }) {
  const [settings, setSettings] = useState<StatisticsSettings>();
  const [form, setForm] = useState({ proxy: 30, security: 30 });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const choices = [7, 14, 30, 60, 90, 180];
  const load = useCallback(async () => {
    const response = await fetch("/statistics/settings", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) throw new Error("Statistics and storage settings are unavailable.");
    const result = await response.json() as StatisticsSettings;
    setSettings(result);
    setForm({ proxy: result.proxy_retention_days, security: result.security_retention_days });
  }, []);
  useEffect(() => { void load().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Settings could not be loaded.")); }, [load]);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (settings && (form.proxy < settings.proxy_retention_days || form.security < settings.security_retention_days) && !window.confirm("Reducing retention permanently deletes older history. Continue?")) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch("/statistics/settings", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ proxy_retention_days: form.proxy, security_retention_days: form.security }) });
      if (!response.ok) throw new Error((await response.text()).trim() || "Settings could not be saved.");
      const result = await response.json() as StatisticsSettings;
      setSettings(result);
      const latest = await getInitial();
      if (latest.security) onSecurity(latest.security);
      setNotice("Retention settings saved.");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "Settings could not be saved."); }
    finally { setBusy(false); }
  }
  return <>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">STATISTICS & STORAGE</p><h2>History retention</h2><p className="muted">Choose how long traffic measurements and security events are retained.</p></div></div>
      <form className="storage-settings" onSubmit={save}>
        <label>Traffic statistics<select value={form.proxy} onChange={(event) => setForm({ ...form, proxy: Number(event.target.value) })}>{choices.map((days) => <option value={days} key={days}>{days} days</option>)}</select></label>
        <label>Security event history<select value={form.security} onChange={(event) => setForm({ ...form, security: Number(event.target.value) })}>{choices.map((days) => <option value={days} key={days}>{days} days</option>)}</select></label>
        <button className="button" type="submit" disabled={busy || !settings}>{busy ? "Saving…" : "Save retention"}</button>
      </form>
      {error && <p className="notice error" role="alert">{error}</p>}{notice && <p className="notice" role="status">{notice}</p>}
    </section>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">CURRENT USAGE</p><h2>Storage</h2></div></div>
      {settings ? <dl className="storage-summary"><div><dt>Statistics database</dt><dd>{bytes(settings.database_bytes)}</dd></div><div><dt>Retained samples</dt><dd>{number(settings.retained_samples)}</dd></div><div><dt>Disk available</dt><dd>{settings.disk_available_bytes == null ? "Not available" : bytes(settings.disk_available_bytes)}</dd></div></dl> : <p className="empty-chart">Loading storage details…</p>}
    </section>
  </>;
}

function HistoryCharts({ rows, definitions }: { rows: HistoryPoint[]; definitions: ChartDefinition[] }) {
  const [requestedIndex, setRequestedIndex] = useState(-1);
  const index = rows.length ? Math.min(requestedIndex < 0 ? rows.length - 1 : requestedIndex, rows.length - 1) : -1;
  const row = index >= 0 ? rows[index] : undefined;
  return <>
    <section className="chart-grid" aria-label="Historical metrics">{definitions.map((definition) => <Chart key={definition.title} definition={definition} rows={rows} selectedIndex={index} onSelect={setRequestedIndex}/>)}</section>
    {rows.length > 0 ? <label className="chart-scrubber"><span>Explore time samples</span><input aria-label="Explore historical sample time" className="chart-range" type="range" min="0" max={rows.length - 1} value={index} disabled={rows.length < 2} onChange={(event) => setRequestedIndex(Number(event.target.value))}/><output className="chart-output">{row?.captured_at ? new Date(row.captured_at).toLocaleString() : "No measurements recorded for this range"}</output></label> : <p className="empty-chart">No historical measurements are available for this range.</p>}
  </>;
}

function Chart({ definition, rows, selectedIndex, onSelect }: { definition: ChartDefinition; rows: HistoryPoint[]; selectedIndex: number; onSelect: (index: number) => void }) {
  const values = rows.map(definition.read);
  const points = chartPoints(values);
  const segments = chartSegments(values);
  const max = points.length ? Math.max(...points.map((point) => point.value)) : 0;
  const selectedPoint = points.find((point) => point.index === selectedIndex);
  const selectedValue = selectedIndex >= 0 ? values[selectedIndex] : undefined;
  const x = rows.length < 2 ? 300 : selectedIndex * 600 / (rows.length - 1);
  const outputId = `chart-output-${definition.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  const format = (value: number | undefined) => definition.unit === "rate" ? rate(value) : definition.unit === "bytes" ? bytes(value) : definition.unit === "percent" ? number(value, "%") : number(value);
  const chooseSample = (event: React.PointerEvent<SVGSVGElement>) => {
    if (rows.length < 2) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    if (bounds.width <= 0) return;
    const index = Math.round((event.clientX - bounds.left) / bounds.width * (rows.length - 1));
    onSelect(Math.max(0, Math.min(rows.length - 1, index)));
  };
  return <article className="panel chart-panel"><div className="panel-title"><div><p className="eyebrow">HISTORY</p><h2>{definition.title}</h2></div><span className="muted">{points.length} samples</span></div>
    {points.length ? <div className="chart-layout"><div className="chart-y-axis" aria-hidden="true"><span>{format(max)}</span><span>{format(max / 2)}</span><span>{format(0)}</span></div><div className="chart-main">
      <svg className="chart" viewBox="0 0 600 160" role="img" aria-label={`${definition.title} historical chart`} aria-describedby={outputId} preserveAspectRatio="none" onPointerMove={chooseSample} onPointerDown={chooseSample}>
        <path className="chart-gridline" d="M0 18H600M0 84H600M0 150H600"/>
        {segments.map((segment, segmentIndex) => segment.length === 1 ? <circle key={segmentIndex} className="chart-line-point" cx={segment[0].x} cy={segment[0].y} r="3"/> : <polyline key={segmentIndex} points={segment.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ")}/>)}
        {selectedIndex >= 0 && <path className="chart-crosshair" d={`M${x.toFixed(1)} 10V150`}/>}
        {selectedPoint && <><circle className="chart-selected" cx={selectedPoint.x} cy={selectedPoint.y} r="5"/><title>{definition.title}: {format(selectedPoint.value)} at {rows[selectedIndex]?.captured_at}</title></>}
      </svg>
      <div className="chart-time-axis" aria-hidden="true">{[rows[0], rows[Math.floor((rows.length - 1) / 2)], rows[rows.length - 1]].map((item, position) => <span key={`${position}:${item?.captured_at}`}>{item?.captured_at ? new Date(item.captured_at).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—"}</span>)}</div>
      <output className="chart-selected-value" id={outputId}>{selectedValue == null ? "No measurement at selected time" : `${format(selectedValue)} · ${rows[selectedIndex]?.captured_at ? new Date(rows[selectedIndex].captured_at).toLocaleString() : ""}`}</output>
    </div></div> : <p className="empty-chart">No measurements recorded for this range.</p>}
  </article>;
}

function Health({ data, metrics, refresh }: { data: Initial; metrics: Metrics; refresh: () => Promise<Initial | undefined> }) {
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  useEffect(() => { let alive = true; fetch("/statistics/history?range=24h", { credentials: "same-origin" }).then((response) => { if (!response.ok) throw new Error(); return response.json() as Promise<HistoryPoint[]>; }).then((rows) => { if (alive) setHistory(rows); }).catch(() => { if (alive) setHistory([]); }); return () => { alive = false; }; }, []);
  const [recovery, setRecovery] = useState<RecoveryStatus>();
  useEffect(() => {
    let alive = true;
    const loadRecovery = () => fetch("/system/recovery", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } }).then((response) => { if (!response.ok) throw new Error(); return response.json() as Promise<RecoveryStatus>; }).then((value) => { if (alive) setRecovery(value); }).catch(() => { if (alive) setRecovery(undefined); });
    void loadRecovery();
    const timer = window.setInterval(() => { void loadRecovery(); }, 15000);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);
  const recoveryServices = recovery?.services ?? [];
  const recoveryEvents = recovery?.events ?? [];
  const healthEvents = data.health_events ?? [];
  const resources: ChartDefinition[] = [
    { title: "CPU usage", read: (row) => row.host?.cpu_percent, unit: "percent" },
    { title: "Memory usage", read: (row) => row.host?.memory_used_bytes, unit: "bytes" },
  ];
  return <>
    <section className="health-summary"><strong className={`state-pill ${worst(data.components).toLowerCase()}`}><i/>{worst(data.components)}</strong><span>Latest health sample</span><button className="button secondary" onClick={() => void refresh()}>Refresh status</button></section>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">SERVICE PATH</p><h2>Gateway → Tunnel → Windows PC → Service</h2></div></div><PathDiagram/><details className="details"><summary>How these checks work</summary><p className="muted">Peer handshake and service reachability are checked from the tunnel namespace. Container liveness and restart counts come from the private observer. A handshake alone does not prove the service is reachable.</p></details></section>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">HOST RESOURCES</p><h2>CPU and memory</h2></div></div><div className="resource-summary"><Stat title="CPU" value={number(metrics.host?.cpu_percent, "%")} detail="Latest host sample"/><Stat title="Memory" value={pct(metrics.host?.memory_used_bytes, metrics.host?.memory_total_bytes)} detail={`${bytes(metrics.host?.memory_used_bytes)} of ${bytes(metrics.host?.memory_total_bytes)}`} color="purple"/></div><HistoryCharts rows={history} definitions={resources}/></section>
    <section className="panel"><div className="panel-title"><div><p className="eyebrow">COMPONENTS</p><h2>Health details</h2></div></div><ComponentCards components={data.components}/></section>
    {recovery && <section className="panel recovery-panel"><div className="panel-title"><div><p className="eyebrow">AUTOMATIC RECOVERY</p><h2>Service recovery</h2><p className="muted">Only crashed or unhealthy application containers are restarted. Upstream outages do not trigger restarts.</p></div>{recovery.checked_at && !recovery.checked_at.startsWith("0001-") && <small className="muted">Checked {displayTime(recovery.checked_at)}</small>}</div>
      {recovery.operation_active && <p className="banner">A maintenance operation is stopping or replacing services; automatic recovery is paused.</p>}
      <div className="recovery-service-list">{recoveryServices.map((service) => { const healthy = service.state === "running" && ["healthy", "none", "starting"].includes(service.health); const stateClass = service.stopped ? "down" : healthy ? "healthy" : service.attempts > 0 ? "degraded" : ""; return <article className="recovery-service" key={service.service}><div><strong>{service.service}</strong><small>{service.state} · {service.health}</small></div><span className={`state-pill ${stateClass}`}><i/>{service.stopped ? "Paused" : healthy ? "Healthy" : service.attempts ? `Retry ${service.attempts}/5` : service.state === "unknown" ? "Checking" : "Waiting"}</span>{service.next_attempt_at && !service.next_attempt_at.startsWith("0001-") && !healthy && !service.stopped && <small>Next check {displayTime(service.next_attempt_at)}</small>}{service.detail && <p>{service.detail}</p>}</article>; })}</div>
      <details className="details recovery-history"><summary>Recovery history · {recoveryEvents.length} recent events</summary>{recoveryEvents.length ? <ol className="health-events">{recoveryEvents.slice(0, 20).map((event, index) => <li key={`${event.at}-${event.service}-${event.action}-${index}`}><time dateTime={event.at}>{displayTime(event.at)}</time><b>{event.service}</b><span>{event.action.replaceAll("_", " ")}{event.attempt ? ` · attempt ${event.attempt}` : ""}</span><p>{event.detail}</p></li>)}</ol> : <p className="empty-chart">No automatic recovery actions have been needed.</p>}</details>
    </section>}
    <section className="panel"><details className="health-history-details"><summary>Health history · {healthEvents.length} recent changes</summary>{healthEvents.length ? <ol className="health-events">{[...healthEvents].reverse().map((event, index) => <li key={`${event.at}-${event.name}-${index}`}><time dateTime={event.at}>{displayTime(event.at)}</time><b>{componentLabel(event.name)}</b><span>{event.from ?? "First check"} → {event.to}</span><p>{publicHealthText(event.detail)}</p></li>)}</ol> : <p className="empty-chart">No health status changes have been recorded.</p>}</details></section>
  </>;
}
function Access({ data }: { data: Initial }) {
  const entries = data.whitelist_entries ?? (data.whitelist ?? []).map((address) => ({ address, name: "" }));
  return <section className="panel"><div className="panel-title"><div><p className="eyebrow">DEFAULT DENY</p><h2>Allowed addresses</h2><p className="muted">IPv4, IPv6, and CIDR ranges with the trusted socket peer address.</p></div></div>
    <form className="inline-form" action="/whitelist/add" method="post"><input type="hidden" name="csrf" value={data.csrf}/><div className="form-field"><label htmlFor="allow-entry">IP address or CIDR</label><input id="allow-entry" name="entry" placeholder="203.0.113.10 or 2001:db8::/64" required maxLength={64}/></div><div className="form-field"><label htmlFor="allow-name">Friendly name (optional)</label><input id="allow-name" name="name" placeholder="e.g. Home phone" maxLength={80}/></div><button className="button" type="submit">Add address</button></form>
    <div className="address-list">{entries.length ? entries.map((entry, index) => <div className="address-row" key={entry.address}><div className="address-label"><code>{entry.address}</code>{entry.name && <span>{entry.name}</span>}</div><div className="address-actions"><details className="address-name-details"><summary>{entry.name ? "Edit name" : "Add name"}</summary><form className="address-name-form" action="/whitelist/name" method="post"><input type="hidden" name="csrf" value={data.csrf}/><input type="hidden" name="entry" value={entry.address}/><label className="sr-only" htmlFor={`allow-name-${index}`}>Friendly name for {entry.address}</label><input id={`allow-name-${index}`} name="name" defaultValue={entry.name} placeholder="e.g. Home phone" maxLength={80}/><button className="button secondary" type="submit">Save name</button></form></details><form action="/whitelist/remove" method="post"><input type="hidden" name="csrf" value={data.csrf}/><input type="hidden" name="entry" value={entry.address}/><button className="button danger" type="submit" aria-label={`Remove ${entry.address}`}>Remove</button></form></div></div>) : <p className="empty-chart">No addresses are configured. Access remains blocked by default.</p>}</div>
  </section>;
}
function WireGuard({ data, onConfigConsumed, onSessionEnded }: { data: Initial; onConfigConsumed: () => void; onSessionEnded: () => void }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const status = data.wireguard_status;
  const configurationAvailable = data.wireguard_config_available;
  async function downloadConfiguration() {
    if (downloading) return;
    setDownloading(true);
    setDownloadError("");
    try {
      const response = await fetch("/wireguard/config", { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: data.csrf }) });
      if (response.status === 401 || response.redirected) {
        onSessionEnded();
        return;
      }
      if (!response.ok) {
        setDownloadError("The configuration could not be downloaded. Please try again.");
        return;
      }
      const configuration = await response.blob();
      const objectURL = URL.createObjectURL(configuration);
      const link = document.createElement("a");
      link.href = objectURL;
      link.download = "windows-peer.conf";
      link.hidden = true;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
      onConfigConsumed();
    } catch {
      setDownloadError("The download did not complete. Please try again.");
    } finally {
      setDownloading(false);
    }
  }
  return <><section className="panel"><div className="panel-title"><div><p className="eyebrow">WINDOWS PEER</p><h2>WireGuard configuration</h2></div></div>
    {configurationAvailable ? <button className="button download-button" type="button" onClick={downloadConfiguration} disabled={downloading}>Download configuration</button> : <form action="/wireguard/rotate" method="post"><input type="hidden" name="csrf" value={data.csrf}/><button className="button danger" type="submit">Regenerate and revoke current peer</button></form>}
    {downloadError && <p className="notice" role="alert">{downloadError}</p>}
  </section>{status && <section className="panel"><div className="panel-title"><div><p className="eyebrow">LIVE DIAGNOSTICS</p><h2>Current tunnel status</h2></div></div><div className="stat-grid"><Stat title="Windows peer" value={status.peer_state} detail={status.peer_last_handshake ? `Handshake ${displayTime(status.peer_last_handshake)}` : "No handshake recorded"} color="blue"/><Stat title="Received" value={bytes(status.peer_rx_bytes)} detail="Peer traffic received by VPS" color="cyan"/><Stat title="Sent" value={bytes(status.peer_tx_bytes)} detail="Peer traffic sent by VPS" color="purple"/></div><p className="muted">{status.peer_detail}</p></section>}</>;
}
function Security({ data }: { data: Initial }) {
  return <section className="panel account-security">
      <div className="panel-title"><div><p className="eyebrow">ADMINISTRATOR ACCOUNT</p><h2>Account security</h2></div></div>
      <div className="account-security-grid">
        <div className="account-security-section"><h3>Change password</h3><p className="muted">Use at least 12 characters. Changing the password signs out all administrator sessions.</p>
          <form className="form-grid" action="/password/change" method="post"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Current password" name="current_password" autocomplete="current-password"/><Field label="New password" name="new_password" autocomplete="new-password"/><Field label="Confirm new password" name="confirm_password" autocomplete="new-password"/>{data.totp_status === "enabled" && <div className="form-field"><label htmlFor="password-change-code">Current six-digit authenticator code for password change</label><input id="password-change-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" maxLength={6} required/></div>}<button className="button" type="submit">Change password</button></form>
          <p className="muted">Administrator recovery: <code>reset-password</code>.</p>
        </div>
        <TOTP data={data}/>
      </div>
  </section>;
}
function Field({ label, name, autocomplete }: { label: string; name: string; autocomplete: string }) { return <div className="form-field"><label htmlFor={name}>{label}</label><input id={name} name={name} type="password" autoComplete={autocomplete} minLength={12} maxLength={1024} required/></div>; }
function TOTP({ data }: { data: Initial }) {
  return <section className="account-security-section totp-factor">
    <div className="account-security-title"><h3>Authenticator</h3><span className={`state-pill ${data.totp_status === "enabled" ? "healthy" : "unknown"}`}><i/>{data.totp_status === "enabled" ? "Enabled" : data.totp_status}</span></div>
    {data.totp_status === "enabled" ? <><p className="muted">A current code is required for administrator sign-in and sensitive account changes.</p><details className="details"><summary>Disable two-factor authentication</summary><p className="muted">Your password and a current code are required. All administrator sessions will be signed out.</p><form action="/totp/disable" method="post" className="form-grid"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Administrator password" name="password" autocomplete="current-password"/><div className="form-field"><label htmlFor="disable-code">Current six-digit authenticator code</label><input id="disable-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" maxLength={6} required/></div><button className="button danger" type="submit">Disable authenticator</button></form></details></> : <><p className="muted">Add a second factor to protect administrator sign-in.</p><form action="/totp/enroll/start" method="post" className="inline-form"><input type="hidden" name="csrf" value={data.csrf}/><Field label="Administrator password" name="password" autocomplete="current-password"/><button className="button" type="submit">Set up authenticator</button></form>{data.totp_setup_visible && <div className="setup-card"><p>Scan the QR code or enter the secret in your authenticator app.</p>{data.totp_qr_code && <img src={data.totp_qr_code} alt="Authenticator setup QR code" width="256" height="256"/>}<code>{data.totp_secret}</code><form action="/totp/enroll/confirm" method="post" className="inline-form"><input type="hidden" name="csrf" value={data.csrf}/><label htmlFor="confirm-code">Six-digit code</label><input id="confirm-code" name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required/><button className="button" type="submit">Confirm authenticator</button></form><form action="/totp/enroll/cancel" method="post"><input type="hidden" name="csrf" value={data.csrf}/><button className="button secondary" type="submit">Cancel setup</button></form></div>}</>}
  </section>;
}

function main() { const root = document.getElementById("root"); if (root) createRoot(root).render(<React.StrictMode><App/></React.StrictMode>); }
main();

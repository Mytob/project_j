const { test, expect } = require('@playwright/test');

const baseURL = process.env.BASE_URL || 'https://admin.domain.test';
const pages = [
  ['/dashboard', 'Overview', 'Overview'],
  ['/statistics', 'Traffic', 'Monitor'],
  ['/system', 'Updates', 'System'],
  ['/backups', 'Backups', 'System', 'Backups'],
  ['/health', 'Health', 'Monitor', 'Health'],
  ['/access-control', 'Access', 'Network'],
  ['/wireguard', 'Tunnel', 'Network', 'Tunnel'],
  ['/security', 'Account', 'Security'],
  ['/security/protection', 'Protection', 'Security', 'Protection'],
  ['/settings', 'Storage', 'System', 'Storage'],
  ['/web-content', 'Website', 'System', 'Website'],
  ['/about', 'About', 'System', 'About'],
];

test('admin navigation and charts work in desktop and mobile-sized browser layouts', async ({ page, browser, browserName }, testInfo) => {
  test.setTimeout(90000);
  const stylePolicyErrors = [];
  let bootstrapRequests = 0;
  await page.route('**/system/recovery', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ operation_active: false, services: null, events: null }),
  }));
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/api/initial') bootstrapRequests += 1;
  });
  await page.route('**/api/initial', async (route) => {
    const response = await route.fetch();
    const initial = await response.json();
    initial.health_events = null;
    initial.wireguard_config_available = true;
    if (initial.wireguard_status) initial.wireguard_status.config_available = true;
    await route.fulfill({ response, json: initial });
  });
  const backup = { name: 'jellyfin-proxy-test-20261022.bak', size_bytes: 2048, modified_at: '2026-10-22T00:00:00Z' };
  const createdBackup = { name: 'jellyfin-proxy-manual-20261022.bak', size_bytes: 4096, modified_at: '2026-10-22T00:01:00Z' };
  let backupList = [backup];
  let maintenanceJob;
  let jobPolls = 0;
  let failNextJobPoll = false;
  const releaseState = { current: { version: '1.6.0-dev.5', build_id: 'currentbuild' }, previous: { version: '1.6.0-dev.4', build_id: 'previousbuild' } };
  let uploadStatus;
  await page.route('**/system/releases', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(releaseState) }));
  await page.route('**/system/backups', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(backupList) }));
  await page.route('**/system/jobs**', async (route) => {
    if (route.request().method() === 'POST') {
      const { action, backup_name: backupName } = route.request().postDataJSON();
      jobPolls = 0;
      maintenanceJob = { id: '0123456789abcdef0123456789abcdef', action, backup_name: backupName, state: 'queued', step: 0, total: action === 'backup' || action === 'cleanup' ? 2 : action === 'delete-backup' ? 1 : 7, message: `${action[0].toUpperCase()}${action.slice(1)} queued`, started_at: '2026-10-22T00:00:00Z', updated_at: '2026-10-22T00:00:00Z' };
      await route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify(maintenanceJob) });
      return;
    }
    if (maintenanceJob && failNextJobPoll) {
      failNextJobPoll = false;
      await route.abort();
      return;
    }
    jobPolls += 1;
    if (maintenanceJob && jobPolls >= 2) {
      const isBackup = maintenanceJob.action === 'backup';
      const isCleanup = maintenanceJob.action === 'cleanup';
      const isDeleteBackup = maintenanceJob.action === 'delete-backup';
      const isUpdate = maintenanceJob.action === 'update';
      if (isUpdate) {
        releaseState.previous = releaseState.current;
        releaseState.current = { version: '1.6.0-dev.6', build_id: 'candidatebuild' };
      }
      maintenanceJob = { ...maintenanceJob, state: 'completed', step: maintenanceJob.total, message: isBackup ? 'Backup created and verified' : `${maintenanceJob.action[0].toUpperCase()}${maintenanceJob.action.slice(1)} completed`, result: isBackup ? createdBackup.name : isDeleteBackup ? maintenanceJob.backup_name : isCleanup ? 'Removed 2 unused image(s); kept 10 protected or in-use image(s)' : '1.6.0-dev.6 · candidatebuild', completed_at: '2026-10-22T00:01:00Z' };
      if (isBackup) backupList = [createdBackup, ...backupList.filter((item) => item.name !== createdBackup.name)];
      if (isDeleteBackup) backupList = backupList.filter((item) => item.name !== maintenanceJob.backup_name);
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(route.request().url().includes('/system/jobs/') ? maintenanceJob : (maintenanceJob ? [maintenanceJob] : [])) });
  });
  await page.route('**/system/uploads', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    uploadStatus = { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', filename: 'candidate.pkg', size_bytes: 7, chunk_bytes: 8388608, total_chunks: 1, received_chunks: [], complete: false, updated_at: '2026-10-22T00:00:00Z' };
    await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(uploadStatus) });
  });
  await page.route('**/system/uploads/**', async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === 'PUT') uploadStatus = { ...uploadStatus, received_chunks: [0] };
    if (url.pathname.endsWith('/complete')) uploadStatus = { ...uploadStatus, complete: true, sha256: 'a'.repeat(64) };
    if (route.request().method() === 'GET' && !uploadStatus) return route.fulfill({ status: 404 });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(uploadStatus) });
  });
  await page.route('**/system/packages/validate', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ current_version: '1.6.0-dev.5', current_build_id: 'currentbuild', candidate_version: '1.6.0-dev.6', candidate_build_id: 'candidatebuild', target_os: 'ubuntu-26.04', architecture: 'amd64', database_schema_minimum: 2, database_schema_maximum: 2 }) }));
  page.on('console', (message) => {
    if (message.type() === 'error' && /Refused to apply inline style/.test(message.text())) stylePolicyErrors.push(message.text());
  });
  const loginResponse = await page.goto('/');
  const contentPolicy = loginResponse.headers()['content-security-policy'] || '';
  expect(contentPolicy).toContain("style-src 'self'");
  expect(contentPolicy).not.toContain('unsafe-inline');
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);

  for (const width of [320, 390, 768, 1024, 1440, 1920, 2560]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth), `no horizontal page overflow at ${width}px`).toBeLessThanOrEqual(width);
  }

  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [path, title, mainSection, tab] of pages) {
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: mainSection, exact: true }).click();
    if (tab) await page.getByRole('navigation', { name: `${mainSection} pages` }).getByRole('link', { name: tab, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`${path.replaceAll('/', '\\/')}$`));
    await expect(page.locator('h1')).toHaveText(title);
  }

  await page.getByRole('navigation', { name: 'System pages' }).getByRole('link', { name: 'Storage', exact: true }).click();
  await page.reload();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.locator('h1')).toHaveText('Storage');
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Monitor', exact: true }).click();
  await page.getByRole('navigation', { name: 'Monitor pages' }).getByRole('link', { name: 'Health', exact: true }).click();
  await expect(page.getByText('Recovery history · 0 recent events', { exact: true })).toBeVisible();
  await expect(page.locator('.health-history-details summary')).toContainText('Health history');

  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'System', exact: true }).click();
  await page.getByRole('navigation', { name: 'System pages' }).getByRole('link', { name: 'Backups', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Stored backups', exact: true })).toBeVisible();
  const backupRow = page.locator('.system-backup-row').filter({ hasText: '2.0 KB' });
  await expect(backupRow).toContainText('2.0 KB');
  await expect(backupRow).toContainText('Managed backup');
  await expect(backupRow).not.toContainText(/jellyfin|proxy/i);
  await page.route('**/system/backups/*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/octet-stream',
    headers: { 'Content-Disposition': `attachment; filename="${backup.name}"` },
    body: 'test backup payload',
  }));
  const backupDownloadEvent = page.waitForEvent('download');
  await backupRow.getByRole('link', { name: 'Download' }).click();
  const backupDownload = await backupDownloadEvent;
  expect(backupDownload.suggestedFilename()).toBe(backup.name);
  await page.getByRole('button', { name: 'Create backup' }).click();
  await expect(page.getByText('Backup created and verified', { exact: true })).toBeVisible({ timeout: 10000 });
  const createdBackupRow = page.locator('.system-backup-row').filter({ hasText: '4.0 KB' });
  await expect(createdBackupRow).toContainText('Managed backup');
  page.once('dialog', (dialog) => dialog.accept());
  await createdBackupRow.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Delete-backup completed', { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.locator('.system-backup-row').filter({ hasText: '4.0 KB' })).toHaveCount(0);
  await expect(page.locator('.system-backup-row').filter({ hasText: '2.0 KB' })).toHaveCount(1);
  await page.getByRole('button', { name: 'Create backup' }).click();
  await expect(page.locator('.system-backup-row').filter({ hasText: '4.0 KB' })).toContainText('Managed backup');

  await page.getByRole('navigation', { name: 'System pages' }).getByRole('link', { name: 'Updates', exact: true }).click();
  await page.locator('#release-package').setInputFiles({ name: 'candidate.pkg', mimeType: 'application/octet-stream', buffer: Buffer.from('package') });
  await page.getByLabel('Independent SHA-256 checksum').fill('a'.repeat(64));
  await page.getByRole('button', { name: 'Upload and verify package' }).click();
  await expect(page.getByRole('heading', { name: 'Compatibility review' })).toBeVisible();
  await page.on('dialog', (dialog) => dialog.accept());
  failNextJobPoll = true;
  await page.getByRole('button', { name: 'Install reviewed update' }).click();
  await expect(page.getByText('Reconnecting to the maintenance service…', { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.getByText('Update completed', { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.getByText('Reconnecting to the maintenance service…', { exact: true })).toHaveCount(0);
  await expect(page.locator('.release-summary').first()).toContainText('1.6.0-dev.6 · candidatebuild');
  await page.getByRole('navigation', { name: 'System pages' }).getByRole('link', { name: 'Backups', exact: true }).click();
  const restoreRow = page.locator('.system-backup-row').filter({ hasText: '4.0 KB' });
  await expect(restoreRow).toHaveCount(1);
  await restoreRow.getByRole('button', { name: 'Restore' }).click();
  await expect(page.getByText('Restore completed', { exact: true })).toBeVisible({ timeout: 10000 });
  await page.getByRole('navigation', { name: 'System pages' }).getByRole('link', { name: 'Updates', exact: true }).click();
  await page.getByRole('button', { name: 'Roll back to previous release' }).click();
  await expect(page.getByText('Rollback completed', { exact: true })).toBeVisible({ timeout: 10000 });
  await page.getByRole('button', { name: 'Clean unused images' }).click();
  await expect(page.getByText('Cleanup completed', { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.locator('.system-job')).toContainText('Removed 2 unused image(s); kept 10 protected or in-use image(s)');

  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Monitor', exact: true }).click();
  const errorRateCard = page.locator('.stat-card').filter({ hasText: 'Latest interval' });
  await expect(errorRateCard).toContainText('Error rate');
  await expect(errorRateCard).toContainText('total HTTP errors since start');

  await page.route('**/wireguard/config', (route) => route.fulfill({
    status: 200,
    contentType: 'application/octet-stream',
    headers: { 'Content-Disposition': 'attachment; filename="windows-peer.conf"' },
    body: 'test WireGuard configuration',
  }));
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Network', exact: true }).click();
  await page.getByRole('navigation', { name: 'Network pages' }).getByRole('link', { name: 'Tunnel', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Download configuration' })).toBeVisible();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download configuration' }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toBe('windows-peer.conf');
  await expect(page.getByRole('button', { name: 'Regenerate and revoke current peer' })).toBeVisible();
  expect(bootstrapRequests).toBe(2);
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Overview', exact: true }).click();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Network', exact: true }).click();
  await page.getByRole('navigation', { name: 'Network pages' }).getByRole('link', { name: 'Tunnel', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Regenerate and revoke current peer' })).toBeVisible();
  expect(bootstrapRequests).toBe(2);
  await page.unroute('**/wireguard/config');

  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Monitor', exact: true }).click();
  await page.getByRole('navigation', { name: 'Monitor pages' }).getByRole('link', { name: 'Health', exact: true }).click();
  await page.route('**/api/initial', (route) => route.abort());
  await page.getByRole('button', { name: 'Refresh status' }).click();
  await expect(page.getByRole('heading', { name: 'Health', exact: true })).toBeVisible();
  await expect(page.locator('.error-card')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
  await page.unroute('**/api/initial');
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByRole('button', { name: 'Try again' })).toHaveCount(0);

  await page.getByRole('navigation', { name: 'Monitor pages' }).getByRole('link', { name: 'Health', exact: true }).click();
  const cpuChart = page.locator('.chart-panel').filter({ has: page.getByRole('heading', { name: 'CPU usage', exact: true }) });
  const slider = page.getByRole('slider', { name: 'Explore historical sample time' });
  await expect.poll(async () => slider.count(), { timeout: 30000 }).toBe(1);
  await expect(slider).toBeVisible();
  await expect.poll(async () => Number(await slider.getAttribute('max')), { timeout: 30000 }).toBeGreaterThan(0);
  const plot = cpuChart.locator('svg.chart');
  await plot.click({ position: { x: 2, y: 20 } });
  expect(Number(await slider.inputValue())).toBe(0);
  await slider.focus();
  await slider.press('ArrowRight');
  expect(Number(await slider.inputValue())).toBe(1);
  await expect(cpuChart.locator('.chart-selected-value')).toContainText('·');

  const mobileOptions = {
    baseURL,
    ignoreHTTPSErrors: true,
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
    hasTouch: true,
    isMobile: browserName !== 'firefox',
  };
  const mobileContext = await browser.newContext(mobileOptions);
  await mobileContext.route('**/system/backups', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([backup]) }));
  await mobileContext.route('**/system/jobs', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await mobileContext.route('**/system/releases', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(releaseState) }));
  const mobilePage = await mobileContext.newPage();
  await mobilePage.goto('/');
  await mobilePage.getByLabel('Password').fill('integration-test-admin-password');
  if (browserName === 'firefox') await mobilePage.getByRole('button', { name: 'Sign in' }).click();
  else await mobilePage.getByRole('button', { name: 'Sign in' }).tap();
  await expect(mobilePage).toHaveURL(/\/dashboard$/);

  for (const [path, title, mainSection, tab] of pages.slice(1)) {
    const menu = mobilePage.getByRole('button', { name: 'Toggle navigation' });
    if (browserName === 'firefox') await menu.click();
    else await menu.tap();
    const link = mobilePage.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: mainSection, exact: true });
    await expect(link).toBeVisible();
    if (browserName === 'firefox') await link.click();
    else await link.tap();
    if (tab) {
      const tabLink = mobilePage.getByRole('navigation', { name: `${mainSection} pages` }).getByRole('link', { name: tab, exact: true });
      if (browserName === 'firefox') await tabLink.click();
      else await tabLink.tap();
    }
    await expect(mobilePage).toHaveURL(new RegExp(`${path.replaceAll('/', '\\/')}$`));
    await expect(mobilePage.locator('h1')).toHaveText(title);
    expect(await mobilePage.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  }
  await mobileContext.close();

  await page.setViewportSize({ width: 844, height: 390 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(844);
  expect(stylePolicyErrors).toEqual([]);
  await testInfo.attach('browser-engine', { body: browserName, contentType: 'text/plain' });
});

const { test, expect } = require('@playwright/test');
const { createHmac } = require('node:crypto');

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(value) {
  let bits = 0;
  let accumulator = 0;
  const bytes = [];
  for (const character of value.replace(/=+$/, '').toUpperCase()) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('Invalid Base32 setup secret');
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function codeAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', secret).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

function acceptedCodes(secret, step) {
  return new Set([step - 1, step, step + 1].filter((value) => value >= 0).map((value) => codeAt(secret, value)));
}

async function waitForStep(page, step) {
  while (Math.floor(Date.now() / 1000 / 30) < step) await page.waitForTimeout(100);
}

test('administrator can authenticate, manage TOTP, change password, and use the admin SPA', async ({ page, browser }) => {
  test.setTimeout(180000);
  page.on('pageerror', (error) => console.log(`Browser page error: ${error.stack || error.message}`));
  const anonymousHistory = await page.request.get('/statistics/history?range=24h');
  expect(anonymousHistory.status()).toBe(401);
  const anonymousEvents = await page.request.get('/statistics/events');
  expect(anonymousEvents.status()).toBe(401);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Jellyfin Proxy' })).toBeVisible();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Service health' })).toBeVisible();
  await expect(page.getByText('integration-test · browser-test')).toBeVisible();
  const overview = await page.locator('.component-card').allTextContents();
  for (const component of ['Admin backend', 'Access control', 'Caddy / proxy', 'WireGuard interface', 'Windows peer', 'Jellyfin endpoint', 'Host metrics', 'Proxy metrics', 'Container status']) {
    expect(overview.join(' ')).toContain(component);
  }
  expect(overview.join(' ')).toContain('Unknown');
  await page.getByRole('link', { name: 'Access control' }).click();
  await expect(page).toHaveURL(/\/access-control$/);
  await expect(page.locator('body')).toContainText('Allowed addresses');
  await expect(page.getByRole('heading', { name: 'Allowed addresses' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Service health' })).toHaveCount(0);
  await page.getByRole('link', { name: 'WireGuard' }).click();
  await expect(page).toHaveURL(/\/wireguard$/);
  await expect(page.getByRole('heading', { name: 'WireGuard configuration' })).toBeVisible();
  await expect(page.getByText('No downloadable copy')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download and delete configuration' })).toHaveCount(0);
  await page.getByRole('link', { name: 'Health' }).click();
  await expect(page).toHaveURL(/\/health$/);
  await expect(page.getByRole('heading', { name: 'Detailed status' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Service health' })).toHaveCount(0);
  await page.getByRole('link', { name: 'Security' }).click();
  await expect(page).toHaveURL(/\/security$/);
  await expect(page.getByRole('heading', { name: 'Administrator authenticator' })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await expect(page).toHaveScreenshot('security-desktop.png', { fullPage: true, animations: 'disabled', maxDiffPixelRatio: 0.015 });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page).toHaveScreenshot('security-mobile.png', { fullPage: true, animations: 'disabled', maxDiffPixelRatio: 0.015 });
  await page.setViewportSize({ width: 1440, height: 1000 });

  const visualPages = [
    ['/dashboard', 'overview', 'Overview'],
    ['/statistics', 'statistics', 'Statistics'],
    ['/health', 'health', 'Health'],
    ['/access-control', 'access-control', 'Access control'],
    ['/wireguard', 'wireguard', 'WireGuard'],
  ];
  const dynamicVisualRegions = [
    page.locator('.build-tag'),
    page.locator('.top-status .live-indicator'),
    page.locator('.page-footer span:last-child'),
    page.locator('.stat-card > strong'),
    page.locator('.stat-card > small'),
    page.locator('.component-card small'),
    page.locator('.component-card .state-pill'),
    page.locator('.chart polyline'),
    page.locator('.chart-crosshair'),
    page.locator('.chart-selected'),
    page.locator('.chart-range'),
    page.locator('.chart-output'),
    page.locator('.health-events time'),
  ];
  for (const [path, name, heading] of visualPages) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    if (name === 'health') await page.addStyleTag({ content: '.health-events { display: none !important; }' });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await expect(page).toHaveScreenshot(`admin-${name}-desktop.png`, { fullPage: true, animations: 'disabled', maxDiffPixelRatio: 0.02, mask: dynamicVisualRegions, maskColor: '#102238' });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page).toHaveScreenshot(`admin-${name}-mobile.png`, { fullPage: true, animations: 'disabled', maxDiffPixelRatio: 0.02, mask: dynamicVisualRegions, maskColor: '#102238' });
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBeTruthy();
  await page.emulateMedia({ reducedMotion: 'no-preference' });

  await page.goto('/security');
  await page.getByLabel('Administrator password').fill('incorrect-password');
  const badPassword = page.waitForResponse((response) => response.url().endsWith('/totp/enroll/start') && response.status() === 401);
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await badPassword;
  await expect(page.getByText('The password was not accepted.')).toBeVisible();

  await page.goto('/security');
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await expect(page).toHaveURL(/\/security$/);
  const qr = page.getByRole('img', { name: 'Authenticator setup QR code' });
  await expect(qr).toBeVisible();
  expect(await qr.evaluate((image) => image.complete && image.naturalWidth === 256)).toBeTruthy();

  const secretText = await page.locator('.setup-card code').textContent();
  const secret = decodeBase32(secretText.trim());
  const step = Math.floor(Date.now() / 1000 / 30);
  const accepted = acceptedCodes(secret, step);
  let incorrect = '000000';
  while (accepted.has(incorrect)) incorrect = String((Number(incorrect) + 1) % 1_000_000).padStart(6, '0');
  await page.getByLabel('Six-digit code').fill(incorrect);
  const rejected = page.waitForResponse((response) => response.url().endsWith('/totp/enroll/confirm') && response.status() === 400);
  await page.getByRole('button', { name: 'Confirm authenticator' }).click();
  await rejected;
  await expect(page.getByText('The authenticator code was not accepted.')).toBeVisible();

  await page.goto('/security');
  await expect(page.getByRole('img', { name: 'Authenticator setup QR code' })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel setup' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByLabel('Password')).toBeVisible();

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('link', { name: 'Security' }).click();
  await expect(page).toHaveURL(/\/security$/);
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await expect(page.getByRole('img', { name: 'Authenticator setup QR code' })).toBeVisible();
  const finalSecret = decodeBase32((await page.locator('.setup-card code').textContent()).trim());
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  await page.getByLabel('Six-digit code').fill(codeAt(finalSecret, currentStep));
  await page.getByRole('button', { name: 'Confirm authenticator' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByLabel('Password')).toBeVisible();
  await expect(page.getByLabel('Authenticator code')).toBeVisible();

  const loginStep = Math.floor(Date.now() / 1000 / 30);
  const acceptedLoginCodes = acceptedCodes(finalSecret, loginStep);
  let wrongLoginCode = '000000';
  while (acceptedLoginCodes.has(wrongLoginCode)) wrongLoginCode = String((Number(wrongLoginCode) + 1) % 1_000_000).padStart(6, '0');
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(wrongLoginCode);
  const rejectedLogin = page.waitForResponse((response) => response.url().endsWith('/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await rejectedLogin;
  await expect(page.getByRole('alert')).toContainText('password or authenticator code was not accepted');

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, loginStep + 1));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('Authenticator code')).toBeVisible();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, loginStep + 1));
  const rejectedReplay = page.waitForResponse((response) => response.url().endsWith('/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await rejectedReplay;
  await expect(page.getByRole('alert')).toContainText('password or authenticator code was not accepted');

  await waitForStep(page, loginStep + 2);
  const disableLoginStep = Math.floor(Date.now() / 1000 / 30);
  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByLabel('Authenticator code').fill(codeAt(finalSecret, disableLoginStep));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('link', { name: 'Security' }).click();
  await expect(page).toHaveURL(/\/security$/);
  await expect(page.getByText('Two-factor authentication is enabled for administrator sign-in.')).toBeVisible();
  await page.getByText('Disable two-factor authentication').click();
  await expect(page.getByLabel('Administrator password')).toBeVisible();
  await page.getByLabel('Administrator password').fill('integration-test-admin-password');
  const disableCodeStep = Math.max(Math.floor(Date.now() / 1000 / 30), disableLoginStep + 1);
  await page.getByLabel('Current six-digit authenticator code').fill(codeAt(finalSecret, disableCodeStep));
  await page.getByRole('button', { name: 'Disable authenticator' }).click();
  await expect(page).toHaveURL(/\?totp=disabled$/);
  await expect(page.getByText('Authenticator disabled. Sign in with your administrator password.')).toBeVisible();
  await expect(page.getByLabel('Authenticator code')).toHaveCount(0);

  await page.getByLabel('Password').fill('integration-test-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  const otherContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const otherPage = await otherContext.newPage();
  await otherPage.goto('/');
  await otherPage.getByLabel('Password').fill('integration-test-admin-password');
  await otherPage.getByRole('button', { name: 'Sign in' }).click();
  await expect(otherPage).toHaveURL(/\/dashboard$/);
  await page.getByRole('link', { name: 'Security' }).click();
  await page.getByLabel('Current password').fill('integration-test-admin-password');
  await page.getByLabel('New password', { exact: true }).fill('new-integration-admin-password');
  await page.getByLabel('Confirm new password').fill('new-integration-admin-password');
  await page.getByRole('button', { name: 'Change password' }).click();
  await expect(page).toHaveURL(/\?password=changed$/);
  await expect(page.getByText('Password changed. Sign in again with the new password.')).toBeVisible();
  expect((await otherPage.request.get('/api/initial')).status()).toBe(401);
  await otherPage.close();
  await otherContext.close();
  await page.getByLabel('Password').fill('integration-test-admin-password');
  const oldPasswordRejected = page.waitForResponse((response) => response.url().endsWith('/login') && response.status() === 401);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await oldPasswordRejected;
  await page.getByLabel('Password').fill('new-integration-admin-password');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('link', { name: 'Statistics' }).click();
  await expect(page).toHaveURL(/\/statistics$/);
  await expect(page.getByRole('heading', { name: 'Statistics' })).toBeVisible();
  await expect(page.getByText('Live via SSE')).toBeVisible({ timeout: 15000 });
  await expect(page.getByText('Active requests', { exact: true })).toBeVisible();
  await expect(page.getByText('Allowed / blocked', { exact: true })).toBeVisible();
  await expect(page.getByText('HTTP requests in flight')).toHaveCount(1);
  await expect(page.locator('.stat-card').filter({ hasText: 'Memory' }).first().locator('strong')).not.toHaveText('—', { timeout: 15000 });
  await expect(page.locator('.stat-card').filter({ hasText: 'Active requests' }).locator('strong')).not.toHaveText('—', { timeout: 15000 });

  for (const range of ['24h', '7d', '30d', '90d']) {
    const response = await page.request.get(`/statistics/history?range=${range}`);
    expect(response.status()).toBe(200);
    expect(Array.isArray(await response.json())).toBeTruthy();
    await page.getByLabel('History range').selectOption(range);
  }
  await expect(page.locator('.chart').first()).toBeVisible();

  const accessOrigin = 'https://access.domain.test';
  const ranged = await page.request.get(`${accessOrigin}/__stream?bytes=128`, { headers: { Range: 'bytes=2-5' } });
  expect(ranged.status()).toBe(206);
  expect(ranged.headers()['content-range']).toBe('bytes 2-5/128');
  expect(Array.from(await ranged.body())).toEqual([2, 3, 4, 5]);

  const concurrent = [0, 1].map(() => page.request.get(`${accessOrigin}/__stream?bytes=1048576&slow=1`));
  const activeValue = page.locator('.stat-card').filter({ hasText: 'Active requests' }).locator('strong');
  await expect.poll(async () => Number((await activeValue.textContent()).replaceAll(',', '')), { timeout: 10000 }).toBeGreaterThan(0);
  const streamed = await Promise.all(concurrent);
  for (const response of streamed) {
    expect(response.status()).toBe(200);
    expect((await response.body()).length).toBe(1048576);
  }
  await expect.poll(async () => Number((await activeValue.textContent()).replaceAll(',', '')), { timeout: 10000 }).toBe(0);

  page.on('websocket', (socket) => {
    console.log(`WebSocket connected: ${socket.url()}`);
    socket.on('socketerror', (error) => console.log(`WebSocket socket error: ${error}`));
    socket.on('close', () => console.log(`WebSocket closed: ${socket.url()}`));
  });
  await page.goto(accessOrigin);
  const websocketEcho = await page.evaluate((url) => new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const timeout = setTimeout(() => { socket.close(); reject(new Error('WebSocket echo timed out')); }, 10000);
    socket.onopen = () => socket.send('streaming-proxy-check');
    socket.onmessage = (event) => { clearTimeout(timeout); socket.close(); resolve(event.data); };
    socket.onerror = () => { clearTimeout(timeout); reject(new Error('WebSocket proxy connection failed')); };
  }), 'wss://access.domain.test/__ws');
  expect(websocketEcho).toBe('streaming-proxy-check');
  await page.goto('https://admin.domain.test/statistics');
  await expect(page.getByRole('heading', { name: 'Statistics' })).toBeVisible();

  await page.evaluate((url) => new Promise((resolve) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 300);
    fetch(url, { mode: 'no-cors', signal: controller.signal }).catch(() => {}).finally(() => { clearTimeout(timer); resolve(); });
  }), `${accessOrigin}/__stream?bytes=1048576&slow=1`);
  await expect.poll(async () => Number((await activeValue.textContent()).replaceAll(',', '')), { timeout: 10000 }).toBe(0);

  let abortedConnections = 0;
  await page.route('**/statistics/events', (route) => {
    if (abortedConnections++ === 0) return route.abort();
    return route.continue();
  });
  const reconnected = page.waitForResponse((response) => response.url().includes('/statistics/events') && response.status() === 200, { timeout: 15000 });
  await page.reload();
  await reconnected;
  await expect(page.getByText('Live via SSE')).toBeVisible({ timeout: 15000 });
  await page.unroute('**/statistics/events');

  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();

  for (const width of [320, 390, 430, 768, 1024, 1440, 1920, 2560]) {
    await page.setViewportSize({ width, height: 900 });
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(pageWidth, `page must not overflow at ${width}px`).toBeLessThanOrEqual(width);
  }
  await page.setViewportSize({ width: 844, height: 390 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(844);

  const mobileContext = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const mobilePage = await mobileContext.newPage();
  await mobilePage.goto('/');
  await mobilePage.getByLabel('Password').fill('new-integration-admin-password');
  await mobilePage.getByRole('button', { name: 'Sign in' }).tap();
  await expect(mobilePage).toHaveURL(/\/dashboard$/);
  const mobileMenu = mobilePage.getByRole('button', { name: 'Toggle navigation' });
  await mobileMenu.tap();
  const healthLink = mobilePage.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Health' });
  await expect(healthLink).toBeVisible();
  await healthLink.tap();
  await expect(mobilePage).toHaveURL(/\/health$/);
  expect(await mobilePage.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await mobilePage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  expect(await mobilePage.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await mobilePage.evaluate(() => { document.documentElement.style.fontSize = ''; });

  await mobileMenu.tap();
  await mobilePage.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Security' }).tap();
  await mobilePage.getByLabel('Current password').fill('new-integration-admin-password');
  await mobilePage.getByLabel('New password', { exact: true }).fill('final-mobile-admin-password');
  await mobilePage.getByLabel('Confirm new password').fill('final-mobile-admin-password');
  await mobilePage.getByRole('button', { name: 'Change password' }).tap();
  await expect(mobilePage).toHaveURL(/\?password=changed$/);
  await mobilePage.getByLabel('Password').fill('final-mobile-admin-password');
  await mobilePage.getByRole('button', { name: 'Sign in' }).tap();
  await expect(mobilePage).toHaveURL(/\/dashboard$/);

  await mobileMenu.tap();
  await mobilePage.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'WireGuard' }).tap();
  mobilePage.once('dialog', (dialog) => dialog.accept());
  await mobilePage.getByRole('button', { name: 'Regenerate and revoke current peer' }).tap();
  await expect(mobilePage).toHaveURL(/\/wireguard\?rotated=1$/);
  await expect(mobilePage.getByRole('status')).toContainText('previous Windows credentials have been revoked');
  const mobileDownload = mobilePage.waitForEvent('download');
  await mobilePage.getByRole('link', { name: 'Download and delete configuration' }).tap();
  expect((await mobileDownload).suggestedFilename()).toBe('jellyfin-proxy.conf');
  await expect.poll(async () => {
    const response = await mobilePage.request.get('/api/initial');
    return (await response.json()).wireguard_config_available;
  }, { timeout: 10000 }).toBe(false);
  await mobileContext.close();
});
